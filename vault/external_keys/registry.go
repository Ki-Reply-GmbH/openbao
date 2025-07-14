package externalkeys

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// ErrKeyAccessDenied is returned when a plugin/mount cannot use an External Key
// because it is lacking permission on one of these levels:
//
// 1. The key does't have a grant for the mount.
//
// 2. The namespace isn't allowed to use the External Key's type:
//   - Because of server-level configuration
//   - Because of namespace-level configuration
var ErrKeyAccessDenied = errors.New("key access denied")

// ServerConfig is a type shorthand for the server's External Keys configuration.
type ServerConfig map[string]*server.ExternalKeysConfig

// Namespacer provides the namespace store APIs required by [Registry].
// This interface lets us avoid a circular dependency on core or placing this
// package in core in the first place.
type Namespacer interface {
	// View provides the storage view for a namespace.
	View(*namespace.Namespace) logical.Storage
	// ParentOf resolves a namespace's parent, if possible.
	ParentOf(context.Context, *namespace.Namespace) (*namespace.Namespace, error)
	// TypeAllowed errors if a namespace cannot use the given External Key type.
	TypeAllowed(context.Context, *namespace.Namespace, string) error
}

type Args struct {
	Config, Key, Mount string
}

// Registry manages External Keys.
type Registry struct {
	wg    sync.WaitGroup
	cache *NamespacedCache[Factory]

	global sync.RWMutex

	// Access to the namespace store.
	namespacer Namespacer

	// A reference to the server's External Keys configuration.
	config ServerConfig

	// Logger to be derived from core.
	logger hclog.Logger
}

// NewRegistry creates a new [Registry].
func NewRegistry(logger hclog.Logger, config ServerConfig, namespacer Namespacer) *Registry {
	return &Registry{
		cache:      NewCache[Factory](),
		namespacer: namespacer,
		config:     config,
		logger:     logger,
	}
}

func (r *Registry) ListConfigs(ctx context.Context) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return r.StorageFor(ns).ListConfigs(ctx)
}

func (r *Registry) ReadConfig(ctx context.Context, args *Args) (*Config, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return r.StorageFor(ns).ReadConfig(ctx, args)
}

func (r *Registry) UpdateConfig(ctx context.Context, args *Args, create bool, f func(*Config) error) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	r.global.Lock()
	defer r.global.Unlock()

	if err := r.StorageFor(ns).UpdateConfig(ctx, args, create, f); err != nil {
		return err
	}

	// Destroy the associated client if it exists.
	r.cache.Remove(ns.Path, args.Config, r.destroy)

	return nil
}

func (r *Registry) DeleteConfig(ctx context.Context, args *Args) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	r.global.Lock()
	defer r.global.Unlock()

	if err := r.StorageFor(ns).DeleteConfigAndKeys(ctx, args); err != nil {
		return err
	}

	// Destroy the associated client if it exists.
	r.cache.Remove(ns.Path, args.Config, r.destroy)

	return nil
}

func (r *Registry) ListKeys(ctx context.Context, args *Args) ([]string, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return r.StorageFor(ns).ListKeys(ctx, args)
}

func (r *Registry) ReadKey(ctx context.Context, args *Args) (*Key, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	return r.StorageFor(ns).ReadKey(ctx, args)
}

func (r *Registry) UpdateKey(ctx context.Context, args *Args, create bool, f func(*Key) error) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	return r.StorageFor(ns).UpdateKey(ctx, args, create, f)
}

func (r *Registry) DeleteKey(ctx context.Context, args *Args) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	return r.StorageFor(ns).DeleteKey(ctx, args)
}

type ConfigBundle struct {
	Name   string  // The config name.
	Config *Config // The config values.

	CallingNamespace *namespace.Namespace // Namespace the config was resolved from.
	TargetNamespace  *namespace.Namespace // Namespace the config lives in.
}

func (r *Registry) ResolveConfigChain(ctx context.Context, args *Args) (*ConfigBundle, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return nil, err
	}

	var bundle ConfigBundle
	bundle.CallingNamespace = ns

	name := args.Config

	for {
		config, err := r.StorageFor(ns).ReadConfig(ctx, &Args{Config: name})
		if err != nil {
			return nil, err
		}

		next, ok := config.Values["inherits"]
		if !ok {
			bundle.Name = name
			bundle.Config = config
			bundle.TargetNamespace = ns
			return &bundle, nil
		}

		name = next
		if ns, err = r.namespacer.ParentOf(ctx, ns); err != nil {
			return nil, err
		}
	}
}

func (r *Registry) GetExternalKey(ctx context.Context, args *Args) (logical.ExternalKey, error) {
	r.global.RLock()
	defer r.global.RUnlock()

	bundle, err := r.ResolveConfigChain(ctx, args)
	if err != nil {
		return nil, err
	}

	// Before fetching the key, we can already perform config-level permission checks.
	ty := bundle.Config.Values["type"]
	if err := r.permitNamespace(ctx, bundle.TargetNamespace, ty); err != nil {
		return nil, err
	}

	// Fetch the key from the resolved namespace. This may be an ancestor of
	// the calling namespace rather than the original calling namespace.
	key, err := r.StorageFor(bundle.TargetNamespace).ReadKey(ctx,
		&Args{Config: bundle.Name, Key: args.Key})
	if err != nil {
		return nil, err
	}

	// Now perform key-level permission checks.
	if err := permitMount(
		bundle.CallingNamespace.Path, bundle.TargetNamespace.Path,
		args.Mount, key.Grants,
	); err != nil {
		return nil, err
	}

	factory, err := r.cache.GetOrCreate(bundle.TargetNamespace.Path, bundle.Name,
		func() (Factory, error) {
			return NewFactory(ctx, bundle.Config.Values)
		})
	if err != nil {
		return nil, err
	}

	return factory.Create(ctx, key.Values)
}

func (r *Registry) permitNamespace(ctx context.Context, ns *namespace.Namespace, ty string) error {
	// If this type is defined in the server config, does it permit it in this namespace?
	if customType, ok := r.config[ty]; ok {
		if !slices.ContainsFunc(customType.Namespaces, func(spec *server.NamespaceSpecifier) bool {
			return ns.CompareSpecifier(spec.Kind, spec.Value)
		}) {
			return fmt.Errorf("%w: namespace %q cannot use external key of this type", ErrKeyAccessDenied, ns.Path)
		}
	}

	// Does the namespace configuration permit the type in this namespace?
	if err := r.namespacer.TypeAllowed(ctx, ns, ty); err != nil {
		return fmt.Errorf("%w: %w", ErrKeyAccessDenied, err)
	}

	return nil
}

// normalizeMount ensures that a mount path has no leading '/'
// and ends in exactly one '/'.
func normalizeMount(mount string) string {
	mount = strings.Trim(mount, "/")
	return mount + "/"
}

func permitMount(caller, target, mount string, grants []string) error {
	mount = normalizeMount(mount)
	mount = caller + mount
	mount = strings.TrimPrefix(mount, target)

	if !slices.Contains(grants, mount) {
		return fmt.Errorf("%w: mount cannot use external key, missing grant", ErrKeyAccessDenied)
	}
	return nil
}

func (r *Registry) HandleNamespaceUpdate(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	r.global.Lock()
	defer r.global.Unlock()

	// Destroy all entries for the namespace (and child namespaces) that have
	// an illegal type.
	r.cache.Drain(ns.Path, r.destroy, func(client Factory) bool {
		return slices.Contains(ns.ExternalKeyTypes, client.Type())
	})

	return nil
}

func (r *Registry) HandleNamespaceDeletion(ctx context.Context) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	r.global.Lock()
	defer r.global.Unlock()

	// Prune all entries for the namespace (and theoretically child namespaces,
	// but those wouldn't exist at this point).
	r.cache.Drain(ns.Path, r.destroy, nil)

	return nil
}

func (r *Registry) HandleServerConfigUpdate(ctx context.Context, config ServerConfig) {
	r.global.Lock()
	defer r.global.Unlock()

	r.config = config
	r.cache.Clear(r.destroy)
}

func (r *Registry) Invalidate(ctx context.Context, key string) error {
	r.global.Lock()
	defer r.global.Unlock()

	return nil
}

func (r *Registry) Finalize() {
	r.global.Lock()
	defer r.global.Unlock()

	r.cache.Clear(r.destroy)
	r.wg.Wait()
}

func (r *Registry) destroy(client Factory, path, name string) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		if err := client.Finalize(ctx); err != nil {
			r.logger.Error("failed to finalize client", "namespace", path, "config", name, "error", err.Error())
		}
	}()
}
