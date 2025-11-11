// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package extkey

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/armon/go-radix"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/command/server"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type Config struct {
	Provider string         `json:"provider,omitempty"`
	Inherits string         `json:"inherits,omitempty"`
	Values   map[string]any `json:"values,omitempty"`
}

func (c *Config) ToMap() map[string]any {
	m := make(map[string]any, len(c.Values)+1)

	switch {
	case c.Provider != "":
		m["provider"] = c.Provider
	case c.Inherits != "":
		m["inherits"] = c.Inherits
	}

	maps.Copy(m, c.Values)
	return m
}

func (c *Config) Validate() (err error) {
	hasProvider, hasInherits := c.Provider != "", c.Inherits != ""

	switch {
	case hasProvider && hasInherits:
		err = errors.New(`fields "provider" and "inherits" are mutually exclusive`)
	case !hasProvider && !hasInherits:
		err = errors.New(`one of fields "provider", "inherits" is required`)
	case hasInherits && len(c.Values) > 0:
		err = errors.New(`field "inherits" requires that no other fields are set`)
	}

	return err
}

type Key struct {
	Values map[string]any `json:"values"`
	Grants []string       `json:"grants"`
}

const (
	StoragePrefix = "external-keys/"
	ConfigsPath   = StoragePrefix + "configs/"
	KeysPath      = StoragePrefix + "keys/"
)

var NameRegexp = regexp.MustCompile(`^\w(([\w-.]+)?\w)?$`)

// ConfigPath returns a config's storage path.
func ConfigPath(config string) string {
	return ConfigsPath + config
}

// KeyPath returns a key's storage path.
func KeyPath(config, key string) string {
	return KeyListPath(config) + key
}

// KeyListPath returns the path to list a config's keys at.
func KeyListPath(config string) string {
	return KeysPath + config + "/"
}

// WriteConfig writes a Config to storage.
func WriteConfig(ctx context.Context, storage logical.Storage, path string, config *Config) error {
	entry, err := logical.StorageEntryJSON(path, config)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// WriteKey writes a Key to storage.
func WriteKey(ctx context.Context, storage logical.Storage, path string, key *Key) error {
	entry, err := logical.StorageEntryJSON(path, key)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// ReadConfig reads a config from storage.
func ReadConfig(ctx context.Context, storage logical.Storage, path string) (*Config, bool, error) {
	entry, err := storage.Get(ctx, path)
	switch {
	case err != nil:
		return nil, false, err
	case entry == nil:
		return nil, false, nil
	}

	var config Config
	return &config, true, entry.DecodeJSON(&config)
}

// ReadKey reads a key from storage.
func ReadKey(ctx context.Context, storage logical.Storage, path string) (*Key, bool, error) {
	entry, err := storage.Get(ctx, path)
	switch {
	case err != nil:
		return nil, false, err
	case entry == nil:
		return nil, false, nil
	}

	var key Key
	return &key, true, entry.DecodeJSON(&key)
}

// CoreView provides callbacks to interact with core components such as the
// namespace store.
type CoreView struct {
	GetStanza func(provider string) *server.ExternalKeysConfig

	// Allow returns an error if provider cannot be used in the passed namespace.
	Allow func(ctx context.Context, ns *namespace.Namespace, provider string) error

	// GetStorage gets a namespace's system barrier view.
	GetStorage func(ctx context.Context, ns *namespace.Namespace) (logical.Storage, error)

	// GetNamespace gets a namespace by path.
	GetNamespace func(ctx context.Context, path string) (*namespace.Namespace, error)
}

// Registry governs external key storage and provides access to external key
// instances to SystemView.
type Registry struct {
	ctx context.Context

	logger hclog.Logger

	// storageLocks is used to maintain consistency between configs and keys
	// in storage and between storage state and cache state. It is exposed to
	// external callers via LockStorage() and UnlockStorage().
	storageLocks []*locksutil.LockEntry

	// caches holds entries of type map[string]*cacheEntry by namespace path.
	// This enables per-namespace cache invalidation both for individual
	// namespaces and recursive namespace trees.
	caches *radix.Tree
	// cacheLock guards caches.
	cacheLock sync.Mutex

	core *CoreView // See CoreView.

	// Providers points to the global map of providers. This is public such that
	// it can be swapped out by tests without modifying the global provider map.
	Providers map[string]*Provider
}

// NewRegistry creates a new Registry.
func NewRegistry(ctx context.Context, logger hclog.Logger, core *CoreView) *Registry {
	return &Registry{
		ctx:          ctx,
		logger:       logger,
		storageLocks: locksutil.CreateLocks(),
		caches:       radix.New(),
		core:         core,
		Providers:    providers,
	}
}

// Request is a key access request. This is passed by SystemView.
type Request struct {
	// ConfigName is the config that is requested.
	ConfigName string
	// KeyName is the key that is requsted.
	KeyName string
	// Mount is the mount path of the plugin that sent the request.
	Mount string
	// IsSystem is true if the calling mount is a system mount.
	IsSystem bool
	// Namespace is the namespace of the caling mount.
	Namespace *namespace.Namespace
}

type cache map[string]*cacheEntry

type cacheEntry struct {
	store kms.KeyStore
	err   error
	init  sync.WaitGroup
}

func (r *Registry) getStorageLock(ns *namespace.Namespace, config string) *locksutil.LockEntry {
	key := fmt.Sprintf("%s/%s", ns.ID, config)
	return locksutil.LockForKey(r.storageLocks, key)
}

func (r *Registry) GetKey(ctx context.Context, req *Request) (kms.Key, error) {
	var (
		err     error
		exists  bool
		config  *Config
		storage logical.Storage
		lock    *locksutil.LockEntry
	)

	defer func() {
		if lock != nil {
			lock.RUnlock()
		}
	}()

	ns, name := req.Namespace, req.ConfigName

	// Walk namespaces until we find a non-inherited config.
	for {
		storage, err = r.core.GetStorage(ctx, ns)
		if err != nil {
			return nil, err
		}

		lock = r.getStorageLock(ns, name)
		lock.RLock()

		config, exists, err = ReadConfig(ctx, storage, ConfigPath(name))
		switch {
		case err != nil:
			return nil, err
		case !exists:
			return nil, fmt.Errorf("config %q not found", name)
		}

		if config.Provider != "" {
			// We've hit a concrete (non-inherited) config, done.
			break
		}

		lock.RUnlock()
		lock = nil

		// Move one namespace up.
		parent, ok := ns.ParentPath()
		if !ok {
			return nil, errors.New("cannot use inherited configs in root namespace; there is no namespace to inherit from")
		}
		ns, err = r.core.GetNamespace(ctx, parent)
		if err != nil {
			return nil, err
		}

		// Carry over the config name.
		name = config.Inherits
	}

	// Read the actual key entry.
	key, exists, err := ReadKey(ctx, storage, KeyPath(name, req.KeyName))
	switch {
	case err != nil:
		return nil, err
	case !exists:
		return nil, fmt.Errorf("key %q not found", req.KeyName)
	}

	// The config's namespace's system mount bypasses grant checks. As a
	// result, testing endpoints under /sys/external-keys are available without
	// explicitly adding a grant for the sys/ mount itself.
	if !req.IsSystem || ns.ID != req.Namespace.ID {
		// Check if this key can be used by the requesting mount. A key's grants may
		// include the relative path of a child namespace, so account for the delta
		// between the requesting namespace and the config's namespace.
		grant := strings.TrimPrefix(req.Namespace.Path, ns.Path) + req.Mount
		if !slices.Contains(key.Grants, grant) {
			return nil, fmt.Errorf("mount %q is not authorized to use key %q", req.Mount, req.KeyName)
		}
	}

	entry, rollback, ok := func() (*cacheEntry, func(), bool) {
		r.cacheLock.Lock()
		defer r.cacheLock.Unlock()

		var c cache
		if raw, ok := r.caches.Get(ns.Path); ok {
			c = raw.(cache)
		} else {
			c = make(cache)
			r.caches.Insert(ns.Path, c)
		}

		if entry, ok := c[name]; ok {
			return entry, nil, true
		}

		entry := &cacheEntry{}
		entry.init.Add(1)

		c[name] = entry

		rollback := func() {
			r.cacheLock.Lock()
			defer r.cacheLock.Unlock()
			delete(c, name)
		}

		return entry, rollback, false
	}()

	lock.RUnlock()
	lock = nil

	// Get the provider.
	prov, err := r.GetProvider(config.Provider)
	if err != nil {
		return nil, err
	}

	if ok {
		entry.init.Wait()

		if entry.err != nil {
			return nil, entry.err
		}

		return prov.getKMSKey(ctx, entry.store, key)
	}

	entry.store, entry.err = func() (kms.KeyStore, error) {
		// Check that the provider allows the namespace.
		if !prov.AllowsNamespace(ns) {
			return nil, fmt.Errorf("namespace %q cannot use provider %q", ns.Path, config.Provider)
		}

		// Check that the namespace allows the provider.
		if err := r.core.Allow(ctx, ns, config.Provider); err != nil {
			return nil, err
		}

		// Instantiate & log in the KMS client.
		return prov.newKMS(ctx, config)
	}()

	entry.init.Done()

	if entry.err != nil {
		rollback()
		return nil, entry.err
	}

	return prov.getKMSKey(ctx, entry.store, key)
}

func (r *Registry) InvalidateConfig(ctx context.Context, ns *namespace.Namespace, name string) {
	r.cacheLock.Lock()
	raw, ok := r.caches.Get(ns.Path)
	if !ok {
		r.cacheLock.Unlock()
		return
	}

	c := raw.(cache)
	entry, ok := c[name]
	if !ok {
		r.cacheLock.Unlock()
		return
	}

	delete(c, name)
	r.cacheLock.Unlock()

	entry.init.Wait()
	if entry.err != nil {
		return
	}

	if err := entry.store.Close(ctx); err != nil {
		r.logger.Error("failed to close KMS client", "namespace", ns.Path, "config", name, "error", err)
	}
}

func (r *Registry) RLockStorage(ctx context.Context, config string) func() {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		panic(err)
	}

	entry := r.getStorageLock(ns, config)
	entry.RLock()

	return entry.RUnlock
}

func (r *Registry) LockStorage(ctx context.Context, config string) (func(), func()) {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		panic(err)
	}

	entry := r.getStorageLock(ns, config)
	entry.Lock()

	called := false
	invalidate := func() { called = true }

	return func() {
		if !called {
			entry.Unlock()
			return
		}
		go func() {
			defer entry.Unlock()
			r.InvalidateConfig(r.ctx, ns, config)
		}()
	}, invalidate
}

func (r *Registry) InvalidateEntry(ctx context.Context, key string) error {
	// TODO(satoqz): Hook this up to core's cache invalidation once read
	// scalability is merged. This would likely parse the path and then call
	// into InvalidateConfig.
	return nil
}

func (r *Registry) InvalidateNamespace(ctx context.Context, path string) {
	r.cacheLock.Lock()
	raw, ok := r.caches.Delete(path)
	r.cacheLock.Unlock()

	if !ok {
		return
	}

	i := newInvalidator(ctx, r.logger)
	i.walk(path, raw)
	i.wg.Wait()
}

func (r *Registry) InvalidateNamespaceRecursive(ctx context.Context, path string) {
	i := newInvalidator(ctx, r.logger)

	r.cacheLock.Lock()
	r.caches.WalkPrefix(path, i.walk)
	r.caches.DeletePrefix(path)
	r.cacheLock.Unlock()

	i.wg.Wait()
}

type invalidator struct {
	ctx    context.Context
	logger hclog.Logger
	wg     sync.WaitGroup
}

func newInvalidator(ctx context.Context, logger hclog.Logger) *invalidator {
	return &invalidator{
		ctx:    ctx,
		logger: logger,
	}
}

func (i *invalidator) walk(path string, raw any) bool {
	for config, entry := range raw.(cache) {
		i.wg.Go(func() {
			entry.init.Wait()
			if entry.err != nil {
				return
			}

			if err := entry.store.Close(i.ctx); err != nil {
				i.logger.Error("failed to close KMS client", "namespace", path, "config", config, "error", err)
			}
		})
	}

	return false
}
