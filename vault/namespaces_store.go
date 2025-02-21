// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armon/go-metrics"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/base62"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Namespace id length; upstream uses 5 characters so we use one more to
// differentiate OpenBao from Vault Enterprise. This allows 2^35 entries; with
// fairly high probability, we'll hit a conflict here and have to regenerate
// but we shouldn't ever run out. This is also different from mount accessors
// (8 hex characters).
//
// See: https://developer.hashicorp.com/vault/api-docs/system/namespaces
const namespaceIdLength = 6

// Namespace storage location.
const namespaceStoreRoot = "core/namespaces/"

// NamespaceStore is used to provide durable storage of namespace. It is
// a singleton store across the Core and contains all child namespaces.
type NamespaceStore struct {
	core    *Core
	storage logical.Storage

	// This lock ensures we don't concurrently modify the store while using
	// a namespace entry. We also store an atomic to check if we need to
	// reload all namespaces.
	lock        sync.RWMutex
	invalidated atomic.Bool

	// List of all namespaces within the store. This is loaded at store
	// initialization time and persisted throughout the lifetime of the
	// instance. Entries should not be returned directly but instead be
	// copied to prevent modification.
	namespaces []*NamespaceEntry

	// logger is the server logger copied over from core
	logger hclog.Logger
}

// NamespaceEntry is used to store a namespace. We wrap namespace.Namespace
// in case there is additional data we wish to store that isn't relevant to
// a namespace instance.
type NamespaceEntry struct {
	UUID      string               `json:"uuid"`
	Namespace *namespace.Namespace `json:"namespace"`
}

// Clone performs a deep copy of the given entry.
func (ne *NamespaceEntry) Clone() *NamespaceEntry {
	meta := make(map[string]string, len(ne.Namespace.CustomMetadata))
	for k, v := range ne.Namespace.CustomMetadata {
		meta[k] = v
	}
	return &NamespaceEntry{
		UUID: ne.UUID,
		Namespace: &namespace.Namespace{
			ID:             ne.Namespace.ID,
			Path:           ne.Namespace.Path,
			CustomMetadata: meta,
		},
	}
}

func (ne *NamespaceEntry) Validate() error {
	if ne.Namespace == nil {
		return errors.New("interior namespace object is nil")
	}

	return ne.Namespace.Validate()
}

// NewNamespaceStore creates a new NamespaceStore that is backed
// using a given view. It used used to durable store and manage named namespace.
func NewNamespaceStore(ctx context.Context, core *Core, logger hclog.Logger) (*NamespaceStore, error) {
	ns := &NamespaceStore{
		core:    core,
		storage: core.barrier,
		logger:  logger,
	}

	// Add namespaces from storage to our table. We can do this without
	// holding a lock as we've not returned ns to anyone yet.
	if err := ns.loadNamespacesLocked(ctx); err != nil {
		return nil, fmt.Errorf("error loading initial namespaces: %w", err)
	}

	return ns, nil
}

func (ns *NamespaceStore) checkInvalidation(ctx context.Context) error {
	if !ns.invalidated.Load() {
		return nil
	}

	ns.lock.Lock()
	defer ns.lock.Unlock()

	// Status might have changed
	if !ns.invalidated.Load() {
		return nil
	}

	if err := ns.loadNamespacesLocked(ctx); err != nil {
		return fmt.Errorf("error handling invalidation: %w", err)
	}

	ns.invalidated.Store(false)
	return nil
}

// loadNamespaces loads all stored namespaces from disk. It assumes the lock
// is held when required.
func (ns *NamespaceStore) loadNamespacesLocked(ctx context.Context) error {
	// Assume we roughly have as many namespaces as we have presently. During
	// invalidation this will pre-allocate enough space to reload everything
	// as we'll likely be essentially in sync already. However, at startup, this
	// will mostly just give us space for the root namespace.
	allNamespaces := make([]*NamespaceEntry, 0, len(ns.namespaces)+1)
	allNamespaces = append(allNamespaces, &NamespaceEntry{Namespace: namespace.RootNamespace})

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		// TODO(ascheel): We'll need to keep track of newly found namespaces
		// here and recurse to find child namespaces.
		if err := logical.HandleListPage(s, namespaceStoreRoot, 100, func(page int, index int, entry string) (bool, error) {
			path := path.Join(namespaceStoreRoot, entry)

			item, err := s.Get(ctx, path)
			if err != nil {
				return false, fmt.Errorf("failed to fetch namespace %v (page %v / index %v): %w", path, page, index, err)
			}

			if item == nil {
				return false, fmt.Errorf("%v has an empty namespace definition (page %v / index %v)", path, page, index)
			}

			var namespace NamespaceEntry
			if err := item.DecodeJSON(&namespace); err != nil {
				return false, fmt.Errorf("failed to decode namespace %v (page %v / index %v): %w", path, page, index, err)
			}

			allNamespaces = append(allNamespaces, &namespace)

			return true, nil
		}, nil); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	ns.namespaces = allNamespaces

	return nil
}

// setupNamespaceStore is used to initialize the namespace store
// when the vault is being unsealed.
func (c *Core) setupNamespaceStore(ctx context.Context) error {
	// Create the Namespace store
	var err error
	nsLogger := c.baseLogger.Named("namespace")
	c.AddLogger(nsLogger)
	c.namespaceStore, err = NewNamespaceStore(ctx, c, nsLogger)
	return err
}

// teardownNamespaceStore is used to reverse setupNamespaceStore
// when the vault is being sealed.
func (c *Core) teardownNamespaceStore() error {
	c.namespaceStore = nil
	return nil
}

func (ns *NamespaceStore) invalidate(ctx context.Context, path string) error {
	// We want to keep invalidation proper fast (as it holds up replication),
	// so defer invalidation to the next load.
	//
	// TODO(ascheel): handle individual entry invalidation correctly. We'll
	// need to handle child namespace invalidation as well. sync.Map could be
	// used instead in the future alongside the actual boolean.
	ns.invalidated.Store(true)
	return nil
}

// SetNamespace is used to create or update a given namespace
func (ns *NamespaceStore) SetNamespace(ctx context.Context, namespace *NamespaceEntry) error {
	defer metrics.MeasureSince([]string{"namespace", "set_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	// Now grab write lock so that we can write to storage.
	ns.lock.Lock()
	defer ns.lock.Unlock()

	return ns.setNamespaceLocked(ctx, namespace)
}

// setNamespaceLocked must be called while holding a write lock over the
// NamespaceStore.
func (ns *NamespaceStore) setNamespaceLocked(ctx context.Context, namespace *NamespaceEntry) error {
	// Copy the entry before validating and potentially mutating it.
	entry := namespace.Clone()
	if err := entry.Validate(); err != nil {
		return fmt.Errorf("failed validating namespace: %w", err)
	}

	index := -1
	if entry.UUID == "" {
		id, err := ns.assignIdentifier(entry.Namespace.Path)
		if err != nil {
			return err
		}

		entry.Namespace.ID = id
		entry.UUID, err = uuid.GenerateUUID()
		if err != nil {
			return err
		}
	} else {
		// Ensure we have no conflicts for paths.
		for idx, existing := range ns.namespaces {
			if existing.UUID == entry.UUID {
				index = idx
				break
			}

			if existing.Namespace.ID == entry.Namespace.ID {
				return errors.New("namespace with specified accessor already exists")
			}

			if existing.Namespace.Path == entry.Namespace.Path {
				return errors.New("namespace with specified path already exists")
			}
		}
	}

	if err := ns.writeNamespace(ctx, entry); err != nil {
		return fmt.Errorf("failed to persist namespace: %w", err)
	}

	if index == -1 {
		ns.namespaces = append(ns.namespaces, entry)
	} else {
		ns.namespaces[index] = entry
	}

	// Since the write succeeded, copy back any potentially changed values.
	namespace.UUID = entry.UUID
	namespace.Namespace.ID = entry.Namespace.ID
	namespace.Namespace.Path = entry.Namespace.Path

	return nil
}

func (ns *NamespaceStore) writeNamespace(ctx context.Context, entry *NamespaceEntry) error {
	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		storagePath := path.Join(namespaceStoreRoot, entry.UUID)
		item, err := logical.StorageEntryJSON(storagePath, &entry)
		if err != nil {
			return fmt.Errorf("error marshalling storage entry: %w", err)
		}

		if err := s.Put(ctx, item); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return fmt.Errorf("error writing namespace: %w", err)
	}

	return nil
}

// / assignIdentifier assumes the lock is held.
func (ns *NamespaceStore) assignIdentifier(path string) (string, error) {
	for {
		id, err := base62.Random(namespaceIdLength)
		if err != nil {
			return "", fmt.Errorf("unable to generate namespace identifier: %w", err)
		}

		var found bool
		for _, existing := range ns.namespaces {
			if existing.Namespace.Path == path {
				return "", errors.New("unable to update when a namespace with this path already exists")
			}

			if existing.Namespace.ID == id {
				found = true
				break
			}
		}

		if found {
			continue
		}

		return id, nil
	}
}

// GetNamespace is used to fetch the namespace with the given uuid.
func (ns *NamespaceStore) GetNamespace(ctx context.Context, uuid string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	for _, item := range ns.namespaces {
		if item.UUID == uuid {
			return item.Clone(), nil
		}
	}

	return nil, nil
}

// GetNamespaceByAccessor is used to fetch the namespace with the given accessor.
func (ns *NamespaceStore) GetNamespaceByAccessor(ctx context.Context, id string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	for _, item := range ns.namespaces {
		if item.Namespace.ID == id {
			return item.Clone(), nil
		}
	}

	return nil, nil
}

// GetNamespaceByPath is used to fetch the namespace with the given path.
func (ns *NamespaceStore) GetNamespaceByPath(ctx context.Context, path string) (*NamespaceEntry, error) {
	defer metrics.MeasureSince([]string{"namespace", "get_namespace_by_path"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	path = namespace.Canonicalize(path)
	for _, item := range ns.namespaces {
		if item.Namespace.Path == path {
			return item.Clone(), nil
		}
	}

	return nil, nil
}

// ModifyNamespace is used to perform modifications to a namespace while
// holding a write lock to prevent other changes to namespaces from occurring
// at the same time.
func (ns *NamespaceStore) ModifyNamespaceByPath(ctx context.Context, path string, callback func(context.Context, *NamespaceEntry) (*NamespaceEntry, error)) error {
	defer metrics.MeasureSince([]string{"namespace", "modify_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	path = namespace.Canonicalize(path)
	if path == "" {
		return errors.New("refusing to modify root namespace")
	}

	var entry *NamespaceEntry
	for _, item := range ns.namespaces {
		if item.Namespace.Path == path {
			entry = item.Clone()
			break
		}
	}

	if entry == nil {
		entry = &NamespaceEntry{Namespace: &namespace.Namespace{}}
	}

	var err error
	entry, err = callback(ctx, entry)
	if err != nil {
		return err
	}

	return ns.setNamespaceLocked(ctx, entry)
}

// ListNamespaces is used to list all available namespaces
func (ns *NamespaceStore) ListNamespaces(ctx context.Context, includeRoot bool) ([]*namespace.Namespace, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespaces"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]*namespace.Namespace, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Clone().Namespace)
	}

	return entries, nil
}

// ListNamespaceUUIDs is used to list the uuids of available namespaces
func (ns *NamespaceStore) ListNamespaceUUIDs(ctx context.Context, includeRoot bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_uuids"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]string, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.UUID)
	}

	return entries, nil
}

// ListNamespaceAccessors is used to list the identifiers of available namespaces
func (ns *NamespaceStore) ListNamespaceAccessors(ctx context.Context, includeRoot bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_accessors"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]string, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Namespace.ID)
	}

	return entries, nil
}

// ListNamespacePaths is used to list the paths of all available namespaces
func (ns *NamespaceStore) ListNamespacePaths(ctx context.Context, includeRoot bool) ([]string, error) {
	defer metrics.MeasureSince([]string{"namespace", "list_namespace_paths"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return nil, err
	}

	ns.lock.RLock()
	defer ns.lock.RUnlock()

	entries := make([]string, 0, len(ns.namespaces))
	for _, item := range ns.namespaces {
		if !includeRoot && item.Namespace.ID == namespace.RootNamespaceID {
			continue
		}

		entries = append(entries, item.Namespace.Path)
	}

	return entries, nil
}

// DeleteNamespace is used to delete the named namespace
func (ns *NamespaceStore) DeleteNamespace(ctx context.Context, uuid string) error {
	defer metrics.MeasureSince([]string{"namespace", "delete_namespace"}, time.Now())

	if err := ns.checkInvalidation(ctx); err != nil {
		return err
	}

	// Now grab write lock so that we can write to storage.
	ns.lock.Lock()
	defer ns.lock.Unlock()

	index := -1
	for idx, item := range ns.namespaces {
		if item.UUID == uuid {
			if item.Namespace.ID == namespace.RootNamespaceID {
				return errors.New("unable to delete root namespace")
			}

			index = idx
			break
		}
	}

	if index == -1 {
		return nil
	}

	// We're guaranteed at least one item remaining since the root namespace
	// should always be present and not be removable.
	ns.namespaces = append(ns.namespaces[0:index], ns.namespaces[index+1:]...)

	if err := logical.WithTransaction(ctx, ns.storage, func(s logical.Storage) error {
		storagePath := path.Join(namespaceStoreRoot, uuid)
		return s.Delete(ctx, storagePath)
	}); err != nil {
		return err
	}

	return nil
}
