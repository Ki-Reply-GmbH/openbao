// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/go-uuid"
	"github.com/openbao/openbao/builtin/plugin"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/versions"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// coreAuthConfigPath is used to store the auth configuration.
	// Auth configuration is protected within the Vault itself, which means it
	// can only be viewed or modified after an unseal.
	coreAuthConfigPath = "core/auth"

	// coreLocalAuthConfigPath is used to store credential configuration for
	// local (non-replicated) mounts
	coreLocalAuthConfigPath = "core/local-auth"

	// credentialBarrierPrefix is the prefix to the UUID used in the
	// barrier view for the credential backends.
	credentialBarrierPrefix = "auth/"

	// credentialRoutePrefix is the mount prefix used for the router
	credentialRoutePrefix = "auth/"

	// credentialTableType is the value we expect to find for the credential
	// table and corresponding entries
	credentialTableType = "auth"
)

var (
	// errLoadAuthFailed if loadCredentials encounters an error
	errLoadAuthFailed = errors.New("failed to setup auth table")

	// credentialAliases maps old backend names to new backend names, allowing us
	// to move/rename backends but maintain backwards compatibility
	credentialAliases = map[string]string{"aws-ec2": "aws"}

	// protectedAuths marks auth mounts that are protected and cannot be remounted
	protectedAuths = []string{
		"auth/token",
	}
)

// enableCredential is used to enable a new credential backend
func (c *Core) enableCredential(ctx context.Context, entry *MountEntry) error {
	// Ensure the token backend is a singleton
	if entry.Type == mountTypeToken || entry.Type == mountTypeNSToken {
		return errors.New("token credential backend cannot be instantiated")
	}

	// Enable credential internally
	if err := c.enableCredentialInternal(ctx, entry, MountTableUpdateStorage); err != nil {
		return err
	}

	return nil
}

// enableCredential is used to enable a new credential backend
func (c *Core) enableCredentialInternal(ctx context.Context, entry *MountEntry, updateStorage bool) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(entry.Path, "/") {
		entry.Path += "/"
	}

	// Ensure there is a name
	if entry.Path == "/" {
		return errors.New("backend path must be specified")
	}

	// not sure why we lock the mounts here
	c.mountsLock.Lock()
	c.authLock.Lock()
	locked := true
	unlock := func() {
		if locked {
			c.authLock.Unlock()
			c.mountsLock.Unlock()
			locked = false
		}
	}
	defer unlock()

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}
	entry.NamespaceID = ns.ID
	entry.namespace = ns

	// Basic check for matching names
	for _, ent := range c.auth.Entries {
		if ns.ID == ent.NamespaceID {
			switch {
			// Existing is oauth/github/ new is oauth/ or
			// existing is oauth/ and new is oauth/github/
			case strings.HasPrefix(ent.Path, entry.Path):
				fallthrough
			case strings.HasPrefix(entry.Path, ent.Path):
				return logical.CodedError(409, fmt.Sprintf("path is already in use at %s", ent.Path))
			}
		}
	}

	// Check for conflicts according to the router
	if conflict := c.router.MountConflict(ctx, credentialRoutePrefix+entry.Path); conflict != "" {
		return logical.CodedError(409, fmt.Sprintf("existing mount at %s", conflict))
	}

	// Generate a new UUID and view
	if entry.UUID == "" {
		entryUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.UUID = entryUUID
	}
	if entry.BackendAwareUUID == "" {
		bUUID, err := uuid.GenerateUUID()
		if err != nil {
			return err
		}
		entry.BackendAwareUUID = bUUID
	}
	if entry.Accessor == "" {
		accessor, err := c.generateMountAccessor("auth_" + entry.Type)
		if err != nil {
			return err
		}
		entry.Accessor = accessor
	}
	// Sync values to the cache
	entry.SyncCache()

	view, err := c.mountEntryView(entry)
	if err != nil {
		return err
	}

	origViewReadOnlyErr := view.GetReadOnlyErr()

	// Mark the view as read-only until the mounting is complete and
	// ensure that it is reset after. This ensures that there will be no
	// writes during the construction of the backend.
	view.SetReadOnlyErr(logical.ErrSetupReadOnly)
	defer view.SetReadOnlyErr(origViewReadOnlyErr)

	var backend logical.Backend
	// Create the new backend
	sysView := c.mountEntrySysView(entry)
	backend, entry.RunningSha256, err = c.newCredentialBackend(ctx, entry, sysView, view)
	if err != nil {
		return err
	}
	if backend == nil {
		return fmt.Errorf("nil backend returned from %q factory", entry.Type)
	}

	// Check for the correct backend type
	backendType := backend.Type()
	if backendType != logical.TypeCredential {
		return fmt.Errorf("cannot mount %q of type %q as an auth backend", entry.Type, backendType)
	}
	// update the entry running version with the configured version, which was verified during registration.
	entry.RunningVersion = entry.Version
	if entry.RunningVersion == "" {
		// don't set the running version to a builtin if it is running as an external plugin
		if entry.RunningSha256 == "" {
			entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeCredential, entry.Type)
		}
	}

	// Update the auth table
	newTable := c.auth.shallowClone()
	newTable.Entries = append(newTable.Entries, entry)
	if updateStorage {
		if err := c.persistAuth(ctx, nil, newTable, &entry.Local, entry.UUID); err != nil {
			c.logger.Error("failed to update auth table", "error", err)
			return fmt.Errorf("failed to update auth table: %w", err)
		}
	}

	c.auth = newTable

	if err := c.router.Mount(backend, credentialRoutePrefix+entry.Path, entry, view); err != nil {
		return err
	}

	// restore the original readOnlyErr, so we can write to the view in
	// Initialize() if necessary
	view.SetReadOnlyErr(origViewReadOnlyErr)
	// initialize, using the core's active context.
	err = backend.Initialize(c.activeContext, &logical.InitializationRequest{Storage: view})
	if err != nil {
		return err
	}

	if c.logger.IsInfo() {
		c.logger.Info("enabled credential backend", "namespace", entry.Namespace().Path, "path", entry.Path, "type", entry.Type, "version", entry.Version)
	}
	return nil
}

// disableCredential is used to disable an existing credential backend
func (c *Core) disableCredential(ctx context.Context, path string) error {
	// Ensure we end the path in a slash
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Ensure the token backend is not affected
	if path == "token/" && ns.Path == namespace.RootNamespace.Path {
		return errors.New("token credential backend cannot be disabled")
	}

	// Disable credential internally
	if err := c.disableCredentialInternal(ctx, path, MountTableUpdateStorage); err != nil {
		return err
	}

	return nil
}

func (c *Core) disableCredentialInternal(ctx context.Context, path string, updateStorage bool) error {
	path = credentialRoutePrefix + path

	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	// Verify exact match of the route
	match := c.router.MatchingMount(ctx, path)
	if match == "" || ns.Path+path != match {
		return errors.New("no matching mount")
	}

	// Get the view for this backend
	view := c.router.MatchingStorageByAPIPath(ctx, path)
	if view == nil {
		return fmt.Errorf("no matching storage %q", path)
	}

	// Get the backend/mount entry for this path, used to remove ignored
	// replication prefixes
	backend := c.router.MatchingBackend(ctx, path)

	// Mark the entry as tainted
	if err := c.taintCredEntry(ctx, ns.ID, path, updateStorage); err != nil {
		c.logger.Error("failed to taint credential entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Taint the router path to prevent routing
	if err := c.router.Taint(ctx, path); err != nil {
		return err
	}

	revokeCtx := namespace.ContextWithNamespace(c.activeContext, ns)

	if backend != nil && c.expiration != nil && updateStorage {
		// Revoke credentials from this path
		if err := c.expiration.RevokePrefix(revokeCtx, path, true); err != nil {
			return err
		}
	}

	if backend != nil {
		// Call cleanup function if it exists
		backend.Cleanup(revokeCtx)
	}

	switch {
	case !updateStorage:
		// Don't attempt to clear data, replication will handle this
	default:
		// Have writable storage, remove the whole thing
		if err := logical.ClearViewWithLogging(revokeCtx, view, c.logger.Named("auth.deletion").With("namespace", ns.Path, "path", path)); err != nil {
			c.logger.Error("failed to clear view for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	// Remove the mount table entry
	if err := c.removeCredEntry(revokeCtx, strings.TrimPrefix(path, credentialRoutePrefix), updateStorage); err != nil {
		c.logger.Error("failed to remove credential entry for path being unmounted", "error", err, "namespace", ns.Path, "path", path)
		return err
	}

	// Unmount the backend
	if err := c.router.Unmount(revokeCtx, path); err != nil {
		return err
	}

	if c.quotaManager != nil {
		if err := c.quotaManager.HandleBackendDisabling(revokeCtx, ns.Path, path); err != nil {
			c.logger.Error("failed to update quotas after disabling auth", "error", err, "namespace", ns.Path, "path", path)
			return err
		}
	}

	if c.logger.IsInfo() {
		c.logger.Info("disabled credential backend", "namespace", ns.Path, "path", path)
	}

	return nil
}

// removeCredEntry is used to remove an entry in the auth table
func (c *Core) removeCredEntry(ctx context.Context, path string, updateStorage bool) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Taint the entry from the auth table
	newTable := c.auth.shallowClone()
	entry, err := newTable.remove(ctx, path)
	if err != nil {
		return err
	}
	if entry == nil {
		c.logger.Error("nil entry found removing entry in auth table", "path", path)
		return logical.CodedError(500, "failed to remove entry in auth table")
	}

	if updateStorage {
		// Update the auth table
		if err := c.persistAuth(ctx, nil, newTable, &entry.Local, entry.UUID); err != nil {
			return fmt.Errorf("failed to update auth table: %w", err)
		}
	}

	c.auth = newTable

	return nil
}

func (c *Core) remountCredential(ctx context.Context, src, dst namespace.MountPathDetails, updateStorage bool) error {
	ns, err := namespace.FromContext(ctx)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(src.MountPath, credentialRoutePrefix) {
		return fmt.Errorf("cannot remount non-auth mount %q", src.MountPath)
	}

	if !strings.HasPrefix(dst.MountPath, credentialRoutePrefix) {
		return fmt.Errorf("cannot remount auth mount to non-auth mount %q", dst.MountPath)
	}

	for _, auth := range protectedAuths {
		if strings.HasPrefix(src.MountPath, auth) {
			return fmt.Errorf("cannot remount %q", src.MountPath)
		}
	}

	for _, auth := range protectedAuths {
		if strings.HasPrefix(dst.MountPath, auth) {
			return fmt.Errorf("cannot remount to %q", dst.MountPath)
		}
	}

	srcRelativePath := src.GetRelativePath(ns)
	dstRelativePath := dst.GetRelativePath(ns)

	// Verify exact match of the route
	srcMatch := c.router.MatchingMountEntry(ctx, srcRelativePath)
	if srcMatch == nil {
		return fmt.Errorf("no matching mount at %q", src.Namespace.Path+src.MountPath)
	}

	if match := c.router.MountConflict(ctx, dstRelativePath); match != "" {
		return fmt.Errorf("path in use at %q", match)
	}

	// Mark the entry as tainted
	if err := c.taintCredEntry(ctx, src.Namespace.ID, src.MountPath, updateStorage); err != nil {
		return err
	}

	// Taint the router path to prevent routing
	if err := c.router.Taint(ctx, srcRelativePath); err != nil {
		return err
	}

	if c.expiration != nil {
		revokeCtx := namespace.ContextWithNamespace(ctx, src.Namespace)
		// Revoke all the dynamic keys
		if err := c.expiration.RevokePrefix(revokeCtx, src.MountPath, true); err != nil {
			return err
		}
	}

	c.authLock.Lock()
	if match := c.router.MountConflict(ctx, dstRelativePath); match != "" {
		c.authLock.Unlock()
		return fmt.Errorf("path in use at %q", match)
	}

	srcMatch.Tainted = false
	srcMatch.NamespaceID = dst.Namespace.ID
	srcMatch.namespace = dst.Namespace
	srcPath := srcMatch.Path
	srcMatch.Path = strings.TrimPrefix(dst.MountPath, credentialRoutePrefix)

	// Update the mount table
	if err := c.persistAuth(ctx, nil, c.auth, &srcMatch.Local, srcMatch.UUID); err != nil {
		srcMatch.Path = srcPath
		srcMatch.Tainted = true
		c.authLock.Unlock()
		return fmt.Errorf("failed to update auth table with error %w", err)
	}

	// Remount the backend, setting the existing route entry
	// against the new path
	if err := c.router.Remount(ctx, srcRelativePath, dstRelativePath); err != nil {
		c.authLock.Unlock()
		return err
	}
	c.authLock.Unlock()

	// Un-taint the new path in the router
	if err := c.router.Untaint(ctx, dstRelativePath); err != nil {
		return err
	}

	return nil
}

// remountCredEntryForceInternal takes a copy of the mount entry for the path and fully
// unmounts and remounts the backend to pick up any changes, such as filtered
// paths. This should be only used internal.
func (c *Core) remountCredEntryForceInternal(ctx context.Context, path string, updateStorage bool) error {
	fullPath := credentialRoutePrefix + path
	me := c.router.MatchingMountEntry(ctx, fullPath)
	if me == nil {
		return fmt.Errorf("cannot find mount for path %q", path)
	}

	me, err := me.Clone()
	if err != nil {
		return err
	}

	if err := c.disableCredentialInternal(ctx, path, updateStorage); err != nil {
		return err
	}

	// Enable credential internally
	if err := c.enableCredentialInternal(ctx, me, updateStorage); err != nil {
		return err
	}

	return nil
}

// taintCredEntry is used to mark an entry in the auth table as tainted
func (c *Core) taintCredEntry(ctx context.Context, nsID, path string, updateStorage bool) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Taint the entry from the auth table
	// We do this on the original since setting the taint operates
	// on the entries which a shallow clone shares anyways
	entry, err := c.auth.setTaint(nsID, strings.TrimPrefix(path, credentialRoutePrefix), true, mountStateUnmounting)
	if err != nil {
		return err
	}

	// Ensure there was a match
	if entry == nil {
		return fmt.Errorf("no matching backend for path %q namespaceID %q", path, nsID)
	}

	if updateStorage {
		// Update the auth table
		if err := c.persistAuth(ctx, nil, c.auth, &entry.Local, entry.UUID); err != nil {
			return fmt.Errorf("failed to update auth table: %w", err)
		}
	}

	return nil
}

// loadCredentials is invoked as part of postUnseal to load the auth table
func (c *Core) loadCredentials(ctx context.Context) error {
	// Previously, this lock would be held after attempting to read the
	// storage entries. While we could never read corrupted entries,
	// we now need to ensure we can gracefully failover from legacy to
	// transactional auth mount table structure. This means holding the locks
	// for longer.
	//
	// Note that this lock is used for consistency with other code during
	// system operation (when mounting and unmounting auth engines), but
	// is not strictly necessary here as unseal(...) is serial and blocks
	// startup until finished.
	c.authLock.Lock()
	defer c.authLock.Unlock()

	// Start with an empty mount table.
	c.auth = nil

	// Migrating auth mounts from the previous single-entry to a transactional
	// variant requires careful surgery that should only be done in the
	// event the backend is transactionally aware. Otherwise, we'll continue
	// to use the legacy storage format indefinitely.
	//
	// This does mean that going backwards (from a transaction-aware storage
	// to not) is not possible without manual reconstruction.
	txnableBarrier, ok := c.barrier.(logical.TransactionalStorage)
	if !ok {
		_, err := c.loadLegacyCredentials(ctx, c.barrier)
		return err
	}

	// Create a write transaction in case we need to persist the initial
	// table or migrate from the old format.
	txn, err := txnableBarrier.BeginTx(ctx)
	if err != nil {
		return err
	}

	// Defer rolling back: we may commit the transaction anyways, but we
	// need to ensure the transaction is cleaned up in the event of an
	// error.
	defer txn.Rollback(ctx)

	legacy, err := c.loadLegacyCredentials(ctx, txn)
	if err != nil {
		return fmt.Errorf("failed to load legacy auth mounts in transaction: %w", err)
	}

	// If we have legacy auth mounts, migration was handled by the above. Otherwise,
	// we need to fetch the new auth mount table.
	if !legacy {
		c.logger.Info("reading transactional auth mount table")
		if err := c.loadTransactionalCredentials(ctx, txn); err != nil {
			return fmt.Errorf("failed to load transactional auth mount table: %w", err)
		}
	}

	// Finally, persist our changes.
	if err := txn.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit auth table changes: %w", err)
	}

	return nil
}

// This function reads the transactional split auth (credential) table.
func (c *Core) loadTransactionalCredentials(ctx context.Context, barrier logical.Storage) error {
	allNamespaces, err := c.ListNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to list namespaces: %w", err)
	}

	var needPersist bool
	globalEntries := make(map[string][]string, len(allNamespaces))
	localEntries := make(map[string][]string, len(allNamespaces))
	for index, ns := range allNamespaces {
		view := NamespaceView(barrier, ns)

		nsGlobal, nsLocal, err := c.listTransactionalCredentialsForNamespace(ctx, view)
		if err != nil {
			c.logger.Error("failed to list transactional mounts for namespace", "error", err, "ns_index", index, "namespace", ns.ID)
			return err
		}

		if len(nsGlobal) > 0 {
			globalEntries[ns.ID] = nsGlobal
		}

		if len(nsLocal) > 0 {
			localEntries[ns.ID] = nsLocal
		}
	}

	if len(globalEntries) == 0 {
		// TODO(ascheel) Assertion: globalEntries is empty iff there is only
		// one namespace (the root namespace).
		c.logger.Info("no auth mounts in transactional auth mount table; adding default auth mount table")
		c.auth, err = c.defaultAuthTable(ctx)
		if err != nil {
			panic(err.Error())
		}
		needPersist = true
	} else {
		c.auth = &MountTable{
			Type: credentialTableType,
		}

		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)
			for index, uuid := range globalEntries[ns.ID] {
				entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreAuthConfigPath, uuid)
				if err != nil {
					return fmt.Errorf("error loading auth mount table entry (%v (%v)/%v/%v): %w", ns.ID, nsIndex, index, uuid, err)
				}

				if entry != nil {
					c.auth.Entries = append(c.auth.Entries, entry)
				}
			}
		}

	}

	if len(localEntries) > 0 {
		for nsIndex, ns := range allNamespaces {
			view := NamespaceView(barrier, ns)

			for index, uuid := range localEntries[ns.ID] {
				entry, err := c.fetchAndDecodeMountTableEntry(ctx, view, coreLocalAuthConfigPath, uuid)
				if err != nil {
					return fmt.Errorf("error loading local auth mount table entry (%v (%v)/%v/%v): %w", ns.ID, nsIndex, index, uuid, err)
				}

				if entry != nil {
					c.auth.Entries = append(c.auth.Entries, entry)
				}
			}
		}
	}

	err = c.runCredentialUpdates(ctx, barrier, needPersist)
	if err != nil {
		c.logger.Error("failed to run legacy auth mount table upgrades", "error", err)
		return err
	}

	return nil
}

func (c *Core) listTransactionalCredentialsForNamespace(ctx context.Context, barrier logical.Storage) ([]string, []string, error) {
	globalEntries, err := barrier.List(ctx, coreAuthConfigPath+"/")
	if err != nil {
		return nil, nil, fmt.Errorf("failed listing core auth mounts: %w", err)
	}

	localEntries, err := barrier.List(ctx, coreLocalAuthConfigPath+"/")
	if err != nil {
		return nil, nil, fmt.Errorf("failed listing core local auth mounts: %w", err)
	}

	return globalEntries, localEntries, nil
}

// This function reads the legacy, single-entry combined auth mount table,
// returning true if it was used. This will let us know (if we're inside
// a transaction) if we need to do an upgrade.
func (c *Core) loadLegacyCredentials(ctx context.Context, barrier logical.Storage) (bool, error) {
	// Load the existing auth mount table
	raw, err := barrier.Get(ctx, coreAuthConfigPath)
	if err != nil {
		c.logger.Error("failed to read auth table", "error", err)
		return false, errLoadAuthFailed
	}
	rawLocal, err := barrier.Get(ctx, coreLocalAuthConfigPath)
	if err != nil {
		c.logger.Error("failed to read local auth table", "error", err)
		return false, errLoadAuthFailed
	}

	if raw != nil {
		authTable, err := c.decodeMountTable(ctx, raw.Value)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the auth table", "error", err)
			return false, err
		}
		c.auth = authTable
	}

	var needPersist bool
	if c.auth == nil {
		// In the event we are inside a transaction, we do not yet know if
		// we have a transactional mount table; exit early and load the new format.
		if _, ok := barrier.(logical.Transaction); ok {
			return false, nil
		}
		c.logger.Info("no mounts in legacy auth table; adding default mount table")
		c.auth, err = c.defaultAuthTable(ctx)
		if err != nil {
			panic(err.Error())
		}
		needPersist = true
	} else {
		if _, ok := barrier.(logical.Transaction); ok {
			// We know we have legacy mount table entries, so force a migration.
			c.logger.Info("migrating legacy mount table to transactional layout")
			needPersist = true
		}
		c.tableMetrics(len(c.auth.Entries), false, true, len(raw.Value))
	}
	if rawLocal != nil {
		localAuthTable, err := c.decodeMountTable(ctx, rawLocal.Value)
		if err != nil {
			c.logger.Error("failed to decompress and/or decode the legacy local auth mount table", "error", err)
			return false, err
		}
		if localAuthTable != nil && len(localAuthTable.Entries) > 0 {
			c.auth.Entries = append(c.auth.Entries, localAuthTable.Entries...)
			c.tableMetrics(len(localAuthTable.Entries), true, true, len(rawLocal.Value))
		}
	}

	// Here, we must call runCredentialUpdates:
	//
	// 1. We may be without any auth mount table and need to create the legacy
	//    table format because we don't have a transaction aware storage
	//    backend.
	// 2. We may have had a legacy auth mount table and need to upgrade into the
	//    new format. runCredentialUpdates will handle this for us.
	err = c.runCredentialUpdates(ctx, barrier, needPersist)
	if err != nil {
		c.logger.Error("failed to run legacy auth mount table upgrades", "error", err)
		return false, err
	}

	// We loaded a legacy auth mount table and successfully migrated it, if
	// necessary.
	return true, nil
}

// Note that this is only designed to work with singletons, as it checks by
// type only.
func (c *Core) runCredentialUpdates(ctx context.Context, barrier logical.Storage, needPersist bool) error {
	// Upgrade to typed auth table
	if c.auth.Type == "" {
		c.auth.Type = credentialTableType
		needPersist = true
	}

	// Upgrade to table-scoped entries
	for _, entry := range c.auth.Entries {
		if entry.Table == "" {
			entry.Table = c.auth.Type
			needPersist = true
		}
		if entry.Accessor == "" {
			accessor, err := c.generateMountAccessor("auth_" + entry.Type)
			if err != nil {
				return err
			}
			entry.Accessor = accessor
			needPersist = true
		}
		if entry.BackendAwareUUID == "" {
			bUUID, err := uuid.GenerateUUID()
			if err != nil {
				return err
			}
			entry.BackendAwareUUID = bUUID
			needPersist = true
		}

		// Don't store built-in version in the auth mount table, to make upgrades smoother.
		if versions.IsBuiltinVersion(entry.Version) {
			entry.Version = ""
			needPersist = true
		}

		if entry.NamespaceID == "" {
			entry.NamespaceID = namespace.RootNamespaceID
			needPersist = true
		}
		ns, err := c.NamespaceByID(ctx, entry.NamespaceID)
		if err != nil {
			return err
		}
		if ns == nil {
			return namespace.ErrNoNamespace
		}
		entry.namespace = ns

		// Sync values to the cache
		entry.SyncCache()
	}

	if !needPersist {
		return nil
	}

	if err := c.persistAuth(ctx, barrier, c.auth, nil, ""); err != nil {
		c.logger.Error("failed to persist auth table", "error", err)
		return errLoadAuthFailed
	}

	return nil
}

// persistAuth is used to persist the auth table after modification
func (c *Core) persistAuth(ctx context.Context, barrier logical.Storage, table *MountTable, local *bool, mount string) error {
	// Sometimes we may not want to explicitly pass barrier; fetch it if
	// necessary.
	if barrier == nil {
		barrier = c.barrier
	}

	// Gracefully handle a transaction-aware backend, if a transaction
	// wasn't created for us. This is safe as we do not support nested
	// transactions.
	needTxnCommit := false
	if txnBarrier, ok := barrier.(logical.TransactionalStorage); ok {
		var err error
		barrier, err = txnBarrier.BeginTx(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin transaction to persist auth mounts: %w", err)
		}

		needTxnCommit = true

		// In the event of an unexpected error, rollback this transaction.
		// A rollback of a committed transaction does not impact the commit.
		defer barrier.(logical.Transaction).Rollback(ctx)
	}

	if table.Type != credentialTableType {
		c.logger.Error("given table to persist has wrong type", "actual_type", table.Type, "expected_type", credentialTableType)
		return errors.New("invalid table type given, not persisting")
	}

	nonLocalAuth := &MountTable{
		Type: credentialTableType,
	}

	localAuth := &MountTable{
		Type: credentialTableType,
	}

	for _, entry := range table.Entries {
		if entry.Table != table.Type {
			c.logger.Error("given entry to persist in auth table has wrong table value", "path", entry.Path, "entry_table_type", entry.Table, "actual_type", table.Type)
			return errors.New("invalid auth entry found, not persisting")
		}

		if entry.Local {
			localAuth.Entries = append(localAuth.Entries, entry)
		} else {
			nonLocalAuth.Entries = append(nonLocalAuth.Entries, entry)
		}

		// We potentially modified the auth mount table entry so update the
		// map accordingly.
		entry.SyncCache()
	}

	// Handle writing the legacy auth mount table by default.
	writeTable := func(mt *MountTable, path string) (int, error) {
		// Encode the auth mount table into JSON and compress it (lzw).
		compressedBytes, err := jsonutil.EncodeJSONAndCompress(mt, nil)
		if err != nil {
			c.logger.Error("failed to encode or compress auth mount table", "error", err)
			return -1, err
		}

		// Create an entry
		entry := &logical.StorageEntry{
			Key:   path,
			Value: compressedBytes,
		}

		// Write to the physical backend
		if err := c.barrier.Put(ctx, entry); err != nil {
			c.logger.Error("failed to persist auth mount table", "error", err)
			return -1, err
		}
		return len(compressedBytes), nil
	}

	if _, ok := barrier.(logical.Transaction); ok {
		// Write a transactional-aware mount table series instead.
		writeTable = func(mt *MountTable, prefix string) (int, error) {
			var size int
			var found bool
			currentEntries := make(map[string]struct{}, len(mt.Entries))
			for index, mtEntry := range mt.Entries {
				if mount != "" && mtEntry.UUID != mount {
					continue
				}

				view := NamespaceView(barrier, mtEntry.Namespace())

				found = true
				currentEntries[mtEntry.UUID] = struct{}{}

				// Encode the mount table into JSON. There is little value in
				// compressing short entries.
				path := path.Join(prefix, mtEntry.UUID)
				encoded, err := jsonutil.EncodeJSON(mtEntry)
				if err != nil {
					c.logger.Error("failed to encode auth mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				// Create a storage entry.
				sEntry := &logical.StorageEntry{
					Key:   path,
					Value: encoded,
				}

				// Write to the backend.
				if err := view.Put(ctx, sEntry); err != nil {
					c.logger.Error("failed to persist auth mount table entry", "index", index, "uuid", mtEntry.UUID, "error", err)
					return -1, err
				}

				size += len(encoded)
			}

			if mount != "" && !found {
				// Delete this component if it exists. This signifies that
				// we're removing this mount. We don't know which namespace
				// this entry could belong to, so remove it from all.
				allNamespaces, err := c.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					view := NamespaceView(barrier, ns)
					path := path.Join(prefix, mount)
					if err := view.Delete(ctx, path); err != nil {
						return -1, fmt.Errorf("requested removal of auth mount from namespace %v (%v) but failed: %w", ns.ID, nsIndex, err)
					}
				}
			}

			if mount == "" {
				allNamespaces, err := c.ListNamespaces(ctx)
				if err != nil {
					return -1, fmt.Errorf("failed to list namespaces: %w", err)
				}

				for nsIndex, ns := range allNamespaces {
					view := NamespaceView(barrier, ns)

					// List all entries and remove any deleted ones.
					presentEntries, err := view.List(ctx, prefix+"/")
					if err != nil {
						return -1, fmt.Errorf("failed to list entries in namespace %v (%v) for removal: %w", ns.ID, nsIndex, err)
					}

					for index, presentEntry := range presentEntries {
						if _, present := currentEntries[presentEntry]; present {
							continue
						}

						if err := view.Delete(ctx, prefix+"/"+presentEntry); err != nil {
							return -1, fmt.Errorf("failed to remove deleted mount %v (%d) in namespace %v (%v): %w", presentEntry, index, ns.ID, nsIndex, err)
						}
					}
				}
			}

			// Finally, delete the legacy entries, if any.
			if err := barrier.Delete(ctx, prefix); err != nil {
				return -1, err
			}

			return size, nil
		}
	}

	var err error
	var compressedBytesLen int
	switch {
	case local == nil:
		// Write non-local mounts
		compressedBytesLen, err = writeTable(nonLocalAuth, coreAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(nonLocalAuth.Entries), false, true, compressedBytesLen)

		// Write local mounts
		compressedBytesLen, err = writeTable(localAuth, coreLocalAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(localAuth.Entries), true, true, compressedBytesLen)
	case *local:
		compressedBytesLen, err = writeTable(localAuth, coreLocalAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(localAuth.Entries), true, true, compressedBytesLen)
	default:
		compressedBytesLen, err = writeTable(nonLocalAuth, coreAuthConfigPath)
		if err != nil {
			return err
		}
		c.tableMetrics(len(nonLocalAuth.Entries), false, true, compressedBytesLen)
	}

	if needTxnCommit {
		if err := barrier.(logical.Transaction).Commit(ctx); err != nil {
			return fmt.Errorf("failed to persist mounts inside transaction: %w", err)
		}
	}

	return nil
}

// setupCredentials is invoked after we've loaded the auth table to
// initialize the credential backends and setup the router
func (c *Core) setupCredentials(ctx context.Context) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	for _, entry := range c.auth.sortEntriesByPathDepth().Entries {
		view, err := c.mountEntryView(entry)
		if err != nil {
			return err
		}

		origViewReadOnlyErr := view.GetReadOnlyErr()

		// Mark the view as read-only until the mounting is complete and
		// ensure that it is reset after. This ensures that there will be no
		// writes during the construction of the backend.
		view.SetReadOnlyErr(logical.ErrSetupReadOnly)
		if strutil.StrListContains(singletonMounts, entry.Type) {
			defer view.SetReadOnlyErr(origViewReadOnlyErr)
		}

		// Initialize the backend
		sysView := c.mountEntrySysView(entry)

		var backend logical.Backend
		backend, entry.RunningSha256, err = c.newCredentialBackend(ctx, entry, sysView, view)
		if err != nil {
			c.logger.Error("failed to create credential entry", "path", entry.Path, "error", err)

			if c.isMountable(ctx, entry, consts.PluginTypeCredential) {
				c.logger.Warn("skipping plugin-based auth entry", "path", entry.Path)
				goto ROUTER_MOUNT
			}
			return errLoadAuthFailed
		}
		if backend == nil {
			return fmt.Errorf("nil backend returned from %q factory", entry.Type)
		}

		// update the entry running version with the configured version, which was verified during registration.
		entry.RunningVersion = entry.Version
		if entry.RunningVersion == "" {
			// don't set the running version to a builtin if it is running as an external plugin
			if entry.RunningSha256 == "" {
				entry.RunningVersion = versions.GetBuiltinVersion(consts.PluginTypeCredential, entry.Type)
			}
		}

		// Do not start up deprecated builtin plugins. If this is a major
		// upgrade, stop unsealing and shutdown. If we've already mounted this
		// plugin, skip backend initialization and mount the data for posterity.
		if versions.IsBuiltinVersion(entry.RunningVersion) {
			_, err := c.handleDeprecatedMountEntry(ctx, entry, consts.PluginTypeCredential)
			if c.isMajorVersionFirstMount(ctx) && err != nil {
				go c.ShutdownCoreError(fmt.Errorf("could not mount %q: %w", entry.Type, err))
				return errLoadAuthFailed
			} else if err != nil {
				c.logger.Error("skipping deprecated auth entry", "name", entry.Type, "path", entry.Path, "error", err)
				backend.Cleanup(ctx)
				backend = nil
				goto ROUTER_MOUNT
			}
		}

		{
			// Check for the correct backend type
			backendType := backend.Type()
			if backendType != logical.TypeCredential {
				return fmt.Errorf("cannot mount %q of type %q as an auth backend", entry.Type, backendType)
			}
		}

	ROUTER_MOUNT:
		// Mount the backend
		path := credentialRoutePrefix + entry.Path
		err = c.router.Mount(backend, path, entry, view)
		if err != nil {
			c.logger.Error("failed to mount auth entry", "path", entry.Path, "namespace", entry.Namespace(), "error", err)
			return errLoadAuthFailed
		}

		if c.logger.IsInfo() {
			c.logger.Info("successfully mounted", "type", entry.Type, "version", entry.RunningVersion, "path", entry.Path, "namespace", entry.Namespace())
		}

		// Ensure the path is tainted if set in the mount table
		if entry.Tainted {
			// Calculate any namespace prefixes here, because when Taint() is called, there won't be
			// a namespace to pull from the context. This is similar to what we do above in c.router.Mount().
			path = entry.Namespace().Path + path
			c.logger.Debug("tainting a mount due to it being marked as tainted in mount table", "entry.path", entry.Path, "entry.namespace.path", entry.Namespace().Path, "full_path", path)
			c.router.Taint(ctx, path)
		}

		// Check if this is the token store
		if entry.Type == mountTypeToken {
			c.tokenStore = backend.(*TokenStore)

			// At some point when this isn't beta we may persist this but for
			// now always set it on mount
			entry.Config.TokenType = logical.TokenTypeDefaultService

			// this is loaded *after* the normal mounts, including cubbyhole
			c.router.tokenStoreSaltFunc = c.tokenStore.Salt
			c.tokenStore.cubbyholeBackend = c.router.MatchingBackend(ctx, mountPathCubbyhole).(*CubbyholeBackend)
		}

		// Initialize
		// Bind locally
		localEntry := entry
		c.postUnsealFuncs = append(c.postUnsealFuncs, func() {
			postUnsealLogger := c.logger.With("type", localEntry.Type, "version", localEntry.RunningVersion, "path", localEntry.Path)
			if backend == nil {
				postUnsealLogger.Error("skipping initialization for nil auth backend")
				return
			}
			if !strutil.StrListContains(singletonMounts, localEntry.Type) {
				view.SetReadOnlyErr(origViewReadOnlyErr)
			}

			err := backend.Initialize(ctx, &logical.InitializationRequest{Storage: view})
			if err != nil {
				postUnsealLogger.Error("failed to initialize auth backend", "error", err)
			}
		})
	}

	return nil
}

// teardownCredentials is used before we seal the vault to reset the credential
// backends to their unloaded state. This is reversed by loadCredentials.
func (c *Core) teardownCredentials(ctx context.Context) error {
	c.authLock.Lock()
	defer c.authLock.Unlock()

	if c.auth != nil {
		authTable := c.auth.shallowClone()
		for _, e := range authTable.Entries {
			backend := c.router.MatchingBackend(namespace.ContextWithNamespace(ctx, e.namespace), credentialRoutePrefix+e.Path)
			if backend != nil {
				backend.Cleanup(ctx)
			}
		}
	}

	c.auth = nil
	c.tokenStore = nil
	return nil
}

// newCredentialBackend is used to create and configure a new credential backend by name.
// It also returns the SHA256 of the plugin, if available.
func (c *Core) newCredentialBackend(ctx context.Context, entry *MountEntry, sysView logical.SystemView, view logical.Storage) (logical.Backend, string, error) {
	t := entry.Type
	if alias, ok := credentialAliases[t]; ok {
		t = alias
	}

	var runningSha string
	f, ok := c.credentialBackends[t]
	if !ok {
		plug, err := c.pluginCatalog.Get(ctx, t, consts.PluginTypeCredential, entry.Version)
		if err != nil {
			return nil, "", err
		}
		if plug == nil {
			errContext := t
			if entry.Version != "" {
				errContext += fmt.Sprintf(", version=%s", entry.Version)
			}
			return nil, "", fmt.Errorf("%w: %s", ErrPluginNotFound, errContext)
		}
		if len(plug.Sha256) > 0 {
			runningSha = hex.EncodeToString(plug.Sha256)
		}

		f = plugin.Factory
		if !plug.Builtin {
			f = wrapFactoryCheckPerms(c, plugin.Factory)
		}
	}
	// Set up conf to pass in plugin_name
	conf := make(map[string]string)
	for k, v := range entry.Options {
		conf[k] = v
	}

	switch {
	case entry.Type == "plugin":
		conf["plugin_name"] = entry.Config.PluginName
	default:
		conf["plugin_name"] = t
	}

	conf["plugin_type"] = consts.PluginTypeCredential.String()
	conf["plugin_version"] = entry.Version

	authLogger := c.baseLogger.Named(fmt.Sprintf("auth.%s.%s", t, entry.Accessor))
	c.AddLogger(authLogger)

	config := &logical.BackendConfig{
		StorageView: view,
		Logger:      authLogger,
		Config:      conf,
		System:      sysView,
		BackendUUID: entry.BackendAwareUUID,
	}

	b, err := f(ctx, config)
	if err != nil {
		return nil, "", err
	}

	return b, runningSha, nil
}

// defaultAuthTable creates a default auth table
func (c *Core) defaultAuthTable(ctx context.Context) (*MountTable, error) {
	ns, err := namespace.FromContext(ctx)
	if err != nil && !errors.Is(err, namespace.ErrNoNamespace) {
		return nil, err
	}
	if ns == nil {
		ns = namespace.RootNamespace
	}

	table := &MountTable{
		Type: credentialTableType,
	}
	tokenUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not generate UUID for default auth table token entry: %w", err)
	}
	tokenAccessor, err := c.generateMountAccessor("auth_token")
	if err != nil {
		return nil, fmt.Errorf("could not generate accessor for default auth table token entry: %w", err)
	}
	tokenBackendUUID, err := uuid.GenerateUUID()
	if err != nil {
		return nil, fmt.Errorf("could not create identity backend UUID: %w", err)
	}
	tokenAuth := &MountEntry{
		Table:            credentialTableType,
		Path:             "token/",
		Type:             mountTypeToken,
		Description:      "token based credentials",
		UUID:             tokenUUID,
		Accessor:         tokenAccessor,
		BackendAwareUUID: tokenBackendUUID,
		NamespaceID:      ns.ID,
		namespace:        ns,
	}

	if ns.ID != namespace.RootNamespaceID {
		tokenAuth.Type = mountTypeNSToken
	}

	table.Entries = append(table.Entries, tokenAuth)
	return table, nil
}
