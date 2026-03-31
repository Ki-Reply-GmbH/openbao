// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package extkey

import (
	"context"
	"maps"

	"github.com/openbao/openbao/sdk/v2/helper/locksutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// StoragePrefix is the per-namespace storage prefix used by External Keys.
	// This goes under /sys.
	StoragePrefix = "external-keys/"

	// KMSConfigPath is where KMSConfig entries are stored by name.
	KMSConfigPath = StoragePrefix + "configs/"

	// KeyConfigPath is where KeyConfig entries are stored by name.
	KeyConfigPath = StoragePrefix + "keys/"
)

// KMSConfig stores provider-level configuration.
type KMSConfig struct {
	Provider  string         `json:"provider"`
	ConfigMap map[string]any `json:"config_map"`
}

// KeyConfig stores key-level configuration.
type KeyConfig struct {
	Grants    []string       `json:"grants"`
	ConfigMap map[string]any `json:"config_map"`
}

// AsMap returns a map representation of this KMSConfig.
func (c *KMSConfig) AsMap() map[string]any {
	m := make(map[string]any, len(c.ConfigMap)+1)
	m["provider"] = c.Provider
	maps.Copy(m, c.ConfigMap)
	return m
}

// ReadKMSConfig reads a KMSConfig from storage.
func ReadKMSConfig(ctx context.Context, storage logical.Storage, path string) (*KMSConfig, error) {
	entry, err := storage.Get(ctx, path)
	if err != nil || entry == nil {
		return nil, err
	}
	var config KMSConfig
	return &config, entry.DecodeJSON(&config)
}

// ReadKeyConfig reads a KeyConfig from storage.
func ReadKeyConfig(ctx context.Context, storage logical.Storage, path string) (*KeyConfig, error) {
	entry, err := storage.Get(ctx, path)
	if err != nil || entry == nil {
		return nil, err
	}
	var key KeyConfig
	return &key, entry.DecodeJSON(&key)
}

// WriteConfig writes a Config to storage.
func WriteConfig(ctx context.Context, storage logical.Storage, path string, config *KMSConfig) error {
	entry, err := logical.StorageEntryJSON(path, config)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// WriteKeyConfig writes a KeyConfig to storage.
func WriteKeyConfig(ctx context.Context, storage logical.Storage, path string, key *KeyConfig) error {
	entry, err := logical.StorageEntryJSON(path, key)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

// Registry manages locking for External Key storage and provides access to
// instantiated keys to SystemView.
type Registry struct {
	// Locks are sharded by namespace to avoid globally blocking key usage while
	// writing a configuration update.
	locks []*locksutil.LockEntry
}

// NewRegistry returns a new Registry.
func NewRegistry() *Registry {
	return &Registry{
		locks: locksutil.CreateLocks(),
	}
}

// Lock acquires an exclusive lock over the given namespace and returns a
// function to release the lock.
func (r *Registry) Lock(path string) func() {
	lock := locksutil.LockForKey(r.locks, path)
	lock.Lock()
	return lock.Unlock
}

// RLock acquires a write-only lock over the given namespace and returns a
// function to release the lock.
func (r *Registry) RLock(path string) func() {
	lock := locksutil.LockForKey(r.locks, path)
	lock.RLock()
	return lock.RUnlock
}
