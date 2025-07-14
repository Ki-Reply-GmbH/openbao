package externalkeys

import (
	"context"
	"encoding/json"
	"net/http"
	"path"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	// Storage location for External Keys (per namespace).
	StoragePrefix = "sys/external-keys/"

	subPathConfigs = "configs/"
	subPathKeys    = "keys/"
)

// Config is a config as written to storage.
type Config struct {
	// Config map passed to the KMS backend.
	Values map[string]string `json:"values"`
}

// Key is a key as written to storage.
type Key struct {
	// Config map passed to the KMS backend.
	Values map[string]string `json:"values"`
	// List of relative mount paths this key can be used by.
	Grants []string `json:"grants"`
}

type StorageContext struct {
	storage logical.Storage
}

func (r *Registry) StorageFor(ns *namespace.Namespace) *StorageContext {
	return &StorageContext{
		storage: logical.NewStorageView(r.namespacer.View(ns), StoragePrefix),
	}
}

func (sc *StorageContext) ListConfigs(ctx context.Context) ([]string, error) {
	return sc.storage.List(ctx, subPathConfigs)
}

func (sc *StorageContext) ReadConfig(ctx context.Context, args *Args) (*Config, error) {
	entry, err := sc.storage.Get(ctx, path.Join(subPathConfigs, args.Config))
	switch {
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, logical.CodedError(http.StatusNotFound, "config not found")
	default:
		var config Config
		return &config, json.Unmarshal(entry.Value, &config)
	}
}

func (sc *StorageContext) UpdateConfig(ctx context.Context, args *Args, create bool, f func(*Config) error) error {
	return logical.WithTransaction(ctx, sc.storage, func(storage logical.Storage) error {
		storagePath := path.Join(subPathConfigs, args.Config)

		entry, err := sc.storage.Get(ctx, storagePath)
		if err != nil {
			return err
		}

		var config Config
		switch {
		case entry != nil:
			if err := json.Unmarshal(entry.Value, &config); err != nil {
				return err
			}
		case create:
			config.Values = make(map[string]string)
		default:
			return logical.CodedError(http.StatusNotFound, "config not found")
		}

		if err := f(&config); err != nil {
			return err
		}

		b, err := json.Marshal(&config)
		if err != nil {
			return err
		}

		return sc.storage.Put(ctx, &logical.StorageEntry{
			Key:   storagePath,
			Value: b,
		})
	})
}

func (sc *StorageContext) DeleteConfigAndKeys(ctx context.Context, args *Args) error {
	return logical.WithTransaction(ctx, sc.storage, func(storage logical.Storage) error {
		// First, clear all keys:
		view := logical.NewStorageView(storage, path.Join(subPathKeys, args.Config)+"/")
		if err := logical.ClearView(ctx, view); err != nil {
			return err
		}

		// Then delete the config itself:
		return storage.Delete(ctx, path.Join(subPathConfigs, args.Config))
	})
}

func (sc *StorageContext) ListKeys(ctx context.Context, args *Args) ([]string, error) {
	// Ensure the config exists, there is a difference between "no keys" and "no config".
	entry, err := sc.storage.Get(ctx, path.Join(subPathConfigs, args.Config))
	switch {
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, logical.CodedError(http.StatusNotFound, "config not found")
	}

	return sc.storage.List(ctx, path.Join(subPathKeys, args.Config)+"/")
}

func (sc *StorageContext) ReadKey(ctx context.Context, args *Args) (*Key, error) {
	entry, err := sc.storage.Get(ctx, path.Join(subPathKeys, args.Config, args.Key))
	switch {
	case err != nil:
		return nil, err
	case entry == nil:
		return nil, logical.CodedError(http.StatusNotFound, "key not found")
	default:
		var key Key
		return &key, json.Unmarshal(entry.Value, &key)
	}
}

func (sc *StorageContext) UpdateKey(ctx context.Context, args *Args, create bool, f func(*Key) error) error {
	return logical.WithTransaction(ctx, sc.storage, func(storage logical.Storage) error {
		storagePath := path.Join(subPathKeys, args.Config, args.Key)

		entry, err := sc.storage.Get(ctx, storagePath)
		if err != nil {
			return err
		}

		var key Key
		switch {
		case entry != nil:
			if err := json.Unmarshal(entry.Value, &key); err != nil {
				return err
			}
		case create:
			key.Values = make(map[string]string)
			key.Grants = []string{}
		default:
			return logical.CodedError(http.StatusNotFound, "key not found")
		}

		if err := f(&key); err != nil {
			return err
		}

		b, err := json.Marshal(&key)
		if err != nil {
			return err
		}

		// Ensure that grants are always normalized.
		for i, grant := range key.Grants {
			key.Grants[i] = normalizeMount(grant)
		}

		return sc.storage.Put(ctx, &logical.StorageEntry{
			Key:   storagePath,
			Value: b,
		})
	})
}

func (sc *StorageContext) DeleteKey(ctx context.Context, args *Args) error {
	return sc.storage.Delete(ctx, path.Join(subPathKeys, args.Config, args.Key))
}
