package externalkeys

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/require"
)

func TestGetExternalKey(t *testing.T) {
	registry, namespacer := TestRegistry(nil)
	ctx := namespace.RootContext(context.Background())

	args1 := &Args{
		Config: "my-config", Key: "my-key", Mount: "my-mount/",
	}

	require.NoError(t, registry.UpdateConfig(ctx, args1, true,
		func(config *Config) error {
			config.Values["type"] = "test"
			return nil
		}))

	require.NoError(t, registry.UpdateKey(ctx, args1, true,
		func(key *Key) error {
			key.Grants = append(key.Grants, args1.Mount)
			return nil
		}))

	key, err := registry.GetExternalKey(ctx, args1)
	require.NoError(t, err)
	require.NotNil(t, key)

	ns1 := namespacer.Add(&namespace.Namespace{
		Path:             "foo/",
		ExternalKeyTypes: []string{"test"},
	})

	args2 := &Args{
		Config: "inherit-from-root", Key: args1.Key, Mount: "my-child-mount/",
	}

	require.NoError(t, registry.UpdateKey(ctx, args1, true,
		func(key *Key) error {
			key.Grants = append(key.Grants, "foo/"+args2.Mount)
			return nil
		}))

	require.NoError(t, registry.UpdateConfig(ns1, args2, true,
		func(config *Config) error {
			config.Values["inherits"] = "my-config"
			return nil
		}))

	key, err = registry.GetExternalKey(ns1, args2)
	require.NoError(t, err)
	require.NotNil(t, key)

	ns2 := namespacer.Add(&namespace.Namespace{
		Path:             "foo/bar/",
		ExternalKeyTypes: []string{},
	})

	args3 := &Args{
		Config: "other-config", Key: "other-key",
	}

	require.NoError(t, registry.UpdateConfig(ns1, args3, true,
		func(config *Config) error {
			config.Values["type"] = "test"
			return nil
		}))

	args4 := &Args{
		Config: "inherit-from-non-root", Key: args3.Key, Mount: "my-other-mount/",
	}

	require.NoError(t, registry.UpdateKey(ns1, args3, true,
		func(key *Key) error {
			key.Grants = append(key.Grants, "bar/"+args4.Mount)
			return nil
		}))

	require.NoError(t, registry.UpdateConfig(ns2, args4, true,
		func(config *Config) error {
			config.Values["inherits"] = "other-config"
			return nil
		}))

	key, err = registry.GetExternalKey(ns2, args4)
	require.NoError(t, err)
	require.NotNil(t, key)
}
