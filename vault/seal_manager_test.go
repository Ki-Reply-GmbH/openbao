package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/helper/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSealManager(t *testing.T) {
	core, keys, root := TestCoreUnsealed(t)

	rootCtx := namespace.RootContext(context.Background())
	ns := &namespace.Namespace{Path: "test/"}
	keyShares := TestCoreCreateSealedNamespaces(t, core, ns)
	require.NotEmpty(t, keyShares[ns.Path])

	sm := core.sealManager

	barrier := sm.NamespaceBarrier(ns.Path)
	require.NotNil(t, barrier)

	prefixBarrier := sm.NamespaceBarrierByLongestPrefix(ns.Path + "foo/")
	require.Equal(t, barrier, prefixBarrier)

	parentBarrier := sm.ParentNamespaceBarrier(ns)
	require.Equal(t, core.barrier, parentBarrier)

	sealStatus, err := sm.GetSealStatus(rootCtx, ns, true)
	require.NoError(t, err)
	require.NotNil(t, sealStatus)

	assert.False(t, sealStatus.Sealed)
	assert.True(t, sealStatus.Initialized)

	// Seal namespace
	err = sm.SealNamespace(rootCtx, ns)
	require.NoError(t, err)

	sealStatus, err = sm.GetSealStatus(rootCtx, ns, true)
	require.NoError(t, err)
	require.NotNil(t, sealStatus)

	assert.True(t, sealStatus.Sealed)
	assert.True(t, sealStatus.Initialized)
	assert.Equal(t, 0, sealStatus.Progress)

	// Unseal namespace again
	for i, key := range keyShares[ns.Path] {
		progress, _ := sm.SecretProgress(ns, true)
		assert.Equal(t, i, progress)

		require.NoError(t, err)

		err = sm.UnsealNamespace(rootCtx, ns, key)
		require.NoError(t, err)
	}

	sealStatus, err = sm.GetSealStatus(rootCtx, ns, true)
	require.NoError(t, err)
	require.NotNil(t, sealStatus)

	assert.False(t, sealStatus.Sealed)
	assert.True(t, sealStatus.Initialized)
	assert.Equal(t, 0, sealStatus.Progress)

	// Rotate namespace keyring
	keyring, err := barrier.Keyring()
	require.NoError(t, err)
	require.NotNil(t, keyring)

	assert.Equal(t, uint32(1), keyring.activeTerm)

	err = sm.RotateNamespaceBarrierKey(rootCtx, ns)
	require.NoError(t, err)

	keyring, err = barrier.Keyring()
	require.NoError(t, err)
	require.NotNil(t, keyring)

	assert.Equal(t, uint32(2), keyring.activeTerm)

	// Seal core
	err = core.Seal(root)
	require.NoError(t, err)

	// Unseal core again
	for i, key := range keys {
		unsealed, err := TestCoreUnseal(core, key)
		require.NoError(t, err)
		if i+1 == len(keys) {
			require.True(t, unsealed)
		}
	}

	sealStatus, err = sm.GetSealStatus(rootCtx, ns, true)
	require.NoError(t, err)
	require.NotNil(t, sealStatus)
	require.True(t, sealStatus.Sealed)
	require.True(t, sealStatus.Initialized)

	// Unseal namespace again
	for i := range 2 {
		progress, _ := sm.SecretProgress(ns, true)
		assert.Equal(t, i, progress)

		key := keyShares[ns.Path][i]
		require.NoError(t, err)

		err = sm.UnsealNamespace(rootCtx, ns, key)
		require.NoError(t, err)
	}

	sealStatus, err = sm.GetSealStatus(rootCtx, ns, true)
	require.NoError(t, err)
	require.NotNil(t, sealStatus)

	assert.False(t, sealStatus.Sealed)
	assert.True(t, sealStatus.Initialized)
	assert.Equal(t, 0, sealStatus.Progress)
}
