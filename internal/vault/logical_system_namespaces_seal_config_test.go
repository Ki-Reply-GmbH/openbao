// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

// testStaticKeyStanza returns a seal stanza for the builtin static wrapper
// with the given current key and, if previousID is set, a previous key that
// remains usable for decryption.
func testStaticKeyStanza(currentID string, currentSeed int, previousID string, previousSeed int) string {
	previous := ""
	if previousID != "" {
		previous = fmt.Sprintf(`
    previous_key_id = "%s"
    previous_key = "%064x"`, previousID, previousSeed)
	}
	return fmt.Sprintf(`seal "static" {
    current_key_id = "%s"
    current_key = "%064x"%s
}`, currentID, currentSeed, previous)
}

// testCreateStaticNamespace creates the namespace foo/ protected by the
// static wrapper, using the key "test-key" derived from seed 1.
func testCreateStaticNamespace(t *testing.T, c *Core) *namespace.Namespace {
	t.Helper()
	rootCtx := namespace.RootContext(context.Background())

	req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
	req.Data["seal"] = testStaticSealStanza("")
	_, err := c.systemBackend.HandleRequest(rootCtx, req)
	require.NoError(t, err)

	ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "foo/")
	require.NoError(t, err)
	require.NotNil(t, ns)
	return ns
}

func TestNamespaceBackend_ReadSealConfig(t *testing.T) {
	t.Parallel()
	c, _, _ := TestCoreUnsealed(t)
	testCreateStaticNamespace(t, c)
	rootCtx := namespace.RootContext(context.Background())

	req := logical.TestRequest(t, logical.ReadOperation, "namespaces/foo/config/seal")
	resp, err := c.systemBackend.HandleRequest(rootCtx, req)
	require.NoError(t, err)
	require.Equal(t, "static", resp.Data["type"])

	metadata, ok := resp.Data["metadata"].(map[string]string)
	require.True(t, ok)
	require.Equal(t, "test-key", metadata["current_key_id"])
	require.NotContains(t, metadata, "current_key")
}

func TestNamespaceBackend_UpdateSealConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		seal    string
		wantErr bool
		// wantKeyID is the key id the stored keys must be encrypted with
		// after a successful update.
		wantKeyID string
	}{
		{
			name:      "rotation to a new key with the previous key still available",
			seal:      testStaticKeyStanza("key-2", 2, "test-key", 1),
			wantKeyID: "key-2",
		},
		{
			name:      "same key with a new configuration",
			seal:      testStaticKeyStanza("test-key", 1, "", 0),
			wantKeyID: "test-key",
		},
		{
			name:    "new key without access to the previous key is rejected",
			seal:    testStaticKeyStanza("key-2", 2, "", 0),
			wantErr: true,
		},
		{
			name: "recovery settings are rejected",
			seal: testStaticSealStanza(`    recovery_shares = 3
    recovery_threshold = 2`),
			wantErr: true,
		},
		{
			name: "shamir is rejected",
			seal: `seal "shamir" {
    shares = 3
    threshold = 2
}`,
			wantErr: true,
		},
		{
			name: "a different seal type is rejected",
			seal: `seal "transit" {
    address = "http://127.0.0.1:1"
    key_name = "test"
}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, rootShares, _ := TestCoreUnsealed(t)
			ns := testCreateStaticNamespace(t, c)
			rootCtx := namespace.RootContext(context.Background())

			req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/config/seal")
			req.Data["seal"] = tt.seal
			_, err := c.systemBackend.HandleRequest(rootCtx, req)
			if tt.wantErr {
				require.Error(t, err)

				// The previous configuration is kept intact.
				_, metadata, err := c.sealManager.NamespaceSealMetadata(ns)
				require.NoError(t, err)
				require.Equal(t, "test-key", metadata["current_key_id"])
				return
			}
			require.NoError(t, err)

			// The stored keys are now encrypted with the new key, so a seal
			// knowing only that key can read them.
			newSeal, err := NewAutoSeal(testStaticAccess(t, tt.wantKeyID, map[string]int{"test-key": 1, "key-2": 2}[tt.wantKeyID]))
			require.NoError(t, err)
			newSeal.SetCore(c)
			newSeal.SetMetaPrefix(NamespaceStoragePathPrefix(ns))
			require.NoError(t, verifyNamespaceSealSwap(rootCtx, newSeal))

			// Reloading from storage, as standby nodes do on invalidation,
			// yields the updated configuration.
			require.NoError(t, c.sealManager.ReloadNamespaceSeal(rootCtx, ns))
			_, metadata, err := c.sealManager.NamespaceSealMetadata(ns)
			require.NoError(t, err)
			require.Equal(t, tt.wantKeyID, metadata["current_key_id"])

			// After a restart, the namespace is unsealed with the new
			// configuration.
			require.NoError(t, TestCoreSeal(c))
			for _, key := range rootShares {
				_, err := TestCoreUnseal(c, key)
				require.NoError(t, err)
			}
			ns, err = c.namespaceStore.GetNamespaceByPath(rootCtx, "foo/")
			require.NoError(t, err)
			require.NotNil(t, ns)
			require.False(t, c.NamespaceSealed(ns), "namespace should be unsealed after restart")
		})
	}
}
