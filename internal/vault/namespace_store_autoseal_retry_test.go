// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	"github.com/stretchr/testify/require"
)

// testWriteNamespaceKMSConfig overwrites the stored auto seal configuration of
// a namespace, which lives under the root barrier for a top-level namespace.
func testWriteNamespaceKMSConfig(t *testing.T, c *Core, ns *namespace.Namespace, keyID, key string) {
	t.Helper()
	buf, err := json.Marshal(&namespaceKMSConfig{
		Type: "static",
		Config: map[string]string{
			"current_key_id": keyID,
			"current_key":    key,
		},
	})
	require.NoError(t, err)
	require.NoError(t, c.barrier.Put(context.Background(), &logical.StorageEntry{
		Key:   NamespaceStoragePathPrefix(ns) + namespaceSealKMSConfigPath,
		Value: buf,
	}))
}

func TestNamespaceStore_AutoUnsealRetry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// breakConfig makes the auto seal of the namespace unusable at the
		// next boot, as an unreachable KMS would.
		breakConfig func(t *testing.T, c *Core, ns *namespace.Namespace)
		// fixViaAPI restores a working configuration through the config/seal
		// endpoint instead of writing it to storage directly.
		fixViaAPI bool
	}{
		{
			name: "stored keys cannot be decrypted",
			breakConfig: func(t *testing.T, c *Core, ns *namespace.Namespace) {
				testWriteNamespaceKMSConfig(t, c, ns, "test-key", fmt.Sprintf("%064x", 9))
			},
		},
		{
			name: "wrapper cannot be configured",
			breakConfig: func(t *testing.T, c *Core, ns *namespace.Namespace) {
				testWriteNamespaceKMSConfig(t, c, ns, "test-key", "")
			},
			fixViaAPI: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, rootShares, root := TestCoreUnsealed(t)
			rootCtx := namespace.RootContext(context.Background())
			ns := testCreateStaticNamespace(t, c)
			nsCtx := namespace.ContextWithNamespace(rootCtx, ns)

			// Store some data in the namespace.
			req := logical.TestRequest(t, logical.UpdateOperation, "sys/mounts/secret")
			req.ClientToken = root
			req.Data["type"] = "kv"
			_, err := c.HandleRequest(nsCtx, req)
			require.NoError(t, err)
			req = logical.TestRequest(t, logical.UpdateOperation, "secret/foo")
			req.ClientToken = root
			req.Data["value"] = "bar"
			_, err = c.HandleRequest(nsCtx, req)
			require.NoError(t, err)

			tt.breakConfig(t, c, ns)

			// Restart: the root namespace must unseal despite the namespace
			// auto seal failing, and the namespace must stay sealed.
			require.NoError(t, TestCoreSeal(c))
			// A real restart starts with no namespace seal in memory; drop the
			// one built before, which would otherwise still work.
			c.sealManager.RemoveNamespace(ns)
			for _, key := range rootShares {
				_, err := TestCoreUnseal(c, key)
				require.NoError(t, err)
			}
			require.False(t, c.Sealed(), "root namespace must unseal")

			ns, err = c.namespaceStore.GetNamespaceByPath(rootCtx, "foo/")
			require.NoError(t, err)
			require.NotNil(t, ns)
			require.True(t, c.NamespaceSealed(ns), "namespace must stay sealed")

			status, err := c.sealManager.SealStatus(rootCtx, ns)
			require.NoError(t, err)
			require.True(t, status.Sealed)
			require.Equal(t, "static", status.Type)

			// While the KMS is still unusable, a retry leaves it pending.
			require.Equal(t, 1, c.namespaceStore.retryPendingAutoUnseal(rootCtx))
			require.True(t, c.NamespaceSealed(ns))

			// Once the KMS works again, the retry unseals the namespace and
			// its data is available again.
			if tt.fixViaAPI {
				req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo/config/seal")
				req.Data["seal"] = testStaticSealStanza("")
				_, err := c.systemBackend.HandleRequest(rootCtx, req)
				require.NoError(t, err)
			} else {
				testWriteNamespaceKMSConfig(t, c, ns, "test-key", fmt.Sprintf("%064x", 1))
			}
			require.Equal(t, 0, c.namespaceStore.retryPendingAutoUnseal(rootCtx))
			require.False(t, c.NamespaceSealed(ns), "namespace must be unsealed after retry")
			require.Empty(t, c.sealManager.PendingAutoUnseal())

			req = logical.TestRequest(t, logical.ReadOperation, "secret/foo")
			req.ClientToken = root
			resp, err := c.HandleRequest(namespace.ContextWithNamespace(rootCtx, ns), req)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Equal(t, "bar", resp.Data["value"])
		})
	}
}
