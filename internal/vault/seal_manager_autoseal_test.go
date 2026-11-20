// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/helper/namespace"
	vaultseal "github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
)

// testStaticAccess returns a seal access backed by the builtin static
// wrapper, using the given key id and a key derived from seed.
func testStaticAccess(t *testing.T, keyID string, seed int) vaultseal.Access {
	t.Helper()
	w := static.NewWrapper()
	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(map[string]string{
		"current_key_id": keyID,
		"current_key":    fmt.Sprintf("%064x", seed),
	}))
	require.NoError(t, err)
	return vaultseal.NewAccess(w)
}

// corruptingAccess wraps a seal access and alters every decrypted value, to
// simulate a KMS configuration that does not round-trip correctly.
type corruptingAccess struct {
	vaultseal.Access
}

func (c *corruptingAccess) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, opts ...wrapping.Option) ([]byte, error) {
	pt, err := c.Access.Decrypt(ctx, blob, opts...)
	if err != nil {
		return nil, err
	}
	return append(pt, 0), nil
}

func TestVerifySealRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		access  func(t *testing.T) vaultseal.Access
		wantErr bool
	}{
		{
			name: "working seal passes",
			access: func(t *testing.T) vaultseal.Access {
				return testStaticAccess(t, "test-key", 1)
			},
		},
		{
			name: "seal returning a different value fails",
			access: func(t *testing.T) vaultseal.Access {
				return &corruptingAccess{Access: testStaticAccess(t, "test-key", 1)}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := verifySealRoundTrip(context.Background(), tt.access(t))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestVerifyNamespaceSealSwap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		seed    int
		wantErr bool
	}{
		{
			name: "same KMS key passes",
			seed: 1,
		},
		{
			name:    "different KMS key cannot decrypt stored keys",
			seed:    2,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _, _ := TestCoreUnsealed(t)
			rootCtx := namespace.RootContext(context.Background())

			// The namespace is created with the static key derived from seed 1.
			req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
			req.Data["seal"] = testStaticSealStanza("")
			_, err := c.systemBackend.HandleRequest(rootCtx, req)
			require.NoError(t, err)

			ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "foo/")
			require.NoError(t, err)
			require.NotNil(t, ns)

			newSeal, err := NewAutoSeal(testStaticAccess(t, "test-key", tt.seed))
			require.NoError(t, err)
			newSeal.SetCore(c)
			newSeal.SetMetaPrefix(NamespaceStoragePathPrefix(ns))

			err = verifyNamespaceSealSwap(rootCtx, newSeal)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
