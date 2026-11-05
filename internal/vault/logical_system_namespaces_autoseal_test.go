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

// testStaticSealStanza returns a seal stanza for the builtin static wrapper,
// which needs no external KMS, followed by the given extra settings.
func testStaticSealStanza(extra string) string {
	return fmt.Sprintf(`seal "static" {
    current_key_id = "test-key"
    current_key = "%064x"
%s
}`, 1, extra)
}

func TestNamespaceBackend_CreateAutoSeal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		seal          string
		wantErr       bool
		wantShares    int
		wantThreshold int
	}{
		{
			name: "recovery key shares are generated",
			seal: testStaticSealStanza(`    recovery_shares = 3
    recovery_threshold = 2`),
			wantShares:    3,
			wantThreshold: 2,
		},
		{
			name: "recovery key generation is deferred",
			seal: testStaticSealStanza(`    recovery_shares = 0
    recovery_threshold = 0`),
		},
		{
			name:    "recovery settings are required",
			seal:    testStaticSealStanza(""),
			wantErr: true,
		},
		{
			name: "shamir settings are rejected",
			seal: testStaticSealStanza(`    shares = 3
    threshold = 2`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, rootShares, _ := TestCoreUnsealed(t)
			b := c.systemBackend
			rootCtx := namespace.RootContext(context.Background())

			req := logical.TestRequest(t, logical.UpdateOperation, "namespaces/foo")
			req.Data["seal"] = tt.seal
			resp, err := b.HandleRequest(rootCtx, req)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, resp)

			if tt.wantShares > 0 {
				require.Len(t, resp.Data["recovery_key_shares"], tt.wantShares)
				require.Equal(t, tt.wantThreshold, resp.Data["recovery_key_threshold"])
			} else {
				require.NotContains(t, resp.Data, "recovery_key_shares")
			}
			require.NotContains(t, resp.Data, "key_shares")

			ns, err := c.namespaceStore.GetNamespaceByPath(rootCtx, "foo/")
			require.NoError(t, err)
			require.NotNil(t, ns)
			require.False(t, c.NamespaceSealed(ns), "namespace should start unsealed")

			// Restart the core: the namespace must be unsealed again
			// automatically, with no key shares supplied.
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
