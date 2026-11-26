// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	vaultseal "github.com/openbao/openbao/v2/internal/vault/seal"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// testStaticPrefixedAutoSeal returns an auto seal backed by the builtin static
// wrapper, storing its keys under the given prefix. The previous key, if set,
// remains usable for decryption.
func testStaticPrefixedAutoSeal(t *testing.T, c *Core, prefix, currentID string, currentSeed int, previousID string, previousSeed int) *autoSeal {
	t.Helper()

	config := map[string]string{
		"current_key_id": currentID,
		"current_key":    fmt.Sprintf("%064x", currentSeed),
	}
	if previousID != "" {
		config["previous_key_id"] = previousID
		config["previous_key"] = fmt.Sprintf("%064x", previousSeed)
	}

	w := static.NewWrapper()
	_, err := w.SetConfig(context.Background(), wrapping.WithConfigMap(config))
	require.NoError(t, err)

	s, err := NewAutoSeal(vaultseal.NewAccess(w))
	require.NoError(t, err)
	s.SetCore(c)
	s.SetMetaPrefix(prefix)
	return s
}

func TestAutoSeal_UpgradeKeysWithMetaPrefix(t *testing.T) {
	t.Parallel()

	const prefix = "namespaces/test-prefix/"

	tests := []struct {
		name      string
		currentID string
		seed      int
		wantKeyID string
	}{
		{
			name:      "stored keys are re-encrypted under the prefix when the key changes",
			currentID: "key-b",
			seed:      2,
			wantKeyID: "key-b",
		},
		{
			name:      "stored keys are left unchanged when the key is the same",
			currentID: "key-a",
			seed:      1,
			wantKeyID: "key-a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _, _ := TestCoreUnsealed(t)
			ctx := context.Background()

			// Store keys under the prefix with the initial key. Recovery
			// generation is deferred, so only the stored keys are upgraded.
			oldSeal := testStaticPrefixedAutoSeal(t, c, prefix, "key-a", 1, "", 0)
			require.NoError(t, oldSeal.SetRecoveryConfig(ctx, &SealConfig{}))
			barrierKey := []byte("0123456789abcdef0123456789abcdef")
			require.NoError(t, oldSeal.SetStoredKeys(ctx, [][]byte{barrierKey}))

			rootBefore, err := c.physical.Get(ctx, StoredBarrierKeysPath)
			require.NoError(t, err)

			newSeal := testStaticPrefixedAutoSeal(t, c, prefix, tt.currentID, tt.seed, "key-a", 1)
			require.NoError(t, newSeal.UpgradeKeys(ctx))

			// The keys under the prefix use the expected key and still
			// decrypt to the original value.
			pe, err := c.physical.Get(ctx, prefix+StoredBarrierKeysPath)
			require.NoError(t, err)
			require.NotNil(t, pe)
			blobInfo := &wrapping.BlobInfo{}
			require.NoError(t, proto.Unmarshal(pe.Value, blobInfo))
			require.Equal(t, tt.wantKeyID, blobInfo.KeyInfo.KeyId)

			keys, err := newSeal.GetStoredKeys(ctx)
			require.NoError(t, err)
			require.Equal(t, [][]byte{barrierKey}, keys)

			// The stored keys of the root namespace are untouched.
			rootAfter, err := c.physical.Get(ctx, StoredBarrierKeysPath)
			require.NoError(t, err)
			require.Equal(t, rootBefore, rootAfter)
		})
	}
}
