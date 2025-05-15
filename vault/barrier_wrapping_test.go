package vault

import (
	"context"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/stretchr/testify/require"
)

func TestWrappedBarrier_Basic(t *testing.T) {
	_, b, _ := mockBarrier(t)
	fb := NewForwardingBackend(b)
	wb, err := NewAESGCMBarrier(fb, "test/")
	require.NoError(t, err)

	testBarrier(t, wb)
}

func TestWrappedBarrier_DoubleEncryption(t *testing.T) {
	_, b, _ := mockBarrier(t)
	fb := NewForwardingBackend(b)
	wb, err := NewAESGCMBarrier(fb, "test/")
	require.NoError(t, err)
	err, _, _ = testInitAndUnseal(t, wb)
	require.NoError(t, err)

	seIn := logical.StorageEntry{Key: "testkey1", Value: []byte("testvalue1")}
	err = wb.Put(context.TODO(), &seIn)
	require.NoError(t, err)

	seOut, err := b.Get(context.TODO(), seIn.Key)
	require.NoError(t, err)
	require.Equal(t, seIn.Key, seOut.Key)
	require.NotEqual(t, seIn.Value, seOut.Value)

	pt, err := wb.Decrypt(context.TODO(), seIn.Key, seOut.Value)
	require.NoError(t, err)
	require.Equal(t, seIn.Value, pt)
}

func TestWrappedBarrier_Rotate(t *testing.T) {
	_, b, _ := mockBarrier(t)
	fb := NewForwardingBackend(b)
	wb, err := NewAESGCMBarrier(fb, "test/")
	require.NoError(t, err)

	testBarrier_Rotate(t, wb)
}
