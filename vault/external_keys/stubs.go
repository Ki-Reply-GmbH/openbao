package externalkeys

import (
	"context"
	"crypto"
	"crypto/cipher"

	"github.com/openbao/openbao/sdk/v2/logical"
)

// This file holds stubs that simulate the lifecycle of a KMS client.
// Everything here is to be replaced eventually by https://github.com/openbao/openbao/issues/1467.

type Factory interface {
	Type() string
	Create(ctx context.Context, config map[string]string) (logical.ExternalKey, error)
	Finalize(ctx context.Context) error
}

type (
	// A stub that implements [ExternalKeyFactory].
	stubFactory struct{}

	// A stub that implements [logical.ExternalKey].
	// It does not have any cryptographic capabilities.
	stubExternalKey struct{}
)

var (
	_ Factory             = (*stubFactory)(nil)
	_ logical.ExternalKey = (*stubExternalKey)(nil)
)

func (s *stubFactory) Type() string                       { return "stub" }
func (s *stubFactory) Finalize(ctx context.Context) error { return nil }
func (s *stubFactory) Create(ctx context.Context, config map[string]string) (logical.ExternalKey, error) {
	return &stubExternalKey{}, nil
}

func (s *stubExternalKey) Signer() (crypto.Signer, bool)       { return nil, false }
func (s *stubExternalKey) Decrypter() (crypto.Decrypter, bool) { return nil, false }
func (s *stubExternalKey) AEAD() (cipher.AEAD, bool)           { return nil, false }

// NewFactory creates a [factory] based on a config map.
func NewFactory(ctx context.Context, config map[string]string) (Factory, error) {
	return &stubFactory{}, nil
}
