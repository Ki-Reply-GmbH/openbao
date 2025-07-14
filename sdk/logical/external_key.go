// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package logical

import (
	"crypto"
	"crypto/cipher"
)

// ExternalKey is opaque cryptographic key material that provides access
// to a selection of standard cryptography interfaces.
type ExternalKey interface {
	// Signer derives a [crypto.Signer] if supported by
	// the underlying key and its configuration.
	Signer() (crypto.Signer, bool)

	// Decrypter derives a [crypto.Decrypter] if supported by
	// the underlying key and its configuration.
	Decrypter() (crypto.Decrypter, bool)

	// Decrypter derives a [cipher.AEAD] if supported
	// by the underlying key and its configuration.
	AEAD() (cipher.AEAD, bool)
}
