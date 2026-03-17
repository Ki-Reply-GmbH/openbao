// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package seal

import (
	"context"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// SealAccess is a wrapper around Seal that exposes accessor methods
// through Core.SealAccess() while restricting the ability to modify
// Core.seal itself.
type SealAccess interface {
	StoredKeysSupported() StoredKeysSupport
	BarrierType() wrapping.WrapperType
	BarrierConfig(context.Context) (*SealConfig, error)
	RecoveryKeySupported() bool
	RecoveryConfig(context.Context) (*SealConfig, error)
	VerifyRecoveryKey(context.Context, []byte) error
	GetAccess() Wrapper
	RecoveryType() string
}
