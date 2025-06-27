// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"errors"

	wrapping "github.com/openbao/go-kms-wrapping/v2"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/seal"
)

// SealAccess is a wrapper around Seal that exposes accessor methods
// through Core.SealAccess() while restricting the ability to modify
// Core.seal itself.
type SealAccess struct {
	seal Seal
}

func NewSealAccess(seal Seal) *SealAccess {
	return &SealAccess{seal: seal}
}

func (s *SealAccess) StoredKeysSupported() seal.StoredKeysSupport {
	return s.seal.StoredKeysSupported()
}

func (s *SealAccess) BarrierType() wrapping.WrapperType {
	return s.seal.BarrierType()
}

func (s *SealAccess) BarrierConfig(ctx context.Context, storage physical.Backend) (*SealConfig, error) {
	return s.seal.BarrierConfig(ctx, storage)
}

func (s *SealAccess) RecoveryKeySupported() bool {
	return s.seal.RecoveryKeySupported()
}

func (s *SealAccess) RecoveryConfig(ctx context.Context, storage physical.Backend) (*SealConfig, error) {
	autoSeal, ok := s.seal.(AutoSeal)
	if !ok {
		return nil, errors.New("not implemented")
	}
	return autoSeal.RecoveryConfig(ctx, storage)
}

func (s *SealAccess) ClearCaches() {
	s.seal.PurgeCachedBarrierConfig()
	if s.seal.RecoveryKeySupported() {
		s.seal.(AutoSeal).PurgeCachedRecoveryConfig()
	}
}
