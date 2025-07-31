// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	uuid "github.com/hashicorp/go-uuid"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	aeadwrapper "github.com/openbao/go-kms-wrapping/wrappers/aead/v2"
	"github.com/openbao/openbao/helper/namespace"
	"github.com/openbao/openbao/helper/pgpkeys"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/shamir"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	vaultseal "github.com/openbao/openbao/vault/seal"
)

// TODO:
func (sm *SealManager) SetRotationConfig(ns *namespace.Namespace, recovery bool, newConfig *SealConfig) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	rotationConfig, ok := sm.rotationConfigByNamespace[ns.UUID]["default"]
	if !ok {
		return errors.New("namespace is not sealable")
	}

	if recovery {
		rotationConfig.recoveryConfig = newConfig
	} else {
		rotationConfig.barrierConfig = newConfig
	}

	return nil
}

// RotationConfig is used to read the rotation configuration
// of a namespace existing in context.
func (sm *SealManager) RotationConfig(ns *namespace.Namespace, recovery bool) *SealConfig {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	rotationConfig, ok := sm.rotationConfigByNamespace[ns.UUID]["default"]
	if !ok {
		return nil
	}

	// Copy the specified seal config
	if recovery {
		if rotationConfig.recoveryConfig != nil {
			return rotationConfig.recoveryConfig.Clone()
		}
	} else {
		if rotationConfig.barrierConfig != nil {
			return rotationConfig.barrierConfig.Clone()
		}
	}

	return nil
}

// RotationThreshold returns the secret threshold for the current seal config.
// This threshold can either be the barrier key threshold or the recovery key
// threshold, depending on whether rotation is being performed on the recovery
// key, or whether the seal supports recovery keys.
func (sm *SealManager) RotationThreshold(ctx context.Context, ns *namespace.Namespace, recovery bool) (int, logical.HTTPCodedError) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return 0, logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	var config *SealConfig
	var err error
	// If we are rotating the recovery key, or if the seal supports
	// recovery keys and we are rotating the barrier key, we use the
	// recovery config as the threshold instead.
	if recovery || seal.RecoveryKeySupported() {
		config, err = seal.RecoveryConfig(ctx)
	} else {
		config, err = seal.Config(ctx)
	}

	if err != nil {
		return 0, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("unable to look up config: %w", err).Error())
	}

	if config == nil {
		return 0, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	return config.SecretThreshold, nil
}

// RotationProgress is used to return the rotation progress (num shares).
func (sm *SealManager) RotationProgress(ns *namespace.Namespace, recovery, verification bool) (bool, int, error) {
	conf := sm.RotationConfig(ns, recovery)
	if conf == nil {
		return false, 0, errors.New("rotation operation not in progress")
	}

	if verification {
		return len(conf.VerificationKey) > 0, len(conf.VerificationProgress), nil
	}

	return true, len(conf.RekeyProgress), nil
}

// InitRotation will either initialize the rotation of barrier
// or recovery key depending on the value of recovery parameter.
func (sm *SealManager) InitRotation(ctx context.Context, ns *namespace.Namespace, newConfig *SealConfig, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	// Initialize the nonce for rotation operation
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error generating nonce for procedure: %w", err).Error())
	}

	currentRotationConfig := sm.RotationConfig(ns, recovery)
	if currentRotationConfig != nil {
		return nil, logical.CodedError(http.StatusBadRequest, "rotation already in progress")
	}

	if recovery {
		var initErr logical.HTTPCodedError
		initErr = sm.initRecoveryRotation(ns, newConfig, nonce)
		if initErr != nil {
			return nil, initErr
		}

		seal := sm.NamespaceSeal(ns)
		if seal == nil {
			return nil, logical.CodedError(http.StatusBadRequest, "namespace not sealable")
		}

		// if no key shares exist, meaning we've initalized the instance
		// without creating them at time, then return the keys immediately
		existingRecoveryConfig, err := seal.RecoveryConfig(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to fetch existing recovery config: %w", err).Error())
		}

		if existingRecoveryConfig == nil {
			return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
		}

		if existingRecoveryConfig.SecretShares == 0 {
			newRecoveryKey, result, err := sm.generateKey(ns, newConfig, true)
			if err != nil {
				return nil, err
			}

			// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
			if len(newConfig.PGPKeys) > 0 {
				var encryptError error
				result, encryptError = sm.pgpEncryptShares(ctx, newConfig, result)
				if encryptError != nil {
					return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
				}
			}

			// If we are requiring validation, return now; otherwise save the recovery key
			if newConfig.VerificationRequired {
				return sm.requireVerification(newConfig, result, newRecoveryKey)
			}

			if err := sm.core.performRecoveryRekey(ctx, newRecoveryKey, newConfig); err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery rotation: %w", err).Error())
			}

			if err := sm.SetRotationConfig(ns, recovery, nil); err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to reset recovery rotate config: %w", err).Error())
			}
			return result, nil
		}

		return nil, nil
	}

	return nil, sm.initBarrierRotation(ns, newConfig, nonce)
}

// initRecoveryRotation initializes rotation of recovery key.
func (sm *SealManager) initRecoveryRotation(ns *namespace.Namespace, config *SealConfig, nonce string) logical.HTTPCodedError {
	if config.StoredShares > 0 {
		return logical.CodedError(http.StatusBadRequest, "stored shares not supported by recovery key")
	}

	// Check if the seal configuration is valid
	// intentionally invoke the `Validate()` instead of `ValidateRecovery()`
	// deny the request if it does not pass the validation check
	if err := config.Validate(); err != nil {
		sm.logger.Error("invalid recovery configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("invalid recovery configuration: %w", err).Error())
	}

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	if !seal.RecoveryKeySupported() {
		return logical.CodedError(http.StatusBadRequest, "recovery keys not supported")
	}

	// Copy the configuration
	newConfig := config.Clone()
	newConfig.Nonce = nonce
	if err := sm.SetRotationConfig(ns, true, newConfig); err != nil {
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to update recovery rotate config: %w", err).Error())
	}

	if sm.logger.IsInfo() {
		sm.logger.Info("rotation initialized", "nonce", newConfig.Nonce, "shares", newConfig.SecretShares, "threshold", newConfig.SecretThreshold, "validation_required", newConfig.VerificationRequired)
	}

	return nil
}

// initBarrierRotation initializes rotation of barrier key.
func (sm *SealManager) initBarrierRotation(ns *namespace.Namespace, config *SealConfig, nonce string) logical.HTTPCodedError {
	if config.StoredShares != 1 {
		sm.logger.Warn("stored keys supported, forcing rotation shares/threshold to 1")
		config.StoredShares = 1
	}

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	if seal.WrapperType() != wrapping.WrapperTypeShamir {
		config.SecretShares = 1
		config.SecretThreshold = 1

		if len(config.PGPKeys) > 0 {
			return logical.CodedError(http.StatusBadRequest, "PGP key encryption not supported when using stored keys")
		}
		if config.Backup {
			return logical.CodedError(http.StatusBadRequest, "key backup not supported when using stored keys")
		}
	}

	if seal.RecoveryKeySupported() {
		if config.VerificationRequired {
			return logical.CodedError(http.StatusBadRequest, "requiring verification not supported when rotating the barrier key with recovery keys")
		}
		sm.logger.Debug("using recovery seal configuration to rotate barrier key")
	}

	// Check if the seal configuration is valid
	if err := config.Validate(); err != nil {
		sm.logger.Error("invalid rotate seal configuration", "error", err)
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("invalid rotate seal configuration: %w", err).Error())
	}

	newConfig := config.Clone()
	newConfig.Nonce = nonce
	if err := sm.SetRotationConfig(ns, false, newConfig); err != nil {
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to update barrier rotate config: %w", err).Error())
	}

	if sm.logger.IsInfo() {
		sm.logger.Info("rotation initialized", "namespace", ns.Path, "nonce", newConfig.Nonce, "shares", newConfig.SecretShares, "threshold", newConfig.SecretThreshold, "verification_required", newConfig.VerificationRequired)
	}

	return nil
}

// CancelRotation is used to cancel an in-progress rotation operation.
func (sm *SealManager) CancelRotation(ns *namespace.Namespace, recovery bool) error {
	return sm.SetRotationConfig(ns, recovery, nil)
}

// UpdateRotation is used to provide a new key share for the rotation
// of barrier or recovery key.
func (sm *SealManager) UpdateRotation(ctx context.Context, ns *namespace.Namespace, key []byte, nonce string, recovery bool) (*RekeyResult, logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	var config *SealConfig
	var err error
	var useRecovery bool
	if recovery || (seal.StoredKeysSupported() == vaultseal.StoredKeysSupportedGeneric && seal.RecoveryKeySupported()) {
		config, err = seal.RecoveryConfig(ctx)
		useRecovery = true
	} else {
		config, err = seal.Config(ctx)
	}

	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to fetch existing config: %w", err).Error())
	}

	if config == nil {
		return nil, logical.CodedError(http.StatusBadRequest, ErrNotInit.Error())
	}

	rotationConfig := sm.RotationConfig(ns, recovery)
	if rotationConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation in progress")
	}

	if recovery {
		return sm.updateRecoveryRotation(ctx, ns, config, key, nonce)
	}

	return sm.updateBarrierRotation(ctx, ns, config, key, nonce, useRecovery)
}

// updateRecoveryRotation is used to provide a new key share for recovery key rotation.
func (sm *SealManager) updateRecoveryRotation(ctx context.Context, ns *namespace.Namespace, config *SealConfig, key []byte, nonce string) (*RekeyResult, logical.HTTPCodedError) {
	rotationConfig := sm.RotationConfig(ns, true)
	recoveryKey, err := sm.progressRotation(rotationConfig, config, key, nonce)
	if err != nil {
		return nil, err
	}

	if recoveryKey == nil {
		return nil, nil
	}

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	// Verify the recovery key
	if err := seal.VerifyRecoveryKey(ctx, recoveryKey); err != nil {
		sm.logger.Error("recovery key verification failed", "error", err)
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Errorf("recovery key verification failed: %w", err).Error())
	}

	newRecoveryKey, result, err := sm.generateKey(ns, rotationConfig, true)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(rotationConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = sm.pgpEncryptShares(ctx, rotationConfig, result)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise save the recovery key
	if rotationConfig.VerificationRequired {
		return sm.requireVerification(rotationConfig, result, newRecoveryKey)
	}

	if err := sm.core.performRecoveryRekey(ctx, newRecoveryKey, rotationConfig); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery rotation: %w", err).Error())
	}

	if err := sm.SetRotationConfig(ns, true, nil); err != nil {
		return nil, logical.CodedError(http.StatusBadRequest, err.Error())
	}

	return result, nil
}

// updateBarrierRotation is used to provide a new key share for barrier key rotation.
func (sm *SealManager) updateBarrierRotation(ctx context.Context, ns *namespace.Namespace, config *SealConfig, key []byte, nonce string, useRecovery bool) (*RekeyResult, logical.HTTPCodedError) {
	rotationConfig := sm.RotationConfig(ns, false)
	recoveredKey, err := sm.progressRotation(rotationConfig, config, key, nonce)
	if err != nil {
		return nil, err
	}

	if recoveredKey == nil {
		return nil, nil
	}

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	switch {
	case useRecovery:
		if err := seal.VerifyRecoveryKey(ctx, recoveredKey); err != nil {
			sm.logger.Error("recovery key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, fmt.Errorf("recovery key verification failed: %w", err).Error())
		}
	case seal.WrapperType() == wrapping.WrapperTypeShamir:
		if seal.StoredKeysSupported() == vaultseal.StoredKeysSupportedShamirRoot {
			shamirWrapper := aeadwrapper.NewShamirWrapper()
			testseal := NewDefaultSeal(vaultseal.NewAccess(shamirWrapper))
			testseal.SetCore(sm.core)
			err := shamirWrapper.SetAesGcmKeyBytes(recoveredKey)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to setup unseal key: %w", err).Error())
			}

			cfg, err := seal.Config(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to setup test barrier config: %w", err).Error())
			}
			testseal.SetCachedConfig(cfg)

			stored, err := testseal.GetStoredKeys(ctx)
			if err != nil {
				return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to read root key: %w", err).Error())
			}
			recoveredKey = stored[0]
		}

		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, logical.CodedError(http.StatusBadRequest, err.Error())
		}

		barrier := sm.NamespaceBarrier(ns.Path)
		if barrier == nil {
			return nil, logical.CodedError(http.StatusBadRequest, "namespace is not sealable")
		}

		if err := barrier.VerifyRoot(recoveredKey); err != nil {
			sm.logger.Error("root key verification failed", "error", err)
			return nil, logical.CodedError(http.StatusBadRequest, fmt.Errorf("root key verification failed: %w", err).Error())
		}
	}

	// Generate a new key: for AutoUnseal, this is a new root key; for Shamir,
	// this is a new unseal key, and performBarrierRekey will also generate a
	// new root key.
	newKey, result, err := sm.generateKey(ns, rotationConfig, true)
	if err != nil {
		return nil, err
	}

	// If PGP keys are passed in, encrypt shares with corresponding PGP keys.
	if len(rotationConfig.PGPKeys) > 0 {
		var encryptError error
		result, encryptError = sm.pgpEncryptShares(ctx, rotationConfig, result)
		if encryptError != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, encryptError.Error())
		}
	}

	// If we are requiring validation, return now; otherwise rotate barrier key
	if rotationConfig.VerificationRequired {
		return sm.requireVerification(rotationConfig, result, newKey)
	}

	if err := sm.core.performBarrierRekey(ctx, newKey, rotationConfig); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to rotate barrier key: %w", err).Error())
	}

	if err := sm.SetRotationConfig(ns, false, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to reset barrier rotate config: %w", err).Error())
	}
	return result, nil
}

// progressRotation checks the key rotation progress, verifying if we have
// enough shares to recover the key.
func (sm *SealManager) progressRotation(rotationConfig, existingConfig *SealConfig, key []byte, nonce string) ([]byte, logical.HTTPCodedError) {
	if len(rotationConfig.VerificationKey) > 0 {
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("rotation operation already finished; verification must be performed; nonce for the verification operation is %q", rotationConfig.VerificationNonce))
	}

	if nonce != rotationConfig.Nonce {
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("incorrect nonce supplied; nonce for rotation operation is %q", rotationConfig.Nonce))
	}

	// Check if we already have this piece
	for _, existing := range rotationConfig.RekeyProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this rotation operation")
		}
	}

	// Store this key
	rotationConfig.RekeyProgress = append(rotationConfig.RekeyProgress, key)

	// Check if we don't have enough keys to unlock
	if len(rotationConfig.RekeyProgress) < existingConfig.SecretThreshold {
		if sm.logger.IsDebug() {
			sm.logger.Debug("cannot rotate yet, not enough keys", "keys", len(rotationConfig.RekeyProgress), "threshold", existingConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Recover the key
	var recoveredKey []byte
	if existingConfig.SecretThreshold == 1 {
		recoveredKey = rotationConfig.RekeyProgress[0]
	} else {
		var err error
		recoveredKey, err = shamir.Combine(rotationConfig.RekeyProgress)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to compute key: %w", err).Error())
		}
	}

	rotationConfig.RekeyProgress = nil
	return recoveredKey, nil
}

// generateKey generates a new root/recovery key dividing it into desired number of key shares.
func (sm *SealManager) generateKey(ns *namespace.Namespace, rotationConfig *SealConfig, recovery bool) ([]byte, *RekeyResult, logical.HTTPCodedError) {
	barrier := sm.NamespaceBarrier(ns.Path)
	if barrier == nil {
		return nil, nil, logical.CodedError(http.StatusBadRequest, "namespace is not sealable")
	}

	// Generate a new root/recovery key
	newKey, err := barrier.GenerateKey(sm.core.secureRandomReader)
	if err != nil {
		sm.logger.Error("failed to generate key", "error", err)
		return nil, nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("key generation failed: %w", err).Error())
	}

	result := &RekeyResult{
		Backup: rotationConfig.Backup,
	}

	seal := sm.NamespaceSeal(ns)
	if seal == nil {
		return nil, nil, logical.CodedError(http.StatusBadRequest, "namespace not sealable")
	}

	if recovery || seal.StoredKeysSupported() != vaultseal.StoredKeysSupportedGeneric {
		// Set result.SecretShares to the new key itself if only a single key
		// part is used -- no Shamir split required.
		if rotationConfig.SecretShares == 1 {
			result.SecretShares = append(result.SecretShares, newKey)
		} else {
			// Split the new key using the Shamir algorithm
			shares, err := shamir.Split(newKey, rotationConfig.SecretShares, rotationConfig.SecretThreshold)
			if err != nil {
				sm.logger.Error("failed to generate shares", "error", err)
				return nil, nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to generate shares: %w", err).Error())
			}
			result.SecretShares = shares
		}
	}
	return newKey, result, nil
}

// pgpEncryptShares encrypts the rotation secret shares using the provided pgp keys.
// If the rotation config also specifies backup, the backup information in saved to storage.
func (sm *SealManager) pgpEncryptShares(ctx context.Context, rotationConfig *SealConfig, rotationResult *RekeyResult) (*RekeyResult, error) {
	hexEncodedShares := make([][]byte, len(rotationResult.SecretShares))
	for i := range rotationResult.SecretShares {
		hexEncodedShares[i] = []byte(hex.EncodeToString(rotationResult.SecretShares[i]))
	}

	var err error
	rotationResult.PGPFingerprints, rotationResult.SecretShares, err = pgpkeys.EncryptShares(hexEncodedShares, rotationConfig.PGPKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt shares: %w", err)
	}

	// If backup is enabled, store backup info in vault.coreBarrierUnsealKeysBackupPath
	if rotationConfig.Backup {
		backupInfo := map[string][]string{}
		for i := 0; i < len(rotationResult.PGPFingerprints); i++ {
			encShare := bytes.NewBuffer(rotationResult.SecretShares[i])
			if backupInfo[rotationResult.PGPFingerprints[i]] == nil {
				backupInfo[rotationResult.PGPFingerprints[i]] = []string{hex.EncodeToString(encShare.Bytes())}
			} else {
				backupInfo[rotationResult.PGPFingerprints[i]] = append(backupInfo[rotationResult.PGPFingerprints[i]], hex.EncodeToString(encShare.Bytes()))
			}
		}

		backupVals := &RekeyBackup{
			Nonce: rotationConfig.Nonce,
			Keys:  backupInfo,
		}
		buf, err := json.Marshal(backupVals)
		if err != nil {
			sm.logger.Error("failed to marshal key backup", "error", err)
			return nil, fmt.Errorf("failed to marshal key backup: %w", err)
		}

		pe := &physical.Entry{
			Key:   coreRecoveryUnsealKeysBackupPath,
			Value: buf,
		}
		if err = sm.core.physical.Put(ctx, pe); err != nil {
			sm.logger.Error("failed to save unseal key backup", "error", err)
			return nil, fmt.Errorf("failed to save unseal key backup: %w", err)
		}
	}

	return rotationResult, nil
}

// requireVerification sets the verification properties on the
// rotationConfig adding nonce and required flag, returns the result.
func (sm *SealManager) requireVerification(rotationConfig *SealConfig, rotationResult *RekeyResult, newKey []byte) (*RekeyResult, logical.HTTPCodedError) {
	nonce, err := uuid.GenerateUUID()
	if err != nil {
		rotationConfig = nil
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to generate verification nonce: %w", err).Error())
	}
	rotationConfig.VerificationNonce = nonce
	rotationConfig.VerificationKey = newKey

	rotationResult.VerificationRequired = true
	rotationResult.VerificationNonce = nonce
	return rotationResult, nil
}

// VerifyRotation verifies the progress of the verification of the rotation operation.
func (sm *SealManager) VerifyRotation(ctx context.Context, ns *namespace.Namespace, key []byte, nonce string, recovery bool) (ret *RekeyVerifyResult, retErr logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	rotationConfig := sm.RotationConfig(ns, recovery)

	// Ensure a rotation is in progress
	if rotationConfig == nil {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation in progress")
	}

	if len(rotationConfig.VerificationKey) == 0 {
		return nil, logical.CodedError(http.StatusBadRequest, "no rotation verification in progress")
	}

	if nonce != rotationConfig.VerificationNonce {
		return nil, logical.CodedError(http.StatusBadRequest, fmt.Sprintf("incorrect nonce supplied; nonce for this verify operation is %q", rotationConfig.VerificationNonce))
	}

	// Check if we already have this piece
	for _, existing := range rotationConfig.VerificationProgress {
		if subtle.ConstantTimeCompare(existing, key) == 1 {
			return nil, logical.CodedError(http.StatusBadRequest, "given key has already been provided during this verify operation")
		}
	}

	// Store this key
	rotationConfig.VerificationProgress = append(rotationConfig.VerificationProgress, key)

	// Check if we don't have enough keys to unlock
	if len(rotationConfig.VerificationProgress) < rotationConfig.SecretThreshold {
		if sm.logger.IsDebug() {
			sm.logger.Debug("cannot verify yet, not enough keys", "keys", len(rotationConfig.VerificationProgress), "threshold", rotationConfig.SecretThreshold)
		}
		return nil, nil
	}

	// Defer reset of progress and rotation of the nonce
	defer func() {
		if ret != nil && ret.Complete {
			return
		}
		// Not complete, so rotate nonce
		nonce, err := uuid.GenerateUUID()
		if err == nil {
			rotationConfig.VerificationProgress = nil
			rotationConfig.VerificationNonce = nonce
			err = sm.SetRotationConfig(ns, recovery, rotationConfig)
			if err == nil && ret != nil {
				ret.Nonce = nonce
			}
		}
	}()

	// Recover the root key or recovery key
	var recoveredKey []byte
	if rotationConfig.SecretThreshold == 1 {
		recoveredKey = rotationConfig.VerificationProgress[0]
	} else {
		var err error
		recoveredKey, err = shamir.Combine(rotationConfig.VerificationProgress)
		if err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to compute key for verification: %w", err).Error())
		}
	}

	if subtle.ConstantTimeCompare(recoveredKey, rotationConfig.VerificationKey) != 1 {
		sm.logger.Error("rotation verification failed")
		return nil, logical.CodedError(http.StatusBadRequest, "rotation verification failed; incorrect key shares supplied")
	}

	if recovery {
		if err := sm.core.performRecoveryRekey(ctx, recoveredKey, rotationConfig); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform recovery key rotation: %w", err).Error())
		}
	} else {
		if err := sm.core.performBarrierRekey(ctx, recoveredKey, rotationConfig); err != nil {
			return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to perform barrier key rotation: %w", err).Error())
		}
	}

	if err := sm.SetRotationConfig(ns, recovery, nil); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to reset rotate config: %w", err).Error())
	}

	return &RekeyVerifyResult{
		Nonce:    rotationConfig.VerificationNonce,
		Complete: true,
	}, nil
}

// RestartRotationVerification is used to start the rotation verification process over.
func (sm *SealManager) RestartRotationVerification(ns *namespace.Namespace, recovery bool) logical.HTTPCodedError {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// Attempt to generate a new nonce, but don't bail if it doesn't succeed
	// (which is extraordinarily unlikely)
	nonce, nonceErr := uuid.GenerateUUID()
	rotationConfig := sm.RotationConfig(ns, recovery)

	// Clear any progress or config
	if rotationConfig != nil {
		rotationConfig.VerificationProgress = nil
		if nonceErr == nil {
			rotationConfig.VerificationNonce = nonce
		}
	}

	if err := sm.SetRotationConfig(ns, recovery, rotationConfig); err != nil {
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("failed to update recovery rotate config: %w", err).Error())
	}

	return nil
}

// RetrieveRotationBackup is used to retrieve any backed-up PGP-encrypted unseal keys.
func (sm *SealManager) RetrieveRotationBackup(ctx context.Context, ns *namespace.Namespace, recovery bool) (*RekeyBackup, logical.HTTPCodedError) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	var view BarrierView
	if recovery {
		view = sm.core.NamespaceView(ns).SubView(coreRecoveryUnsealKeysBackupPath)
	} else {
		view = sm.core.NamespaceView(ns).SubView(coreBarrierUnsealKeysBackupPath)
	}

	barrier := sm.core.sealManager.StorageAccessForPath(view.Prefix())
	entry, err := barrier.Get(ctx, view.Prefix())
	if err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error getting keys from backup: %w", err).Error())
	}
	if entry == nil {
		return nil, nil
	}

	ret := &RekeyBackup{}
	if err = jsonutil.DecodeJSON(entry, ret); err != nil {
		return nil, logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error decoding backup keys: %w", err).Error())
	}

	return ret, nil
}

// DeleteRotationBackup is used to delete any backed-up PGP-encrypted unseal keys.
func (sm *SealManager) DeleteRotationBackup(ctx context.Context, ns *namespace.Namespace, recovery bool) logical.HTTPCodedError {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	var view BarrierView
	if recovery {
		view = sm.core.NamespaceView(ns).SubView(coreRecoveryUnsealKeysBackupPath)
	} else {
		view = sm.core.NamespaceView(ns).SubView(coreBarrierUnsealKeysBackupPath)
	}

	barrier := sm.core.sealManager.StorageAccessForPath(view.Prefix())
	if err := barrier.Delete(ctx, view.Prefix()); err != nil {
		return logical.CodedError(http.StatusInternalServerError, fmt.Errorf("error deleting backup keys: %w", err).Error())
	}

	return nil
}
