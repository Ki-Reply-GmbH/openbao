// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/vault/seal"
)

var (
	autoSealUnavailableDuration = []string{"seal", "unreachable", "time"}

	// vars for unit testings
	sealHealthTestIntervalNominal   = 10 * time.Minute
	sealHealthTestIntervalUnhealthy = 1 * time.Minute
	sealHealthTestTimeout           = 1 * time.Minute
)

// autoSeal is a Seal implementation that contains logic for encrypting and
// decrypting stored keys via an underlying AutoSealAccess implementation, as
// well as logic related to recovery keys and barrier config.
type autoSeal struct {
	seal.Access

	barrierType    wrapping.WrapperType
	barrierConfig  atomic.Value
	recoveryConfig atomic.Value

	hcLock          sync.Mutex
	healthCheckStop chan struct{}
}

type AutoSeal interface {
	Seal
	Init(context.Context) error
	Finalize(context.Context) error
	RecoveryType() string
	RecoveryConfig(context.Context, physical.Backend) (*SealConfig, error) // SealAccess
	RecoveryKey(context.Context, physical.Backend) ([]byte, error)
	SetRecoveryConfig(context.Context, physical.Backend, *SealConfig) error
	SetCachedRecoveryConfig(*SealConfig)
	PurgeCachedRecoveryConfig()
	SetRecoveryKey(context.Context, physical.Backend, []byte) error
	VerifyRecoveryKey(context.Context, physical.Backend, []byte) error // SealAccess
}

// Ensure we are implementing the Seal interface
var _ AutoSeal = (*autoSeal)(nil)

func NewAutoSeal(lowLevel seal.Access) (*autoSeal, error) {
	ret := &autoSeal{
		Access: lowLevel,
	}
	ret.barrierConfig.Store((*SealConfig)(nil))
	ret.recoveryConfig.Store((*SealConfig)(nil))

	// Having the wrapper type in a field is just a convenience since Seal.BarrierType()
	// does not return an error.
	var err error
	ret.barrierType, err = ret.Type(context.Background())
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (d *autoSeal) GetAccess() seal.Access {
	return d.Access
}

func (d *autoSeal) Init(ctx context.Context) error {
	return d.Access.Init(ctx)
}

func (d *autoSeal) Finalize(ctx context.Context) error {
	return d.Access.Finalize(ctx)
}

func (d *autoSeal) BarrierType() wrapping.WrapperType {
	return d.barrierType
}

func (d *autoSeal) StoredKeysSupported() seal.StoredKeysSupport {
	return seal.StoredKeysSupportedGeneric
}

func (d *autoSeal) RecoveryKeySupported() bool {
	return true
}

// SetStoredKeys uses the autoSeal.Access.Encrypts method to wrap the keys. The stored entry
// does not need to be seal wrapped in this case.
func (d *autoSeal) SetStoredKeys(ctx context.Context, storage physical.Backend, keys [][]byte) error {
	return writeStoredKeys(ctx, storage, d.Access, keys)
}

// GetStoredKeys retrieves the key shares by unwrapping the encrypted key using the
// autoseal.
func (d *autoSeal) GetStoredKeys(ctx context.Context, storage physical.Backend) ([][]byte, error) {
	return readStoredKeys(ctx, storage, d.Access)
}

func (d *autoSeal) upgradeStoredKeys(ctx context.Context, storage physical.Backend) error {
	pe, err := storage.Get(ctx, StoredBarrierKeysPath)
	if err != nil {
		return fmt.Errorf("failed to fetch stored keys: %w", err)
	}
	if pe == nil {
		return errors.New("no stored keys found")
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return fmt.Errorf("failed to proto decode stored keys: %w", err)
	}

	keyId, err := d.Access.KeyId(ctx)
	if err != nil {
		return err
	}
	if blobInfo.KeyInfo != nil && blobInfo.KeyInfo.KeyId != keyId {
		pt, err := d.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted stored keys: %w", err)
		}

		// Decode the barrier entry
		var keys [][]byte
		if err := json.Unmarshal(pt, &keys); err != nil {
			return fmt.Errorf("failed to decode stored keys: %w", err)
		}

		if err := d.SetStoredKeys(ctx, storage, keys); err != nil {
			return fmt.Errorf("failed to save upgraded stored keys: %w", err)
		}
	}
	return nil
}

// UpgradeKeys re-encrypts and saves the stored keys and the recovery key
// with the current key if the current KeyId is different from the KeyId
// the stored keys and the recovery key are encrypted with. The provided
// Context must be non-nil.
func (d *autoSeal) UpgradeKeys(ctx context.Context, storage physical.Backend) error {
	// Many of the seals update their keys to the latest KeyId when Encrypt
	// is called.
	if _, err := d.Encrypt(ctx, []byte("a"), nil); err != nil {
		return err
	}

	if err := d.upgradeRecoveryKey(ctx, storage); err != nil {
		return err
	}
	if err := d.upgradeStoredKeys(ctx, storage); err != nil {
		return err
	}
	return nil
}

func (d *autoSeal) BarrierConfig(ctx context.Context, storage physical.Backend) (*SealConfig, error) {
	if d.barrierConfig.Load().(*SealConfig) != nil {
		return d.barrierConfig.Load().(*SealConfig).Clone(), nil
	}

	sealType := "barrier"

	entry, err := storage.Get(ctx, barrierSealConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q seal configuration: %w", sealType, err)
	}

	// If the seal configuration is missing, we are not initialized
	if entry == nil {
		return nil, nil
	}

	conf := &SealConfig{}
	err = json.Unmarshal(entry.Value, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %q seal configuration: %w", sealType, err)
	}

	// Check for a valid seal configuration
	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("%q seal validation failed: %w", sealType, err)
	}

	if conf.Type != d.BarrierType().String() {
		return nil, fmt.Errorf("barrier seal type of %q does not match loaded type of %q", conf.Type, d.BarrierType())
	}

	d.SetCachedBarrierConfig(conf)
	return conf.Clone(), nil
}

func (d *autoSeal) SetBarrierConfig(ctx context.Context, storage physical.Backend, conf *SealConfig, _ bool) error {
	conf.Type = d.BarrierType().String()

	// Encode the seal configuration
	buf, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to encode barrier seal configuration: %w", err)
	}

	// Store the seal configuration
	pe := &physical.Entry{
		Key:   barrierSealConfigPath,
		Value: buf,
	}

	if err := storage.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to write barrier seal configuration: %w", err)
	}

	d.SetCachedBarrierConfig(conf.Clone())

	return nil
}

func (d *autoSeal) PurgeCachedBarrierConfig() {
	d.barrierConfig.Store((*SealConfig)(nil))
}

func (d *autoSeal) SetCachedBarrierConfig(config *SealConfig) {
	d.barrierConfig.Store(config)
}

func (d *autoSeal) RecoveryType() string {
	return RecoveryTypeShamir
}

// RecoveryConfig returns the recovery config on recoverySealConfigPath.
func (d *autoSeal) RecoveryConfig(ctx context.Context, storage physical.Backend) (*SealConfig, error) {
	if d.recoveryConfig.Load().(*SealConfig) != nil {
		return d.recoveryConfig.Load().(*SealConfig).Clone(), nil
	}

	sealType := "recovery"

	entry, err := storage.Get(ctx, recoverySealConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q seal configuration: %w", sealType, err)
	}

	// If the seal configuration is missing, we are not initialized
	if entry == nil {
		return nil, nil
	}

	conf := &SealConfig{}
	if err := json.Unmarshal(entry.Value, conf); err != nil {
		return nil, fmt.Errorf("failed to decode %q seal configuration: %w", sealType, err)
	}

	// Check for a valid seal configuration
	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("%q seal validation failed: %w", sealType, err)
	}

	if conf.Type != d.RecoveryType() {
		return nil, fmt.Errorf("recovery seal type of %q does not match loaded type of %q", conf.Type, d.RecoveryType())
	}

	d.SetCachedRecoveryConfig(conf)
	return conf.Clone(), nil
}

// SetRecoveryConfig writes the recovery configuration to the physical storage
// and sets it as the seal's recoveryConfig.
func (d *autoSeal) SetRecoveryConfig(ctx context.Context, storage physical.Backend, conf *SealConfig) error {
	conf.Type = d.RecoveryType()

	// Encode the seal configuration
	buf, err := json.Marshal(conf)
	if err != nil {
		return fmt.Errorf("failed to encode recovery seal configuration: %w", err)
	}

	// Store the seal configuration directly in the physical storage
	pe := &physical.Entry{
		Key:   recoverySealConfigPath,
		Value: buf,
	}

	if err := storage.Put(ctx, pe); err != nil {
		return fmt.Errorf("failed to write recovery seal configuration: %w", err)
	}

	d.recoveryConfig.Store(conf.Clone())

	return nil
}

func (d *autoSeal) PurgeCachedRecoveryConfig() {
	d.recoveryConfig.Store((*SealConfig)(nil))
}

func (d *autoSeal) SetCachedRecoveryConfig(config *SealConfig) {
	d.recoveryConfig.Store(config)
}

func (d *autoSeal) VerifyRecoveryKey(ctx context.Context, storage physical.Backend, key []byte) error {
	if key == nil {
		return errors.New("recovery key to verify is nil")
	}

	pt, err := d.getRecoveryKeyInternal(ctx, storage)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(key, pt) != 1 {
		return errors.New("recovery key does not match submitted values")
	}

	return nil
}

func (d *autoSeal) SetRecoveryKey(ctx context.Context, storage physical.Backend, key []byte) error {
	if key == nil {
		return errors.New("recovery key to store is nil")
	}

	// Encrypt and marshal the keys
	blobInfo, err := d.Encrypt(ctx, key, nil)
	if err != nil {
		return fmt.Errorf("failed to encrypt keys for storage: %w", err)
	}

	value, err := proto.Marshal(blobInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal value for storage: %w", err)
	}

	be := &physical.Entry{
		Key:   recoveryKeyPath,
		Value: value,
	}

	if err := storage.Put(ctx, be); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	return nil
}

func (d *autoSeal) RecoveryKey(ctx context.Context, storage physical.Backend) ([]byte, error) {
	return d.getRecoveryKeyInternal(ctx, storage)
}

func (d *autoSeal) getRecoveryKeyInternal(ctx context.Context, storage physical.Backend) ([]byte, error) {
	pe, err := storage.Get(ctx, recoveryKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery key: %w", err)
	}
	if pe == nil {
		return nil, errors.New("no recovery key found")
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return nil, fmt.Errorf("failed to proto decode stored keys: %w", err)
	}

	pt, err := d.Decrypt(ctx, blobInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted stored keys: %w", err)
	}

	return pt, nil
}

func (d *autoSeal) upgradeRecoveryKey(ctx context.Context, storage physical.Backend) error {
	pe, err := storage.Get(ctx, recoveryKeyPath)
	if err != nil {
		return fmt.Errorf("failed to fetch recovery key: %w", err)
	}
	if pe == nil {
		return errors.New("no recovery key found")
	}

	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(pe.Value, blobInfo); err != nil {
		return fmt.Errorf("failed to proto decode recovery key: %w", err)
	}

	keyId, err := d.Access.KeyId(ctx)
	if err != nil {
		return err
	}

	if blobInfo.KeyInfo != nil && blobInfo.KeyInfo.KeyId != keyId {
		pt, err := d.Decrypt(ctx, blobInfo, nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt encrypted recovery key: %w", err)
		}
		if err := d.SetRecoveryKey(ctx, storage, pt); err != nil {
			return fmt.Errorf("failed to save upgraded recovery key: %w", err)
		}
	}
	return nil
}

// StartHealthCheck starts a goroutine that tests the health of the auto-unseal backend once every 10 minutes.
// If unhealthy, logs a warning on the condition and begins testing every one minute until healthy again.
func (d *autoSeal) StartHealthCheck(core *Core) {
	d.StopHealthCheck()
	d.hcLock.Lock()
	defer d.hcLock.Unlock()

	healthCheck := time.NewTicker(sealHealthTestIntervalNominal)
	d.healthCheckStop = make(chan struct{})
	healthCheckStop := d.healthCheckStop
	ctx := core.activeContext

	go func() {
		lastTestOk := true
		lastSeenOk := time.Now()

		fail := func(msg string, args ...interface{}) {
			core.logger.Warn(msg, args...)
			if lastTestOk {
				healthCheck.Reset(sealHealthTestIntervalUnhealthy)
			}
			lastTestOk = false
			core.MetricSink().SetGauge(autoSealUnavailableDuration, float32(time.Since(lastSeenOk).Milliseconds()))
		}
		for {
			select {
			case <-healthCheckStop:
				if healthCheck != nil {
					healthCheck.Stop()
				}
				healthCheckStop = nil
				return
			case t := <-healthCheck.C:
				func() {
					ctx, cancel := context.WithTimeout(ctx, sealHealthTestTimeout)
					defer cancel()

					testVal := fmt.Sprintf("Heartbeat %d", mathrand.Intn(1000))
					ciphertext, err := d.Access.Encrypt(ctx, []byte(testVal), nil)

					if err != nil {
						fail("failed to encrypt seal health test value, seal backend may be unreachable", "error", err)
					} else {
						func() {
							ctx, cancel := context.WithTimeout(ctx, sealHealthTestTimeout)
							defer cancel()
							plaintext, err := d.Access.Decrypt(ctx, ciphertext, nil)
							if err != nil {
								fail("failed to decrypt seal health test value, seal backend may be unreachable", "error", err)
							}
							if !bytes.Equal([]byte(testVal), plaintext) {
								fail("seal health test value failed to decrypt to expected value")
							} else {
								core.logger.Debug("seal health test passed")
								if !lastTestOk {
									core.logger.Info("seal backend is now healthy again", "downtime", t.Sub(lastSeenOk).String())
									healthCheck.Reset(sealHealthTestIntervalNominal)
								}
								lastTestOk = true
								lastSeenOk = t
								core.MetricSink().SetGauge(autoSealUnavailableDuration, 0)
							}
						}()
					}
				}()
			}
		}
	}()
}

func (d *autoSeal) StopHealthCheck() {
	d.hcLock.Lock()
	defer d.hcLock.Unlock()
	if d.healthCheckStop != nil {
		close(d.healthCheckStop)
		d.healthCheckStop = nil
	}
}
