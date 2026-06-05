// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyeditor owns policy editor storage backends. The initial backend
// is intentionally offline-only: it edits a local signer store while holding the
// same cooperative lock used by apstore.
package policyeditor

import (
	"context"
	"fmt"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const DefaultIdentityID = "default"

// Store is the persistence boundary used by appolicy. Future online backends
// should implement this interface without changing editor state/UI code.
type Store interface {
	Load(context.Context) (*policy.StoredConfig, error)
	Save(context.Context, *policy.StoredConfig) error
	Validate(context.Context, *policy.StoredConfig) error
}

// PassphraseProvider supplies the signer store passphrase only when an
// operation needs the production keystore.
type PassphraseProvider func(context.Context) ([]byte, error)

// OfflineStore edits policy.yaml directly in a local signer data directory.
type OfflineStore struct {
	DataDir            string
	IdentityID         string
	Passphrase         []byte
	PassphraseProvider PassphraseProvider
	Now                func() time.Time

	// Config overrides the runtime signer config used for validation. When nil,
	// the config is loaded from DataDir.
	Config *apconfig.ServerConfig
}

// Load verifies policy.yaml.hmac, parses policy.yaml, and validates the stored
// content against signer runtime defaults.
func (s OfflineStore) Load(ctx context.Context) (*policy.StoredConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.validateOptions(); err != nil {
		return nil, err
	}
	masterKey, clear, err := s.unlock(ctx)
	if err != nil {
		return nil, err
	}
	defer clear()

	stored, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.DataDir, s.identityID(), masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load verified policy: %w", err)
	}
	if err := s.Validate(ctx, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

// Validate compiles a stored policy using the same runtime defaults as
// apsigner. It does not read or write policy.yaml.
func (s OfflineStore) Validate(ctx context.Context, stored *policy.StoredConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.identityID() == "" {
		return fmt.Errorf("identity ID is required")
	}
	if stored == nil {
		stored = &policy.StoredConfig{}
	}
	serverCfg, err := s.serverConfig()
	if err != nil {
		return err
	}
	if _, err := policyruntime.ApplyStoredConfig(s.DataDir, &serverCfg, stored); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	return nil
}

// ValidateAttestation compiles a stored attestation policy using the same
// runtime defaults as apsigner. It does not read or write attestation.yaml.
func (s OfflineStore) ValidateAttestation(ctx context.Context, stored *policy.StoredConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.identityID() == "" {
		return fmt.Errorf("identity ID is required")
	}
	if stored == nil {
		stored = &policy.StoredConfig{}
	}
	serverCfg, err := s.serverConfig()
	if err != nil {
		return err
	}
	if _, err := policyruntime.ApplyAttestationStoredConfig(s.DataDir, &serverCfg, stored); err != nil {
		return fmt.Errorf("invalid attestation policy: %w", err)
	}
	return nil
}

// Save verifies the current on-disk policy first, validates the requested
// replacement, then writes policy.yaml plus a fresh integrity sidecar.
func (s OfflineStore) Save(ctx context.Context, stored *policy.StoredConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateOptions(); err != nil {
		return err
	}
	guard, err := storelock.AcquireExclusive(s.DataDir)
	if err != nil {
		return fmt.Errorf("failed to acquire offline store lock: %w (stop apsigner and other store-mutating tools before editing policy offline)", err)
	}
	defer func() { _ = guard.Close() }()

	masterKey, clear, err := s.unlock(ctx)
	if err != nil {
		return err
	}
	defer clear()

	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.DataDir, s.identityID(), masterKey); err != nil {
		return fmt.Errorf("refusing to overwrite unverified policy: %w", err)
	}
	serverCfg, err := s.serverConfig()
	if err != nil {
		return err
	}
	if _, err := policyruntime.SaveStoredConfigWithMasterKey(
		s.DataDir,
		s.identityID(),
		&serverCfg,
		stored,
		masterKey,
		s.now(),
	); err != nil {
		return err
	}
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.DataDir, s.identityID(), masterKey); err != nil {
		return fmt.Errorf("saved policy failed verification: %w", err)
	}
	return nil
}

// SaveYAML verifies the current on-disk policy first, parses and validates the
// requested replacement, then writes the exact YAML bytes plus a fresh sidecar.
func (s OfflineStore) SaveYAML(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateOptions(); err != nil {
		return err
	}
	stored, err := policy.ParseStoredConfig(data)
	if err != nil {
		return fmt.Errorf("failed to parse policy YAML: %w", err)
	}
	guard, err := storelock.AcquireExclusive(s.DataDir)
	if err != nil {
		return fmt.Errorf("failed to acquire offline store lock: %w (stop apsigner and other store-mutating tools before editing policy offline)", err)
	}
	defer func() { _ = guard.Close() }()

	masterKey, clear, err := s.unlock(ctx)
	if err != nil {
		return err
	}
	defer clear()

	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.DataDir, s.identityID(), masterKey); err != nil {
		return fmt.Errorf("refusing to overwrite unverified policy: %w", err)
	}
	if err := s.Validate(ctx, stored); err != nil {
		return err
	}
	if err := policy.SavePolicyBytesWithMasterKey(
		s.DataDir,
		s.identityID(),
		data,
		masterKey,
		s.now(),
	); err != nil {
		return err
	}
	if _, err := policy.LoadVerifiedStoredConfigWithMasterKey(s.DataDir, s.identityID(), masterKey); err != nil {
		return fmt.Errorf("saved policy failed verification: %w", err)
	}
	return nil
}

// SaveAttestationYAML verifies the current on-disk attestation policy first,
// parses and validates the requested replacement, then writes the exact YAML
// bytes plus a fresh sidecar.
func (s OfflineStore) SaveAttestationYAML(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateOptions(); err != nil {
		return err
	}
	stored, err := policy.ParseStoredAttestationConfig(data)
	if err != nil {
		return fmt.Errorf("failed to parse attestation YAML: %w", err)
	}
	guard, err := storelock.AcquireExclusive(s.DataDir)
	if err != nil {
		return fmt.Errorf("failed to acquire offline store lock: %w (stop apsigner and other store-mutating tools before editing policy offline)", err)
	}
	defer func() { _ = guard.Close() }()

	masterKey, clear, err := s.unlock(ctx)
	if err != nil {
		return err
	}
	defer clear()

	if _, err := policy.LoadVerifiedAttestationConfigWithMasterKey(s.DataDir, s.identityID(), masterKey); err != nil {
		return fmt.Errorf("refusing to overwrite unverified attestation policy: %w", err)
	}
	if err := s.ValidateAttestation(ctx, stored); err != nil {
		return err
	}
	if err := policy.SaveAttestationBytesWithMasterKey(
		s.DataDir,
		s.identityID(),
		data,
		masterKey,
		s.now(),
	); err != nil {
		return err
	}
	if _, err := policy.LoadVerifiedAttestationConfigWithMasterKey(s.DataDir, s.identityID(), masterKey); err != nil {
		return fmt.Errorf("saved attestation policy failed verification: %w", err)
	}
	return nil
}

// HasPassphrase reports whether this store already has a passphrase cached
// locally for production store operations.
func (s *OfflineStore) HasPassphrase() bool {
	return s != nil && len(s.Passphrase) > 0
}

// RequiresPassphraseForSave reports whether a production save should collect a
// passphrase before calling Save. It is used by interactive UIs so passphrase
// collection happens on-screen rather than inside a background save command.
func (s *OfflineStore) RequiresPassphraseForSave() bool {
	return s != nil && s.DataDir != "" && len(s.Passphrase) == 0 && s.PassphraseProvider == nil
}

// SetPassphrase caches a copy of passphrase for later production store
// operations and disables any deferred provider.
func (s *OfflineStore) SetPassphrase(passphrase []byte) {
	if s == nil {
		return
	}
	s.ClearPassphrase()
	s.Passphrase = append([]byte(nil), passphrase...)
	s.PassphraseProvider = nil
}

// ClearPassphrase zeros and removes any passphrase cached on this store.
func (s *OfflineStore) ClearPassphrase() {
	if s == nil {
		return
	}
	for i := range s.Passphrase {
		s.Passphrase[i] = 0
	}
	s.Passphrase = nil
}

func (s OfflineStore) validateOptions() error {
	if err := s.validateOptionsWithoutPassphrase(); err != nil {
		return err
	}
	if len(s.Passphrase) == 0 && s.PassphraseProvider == nil {
		return fmt.Errorf("passphrase is required")
	}
	return nil
}

func (s OfflineStore) validateOptionsWithoutPassphrase() error {
	if s.DataDir == "" {
		return fmt.Errorf("data directory is required")
	}
	if s.identityID() == "" {
		return fmt.Errorf("identity ID is required")
	}
	return nil
}

func (s OfflineStore) identityID() string {
	if s.IdentityID != "" {
		return s.IdentityID
	}
	return DefaultIdentityID
}

func (s OfflineStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s OfflineStore) serverConfig() (apconfig.ServerConfig, error) {
	if s.Config != nil {
		return s.Config.Clone(), nil
	}
	if s.DataDir == "" {
		return apconfig.ServerConfig{}, nil
	}
	cfg, err := apconfig.LoadServerConfig(s.DataDir)
	if err != nil {
		return apconfig.ServerConfig{}, fmt.Errorf("failed to load signer config: %w", err)
	}
	return cfg, nil
}

func (s OfflineStore) unlock(ctx context.Context) ([]byte, func(), error) {
	passphrase := s.Passphrase
	clearPassphrase := func() {}
	if len(passphrase) == 0 && s.PassphraseProvider != nil {
		p, err := s.PassphraseProvider(ctx)
		if err != nil {
			return nil, func() {}, err
		}
		passphrase = p
		clearPassphrase = func() {
			for i := range p {
				p[i] = 0
			}
		}
	}
	if len(passphrase) == 0 {
		return nil, func() {}, fmt.Errorf("passphrase is required")
	}

	metadataDir := storepaths.NewPaths(s.DataDir).KeystoreMetadataDir(s.identityID())
	meta, err := apcrypto.LoadKeystoreMetadata(metadataDir)
	if err != nil {
		clearPassphrase()
		return nil, func() {}, fmt.Errorf("failed to load keystore metadata: %w", err)
	}
	if meta == nil {
		clearPassphrase()
		return nil, func() {}, fmt.Errorf("keystore not initialized (missing .keystore file in %s) - run migration first", metadataDir)
	}

	masterKey, err := meta.VerifyAndDeriveMasterKey(passphrase)
	clearPassphrase()
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to unlock keystore: %w", err)
	}
	return masterKey, func() { apcrypto.ZeroBytes(masterKey) }, nil
}
