// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyeditor owns policy editor storage backends. The initial backend
// is intentionally offline-only: it edits a local signer store while holding the
// same cooperative lock used by apstore.
package policyeditor

import (
	"context"
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/noderole"
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

// OfflineStore edits one local policy document directly in a signer data
// directory.
type OfflineStore struct {
	DataDir            string
	IdentityID         string
	Target             Target
	Passphrase         []byte
	PassphraseProvider PassphraseProvider
	Now                func() time.Time

	// Config overrides the runtime signer config used for validation. When nil,
	// the config is loaded from DataDir.
	Config *serverconfig.ServerConfig
}

// Load verifies the selected policy document integrity sidecar, parses the
// document, and validates the stored content against signer runtime defaults.
func (s OfflineStore) Load(ctx context.Context) (*policy.StoredConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.validateOptions(); err != nil {
		return nil, err
	}
	kr, clear, err := s.unlock(ctx)
	if err != nil {
		return nil, err
	}
	defer clear()

	stored, err := s.loadVerifiedWithKeyring(kr)
	if err != nil {
		return nil, fmt.Errorf("failed to load verified %s: %w", s.target().StatusNoun(), err)
	}
	if err := s.Validate(ctx, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

// Validate compiles a stored policy using the same runtime defaults as
// apsigner. It does not read or write policy files.
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
	switch s.target() {
	case TargetSentry:
		if _, err := policyruntime.ApplySentryStoredConfig(s.DataDir, &serverCfg, stored); err != nil {
			return fmt.Errorf("invalid sentry policy: %w", err)
		}
	default:
		if _, err := policyruntime.ApplyStoredConfig(s.DataDir, &serverCfg, stored); err != nil {
			return fmt.Errorf("invalid policy: %w", err)
		}
	}
	return nil
}

// Save verifies the current on-disk policy document first, validates the
// requested replacement, then writes the selected document plus a fresh
// integrity sidecar.
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

	kr, clear, err := s.unlock(ctx)
	if err != nil {
		return err
	}
	defer clear()

	if _, err := s.loadVerifiedWithKeyring(kr); err != nil {
		return fmt.Errorf("refusing to overwrite unverified %s: %w", s.target().StatusNoun(), err)
	}
	serverCfg, err := s.serverConfig()
	if err != nil {
		return err
	}
	switch s.target() {
	case TargetSentry:
		if _, err := policyruntime.SaveStoredSentryConfigWithKeyring(
			s.DataDir,
			s.identityID(),
			&serverCfg,
			stored,
			kr,
			s.now(),
		); err != nil {
			return err
		}
	default:
		if _, err := policyruntime.SaveStoredConfigWithKeyring(
			s.DataDir,
			s.identityID(),
			&serverCfg,
			stored,
			kr,
			s.now(),
		); err != nil {
			return err
		}
	}
	if _, err := s.loadVerifiedWithKeyring(kr); err != nil {
		return fmt.Errorf("saved %s failed verification: %w", s.target().StatusNoun(), err)
	}
	return nil
}

// SaveYAML verifies the current on-disk policy document first, parses and
// validates the requested replacement, then writes the exact YAML bytes plus a
// fresh sidecar.
func (s OfflineStore) SaveYAML(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.validateOptions(); err != nil {
		return err
	}
	stored, err := s.target().Parse(data)
	if err != nil {
		return fmt.Errorf("failed to parse %s: %w", s.target().DocumentName(), err)
	}
	guard, err := storelock.AcquireExclusive(s.DataDir)
	if err != nil {
		return fmt.Errorf("failed to acquire offline store lock: %w (stop apsigner and other store-mutating tools before editing policy offline)", err)
	}
	defer func() { _ = guard.Close() }()

	kr, clear, err := s.unlock(ctx)
	if err != nil {
		return err
	}
	defer clear()

	if _, err := s.loadVerifiedWithKeyring(kr); err != nil {
		return fmt.Errorf("refusing to overwrite unverified %s: %w", s.target().StatusNoun(), err)
	}
	if err := s.Validate(ctx, stored); err != nil {
		return err
	}
	if err := s.saveBytesWithKeyring(data, kr); err != nil {
		return err
	}
	if _, err := s.loadVerifiedWithKeyring(kr); err != nil {
		return fmt.Errorf("saved %s failed verification: %w", s.target().StatusNoun(), err)
	}
	return nil
}

// SaveSentryYAML verifies the current on-disk sentry policy first,
// parses and validates the requested replacement, then writes the exact YAML
// bytes to policy.yaml plus a fresh sidecar.
func (s OfflineStore) SaveSentryYAML(ctx context.Context, data []byte) error {
	s.Target = TargetSentry
	return s.SaveYAML(ctx, data)
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
	if target := s.target(); target != TargetAuto {
		nodeDoc, _, err := noderole.Load(storepaths.NewPaths(s.DataDir))
		if err != nil {
			return fmt.Errorf("failed to load node role: %w", err)
		}
		roleTarget, err := TargetForNodeRole(nodeDoc.Role)
		if err != nil {
			return err
		}
		if target != roleTarget {
			return fmt.Errorf("policy target %q is not allowed on %s nodes", target, nodeDoc.Role)
		}
	}
	return nil
}

func (s OfflineStore) identityID() string {
	if s.IdentityID != "" {
		return s.IdentityID
	}
	return DefaultIdentityID
}

func (s OfflineStore) target() Target {
	if s.Target != "" && s.Target != TargetAuto {
		return s.Target
	}
	if s.DataDir != "" {
		if target, err := ResolveTarget(s.DataDir, TargetAuto); err == nil {
			return target
		}
	}
	return TargetSigner
}

func (s OfflineStore) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s OfflineStore) serverConfig() (serverconfig.ServerConfig, error) {
	if s.Config != nil {
		return s.Config.Clone(), nil
	}
	if s.DataDir == "" {
		return serverconfig.ServerConfig{}, nil
	}
	cfg, err := serverconfig.LoadServerConfig(s.DataDir)
	if err != nil {
		return serverconfig.ServerConfig{}, fmt.Errorf("failed to load signer config: %w", err)
	}
	return cfg, nil
}

func (s OfflineStore) unlock(ctx context.Context) (*apcrypto.Keyring, func(), error) {
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
	kr, err := apcrypto.OpenKeyringStore(metadataDir, passphrase)
	clearPassphrase()
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to unlock keystore: %w", err)
	}
	return kr, func() { kr.Zero() }, nil
}

func (s OfflineStore) loadVerifiedWithKeyring(kr *apcrypto.Keyring) (*policy.StoredConfig, error) {
	switch s.target() {
	case TargetSentry:
		return policy.LoadVerifiedSentryConfigWithKeyring(s.DataDir, s.identityID(), kr)
	default:
		return policy.LoadVerifiedStoredConfigWithKeyring(s.DataDir, s.identityID(), kr)
	}
}

func (s OfflineStore) saveBytesWithKeyring(data []byte, kr *apcrypto.Keyring) error {
	switch s.target() {
	case TargetSentry:
		return policy.SaveSentryBytesWithKeyring(s.DataDir, s.identityID(), data, kr, s.now())
	default:
		return policy.SavePolicyBytesWithKeyring(s.DataDir, s.identityID(), data, kr, s.now())
	}
}
