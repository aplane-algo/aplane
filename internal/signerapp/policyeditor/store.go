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

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Store is the persistence boundary used by the shared policy editor. Online,
// offline-rescue, and standalone-draft backends implement it without changing
// editor state or UI code.
type Store interface {
	Load(context.Context) (*policy.StoredConfig, error)
	Save(context.Context, *policy.StoredConfig) error
	Validate(context.Context, *policy.StoredConfig) error
	Persistence() Persistence
}

// PersistenceKind identifies whether an editor save publishes a managed
// production document or only replaces a standalone draft.
type PersistenceKind string

const (
	PersistenceProduction PersistenceKind = "production"
	PersistenceDraft      PersistenceKind = "draft"
)

// Persistence describes the destination and security effect of Store.Save.
// The editor uses this contract for truthful operator-facing prompts and
// status; it must not infer persistence semantics from concrete store types.
type Persistence struct {
	Kind PersistenceKind
	Path string
}

// PassphraseProvider supplies the signer store passphrase only when an
// operation needs the production keystore.
type PassphraseProvider func(context.Context) ([]byte, error)

// OfflineStore edits one local policy document directly in a signer data
// directory.
type OfflineStore struct {
	DataDir            string
	Target             Target
	Passphrase         []byte
	PassphraseProvider PassphraseProvider
	Now                func() time.Time
	mutationLock       *storelock.Guard

	// Config overrides the runtime signer config used for validation. When nil,
	// the config is loaded from DataDir.
	Config *serverconfig.ServerConfig
}

// Persistence reports that Save publishes the managed policy document and its
// integrity sidecar.
func (s *OfflineStore) Persistence() Persistence {
	return Persistence{Kind: PersistenceProduction}
}

// ResolvedPath returns the policy path selected by an authenticated fresh
// store-root read. It never derives authority from directory enumeration.
func (s OfflineStore) ResolvedPath(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	kr, clear, err := s.unlock(ctx)
	if err != nil {
		return "", err
	}
	defer clear()
	active, err := genstore.ResolveStoreRootWithKeyring(storepaths.NewPaths(s.DataDir), kr)
	if err != nil {
		return "", err
	}
	return active.PolicyPath(), nil
}

// UseExclusiveMutationLock supplies an already-held lock for Save and
// SaveYAML. The guard must cover this store's data directory. This permits a
// root rescue workflow to hold one lock across policy publication and
// ownership normalization without recursively acquiring flock.
func (s *OfflineStore) UseExclusiveMutationLock(guard *storelock.Guard) error {
	if s == nil {
		return fmt.Errorf("offline store is required")
	}
	if guard == nil || !guard.HoldsExclusiveFor(s.DataDir) {
		return fmt.Errorf("exclusive mutation lock does not cover policy data directory %s", s.DataDir)
	}
	s.mutationLock = guard
	return nil
}

// Load verifies the selected policy document integrity sidecar, parses the
// document, and validates the stored content against signer runtime defaults.
func (s OfflineStore) Load(ctx context.Context) (*policy.StoredConfig, error) {
	stored, _, err := s.LoadVerifiedYAML(ctx)
	return stored, err
}

// LoadVerifiedYAML verifies and validates the selected production policy and
// returns the exact YAML bytes covered by the verified integrity sidecar.
func (s OfflineStore) LoadVerifiedYAML(ctx context.Context) (*policy.StoredConfig, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := s.validateOptions(); err != nil {
		return nil, nil, err
	}
	kr, clear, err := s.unlock(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer clear()

	stored, data, err := s.loadVerifiedYAMLWithKeyring(kr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load verified %s: %w", s.target().StatusNoun(), err)
	}
	if err := s.Validate(ctx, stored); err != nil {
		return nil, nil, err
	}
	return stored, data, nil
}

// Validate compiles a stored policy using the same runtime defaults as
// apsigner. It does not read or write policy files.
func (s OfflineStore) Validate(ctx context.Context, stored *policy.StoredConfig) error {
	if err := ctx.Err(); err != nil {
		return err
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
	release, err := s.acquireMutationLock()
	if err != nil {
		return fmt.Errorf("failed to acquire offline store lock: %w (stop apsigner and other store-mutating tools before editing policy offline)", err)
	}
	defer release()

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
		active, err := genstore.ResolveStoreRootWithKeyring(storepaths.NewPaths(s.DataDir), kr)
		if err != nil {
			return err
		}
		if _, err := policyruntime.SaveStoredSentryConfigActiveWithKeyring(
			s.DataDir,
			&serverCfg,
			active,
			stored,
			kr,
			s.now(),
		); err != nil {
			return err
		}
	default:
		active, err := genstore.ResolveStoreRootWithKeyring(storepaths.NewPaths(s.DataDir), kr)
		if err != nil {
			return err
		}
		if _, err := policyruntime.SaveStoredConfigActiveWithKeyring(
			s.DataDir,
			&serverCfg,
			active,
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
	release, err := s.acquireMutationLock()
	if err != nil {
		return fmt.Errorf("failed to acquire offline store lock: %w (stop apsigner and other store-mutating tools before editing policy offline)", err)
	}
	defer release()

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

func (s OfflineStore) acquireMutationLock() (func(), error) {
	if s.mutationLock != nil {
		if !s.mutationLock.HoldsExclusiveFor(s.DataDir) {
			return nil, fmt.Errorf("supplied exclusive mutation lock is no longer active for %s", s.DataDir)
		}
		return func() {}, nil
	}
	guard, err := storelock.AcquireExclusive(s.DataDir)
	if err != nil {
		return nil, err
	}
	return func() { _ = guard.Close() }, nil
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

	paths := storepaths.NewPaths(s.DataDir)
	_, kr, err := genstore.OpenStoreRootSelection(paths, passphrase)
	clearPassphrase()
	if err != nil {
		return nil, func() {}, fmt.Errorf("failed to unlock keystore: %w", err)
	}
	return kr, func() { kr.Zero() }, nil
}

func (s OfflineStore) loadVerifiedWithKeyring(kr *apcrypto.Keyring) (*policy.StoredConfig, error) {
	stored, _, err := s.loadVerifiedYAMLWithKeyring(kr)
	return stored, err
}

func (s OfflineStore) loadVerifiedYAMLWithKeyring(kr *apcrypto.Keyring) (*policy.StoredConfig, []byte, error) {
	active, err := genstore.ResolveStoreRootWithKeyring(storepaths.NewPaths(s.DataDir), kr)
	if err != nil {
		return nil, nil, err
	}
	switch s.target() {
	case TargetSentry:
		return policy.LoadVerifiedSentryConfigDocumentActive(active, kr)
	default:
		return policy.LoadVerifiedStoredConfigDocumentActive(active, kr)
	}
}

func (s OfflineStore) saveBytesWithKeyring(data []byte, kr *apcrypto.Keyring) error {
	active, err := genstore.ResolveStoreRootWithKeyring(storepaths.NewPaths(s.DataDir), kr)
	if err != nil {
		return err
	}
	switch s.target() {
	case TargetSentry:
		return policy.SaveSentryBytesActiveWithKeyring(active, data, kr, s.now())
	default:
		return policy.SavePolicyBytesActiveWithKeyring(active, data, kr, s.now())
	}
}
