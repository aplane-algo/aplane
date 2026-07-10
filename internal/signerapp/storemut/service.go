// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package storemut centralizes signer-owned persistent mutations that should
// execute behind a single authoritative writer in apsigner.
package storemut

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// TokenUpdater is implemented by components that must observe token rotation.
type TokenUpdater interface {
	UpdateToken(token string)
}

// Service performs signer-owned persistent mutations.
type Service struct {
	identityID      string
	keyPaths        storepaths.Paths
	httpTokenUpdate TokenUpdater
	sshTokenUpdate  TokenUpdater
}

// New creates a new signer mutation service for an identity.
func New(identityID string, keyPaths storepaths.Paths, httpTokenUpdate, sshTokenUpdate TokenUpdater) *Service {
	return &Service{
		identityID:      identityID,
		keyPaths:        keyPaths,
		httpTokenUpdate: httpTokenUpdate,
		sshTokenUpdate:  sshTokenUpdate,
	}
}

// RevokeToken rotates the signer API token on disk and updates in-process users.
func (s *Service) RevokeToken() (string, error) {
	newToken, err := tokenfile.GenerateToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate new token: %w", err)
	}

	tokenPath := tokenfile.GetAPlaneTokenPathForRoot(s.keyPaths.Root(), s.identityID)
	if err := fsutil.MkdirAll(filepath.Dir(tokenPath)); err != nil {
		return "", fmt.Errorf("failed to create token directory: %w", err)
	}
	if err := tokenfile.WriteToken(tokenPath, newToken); err != nil {
		return "", fmt.Errorf("failed to write new token: %w", err)
	}

	if s.httpTokenUpdate != nil {
		s.httpTokenUpdate.UpdateToken(newToken)
	}
	if s.sshTokenUpdate != nil {
		s.sshTokenUpdate.UpdateToken(newToken)
	}

	return tokenPath, nil
}

// DeleteKey moves a key file out of the active key set into the identity archive.
func (s *Service) DeleteKey(address, keyFile string) (*keymgmt.DeleteResult, error) {
	return keymgmt.DeleteKey(address, keyFile, s.keyPaths.DeletedKeysDir(s.identityID))
}

// GenerateKeyWithActivatedContext creates and persists a key type using the
// identity-scoped activated compiled key type set.
func (s *Service) GenerateKeyWithActivatedContext(ctx context.Context, keyType string, masterKey []byte, params map[string]string, activated []string) (*keymgmt.GenerateResult, error) {
	return keymgmt.GenerateKeyWithActivatedContext(ctx, s.keyPaths, s.identityID, keyType, masterKey, params, activated)
}

// ImportKeyFromMnemonicWithActivated imports and persists a standard key using
// the identity-scoped activated compiled key type set.
func (s *Service) ImportKeyFromMnemonicWithActivated(keyType, mnemonic string, masterKey []byte, params map[string]string, activated []string) (*keymgmt.ImportResult, error) {
	return s.ImportKeyFromMnemonicWithActivatedContext(context.Background(), keyType, mnemonic, masterKey, params, activated)
}

// ImportKeyFromMnemonicWithActivatedContext imports and persists a standard key
// using the identity-scoped activated compiled key type set.
func (s *Service) ImportKeyFromMnemonicWithActivatedContext(ctx context.Context, keyType, mnemonic string, masterKey []byte, params map[string]string, activated []string) (*keymgmt.ImportResult, error) {
	return keymgmt.ImportKeyWithActivatedContext(ctx, s.keyPaths, s.identityID, keyType, mnemonic, masterKey, params, activated)
}

// SaveGenericLSig persists a generated generic LogicSig key file.
func (s *Service) SaveGenericLSig(keyType string, parameters map[string]string, bytecode []byte, saltCounter byte, tealSource string, signingArgs []keys.StoredSigningArg, masterKey []byte) error {
	payload := keys.NewGenericLSigPayload(
		keyType,
		parameters,
		bytecode,
		saltCounter,
		tealSource,
		signingArgs,
		keys.TemplateFingerprintForKeyType(keyType),
	)
	_, err := keys.SavePayload(s.keyPaths, s.identityID, payload, masterKey)
	return err
}

// SaveServerSetting persists a single signer-owned config setting.
func (s *Service) SaveServerSetting(dataDir, key string, value interface{}) error {
	return serverconfig.SaveSetting(dataDir, key, value)
}

// SaveIdentitySetting persists a single identity-scoped setting.
func (s *Service) SaveIdentitySetting(dataDir, key string, value interface{}) error {
	return identity.SaveStoredSetting(dataDir, s.identityID, key, value)
}
