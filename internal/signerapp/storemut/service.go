// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package storemut centralizes signer-owned persistent mutations that should
// execute behind a single authoritative writer in apsigner.
package storemut

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

// TokenUpdater is implemented by components that must observe token rotation.
type TokenUpdater interface {
	UpdateToken(token string)
}

// Service performs signer-owned persistent mutations.
type Service struct {
	keyPaths        storepaths.Paths
	httpTokenUpdate TokenUpdater
	sshTokenUpdate  TokenUpdater
}

// New creates a new signer mutation service for the product store.
func New(keyPaths storepaths.Paths, httpTokenUpdate, sshTokenUpdate TokenUpdater) *Service {
	return &Service{
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

	tokenPath := tokenfile.GetAPlaneTokenPathForRoot(s.keyPaths.Root())
	if err := fsutil.MkdirAllPrivate(filepath.Dir(tokenPath)); err != nil {
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
	active, err := genstore.ResolveActive(s.keyPaths)
	if err != nil {
		return nil, err
	}
	return keymgmt.DeleteKeyActive(active, address, keyFile)
}

// GenerateKeyWithActivatedContext creates and persists a key type using the
// product store's activated compiled key type set.
func (s *Service) GenerateKeyWithActivatedContext(ctx context.Context, keyType string, kr *crypto.Keyring, params map[string]string, activated []string) (*keymgmt.GenerateResult, error) {
	return keymgmt.GenerateKeyWithActivatedContext(ctx, s.keyPaths, keyType, kr, params, activated)
}

// ImportKeyFromMnemonicWithActivated imports and persists a standard key using
// the product store's activated compiled key type set.
func (s *Service) ImportKeyFromMnemonicWithActivated(keyType, mnemonic string, kr *crypto.Keyring, params map[string]string, activated []string) (*keymgmt.ImportResult, error) {
	return s.ImportKeyFromMnemonicWithActivatedContext(context.Background(), keyType, mnemonic, kr, params, activated)
}

// ImportKeyFromMnemonicWithActivatedContext imports and persists a standard key
// using the product store's activated compiled key type set.
func (s *Service) ImportKeyFromMnemonicWithActivatedContext(ctx context.Context, keyType, mnemonic string, kr *crypto.Keyring, params map[string]string, activated []string) (*keymgmt.ImportResult, error) {
	return keymgmt.ImportKeyWithActivatedContext(ctx, s.keyPaths, keyType, mnemonic, kr, params, activated)
}

// SaveGenericLSig persists a generated generic LogicSig key file.
func (s *Service) SaveGenericLSig(keyType string, parameters map[string]string, bytecode []byte, saltCounter byte, compilerAutoSalted bool, tealSource string, signingArgs []keys.StoredSigningArg, opcodeProfile lsigresource.OpcodeProfile, kr *crypto.Keyring) error {
	var payload *keys.Payload
	if compilerAutoSalted {
		payload = keys.NewAutoSaltedGenericLSigPayload(
			keyType, parameters, bytecode, tealSource, signingArgs,
			keys.TemplateFingerprintForKeyType(keyType),
		)
	} else {
		payload = keys.NewGenericLSigPayload(
			keyType, parameters, bytecode, saltCounter, tealSource, signingArgs,
			keys.TemplateFingerprintForKeyType(keyType),
		)
	}
	if err := payload.SetLogicSigOpcodeProfile(opcodeProfile, false); err != nil {
		return err
	}
	_, err := keys.SavePayload(s.keyPaths, payload, kr)
	return err
}

// SaveServerSetting persists a single signer-owned config setting.
func (s *Service) SaveServerSetting(dataDir, key string, value interface{}) error {
	return serverconfig.SaveSetting(dataDir, key, value)
}

// SaveRuntimeSetting persists a single product-runtime setting.
func (s *Service) SaveRuntimeSetting(dataDir, key string, value interface{}) error {
	return productruntime.SaveStoredSetting(dataDir, key, value)
}
