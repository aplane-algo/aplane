// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
)

// PreparedGeneration describes the account a generation request would create.
// It has no address: that depends on a spending key that does not exist yet.
type PreparedGeneration struct {
	KeyType     string
	Parameters  map[string]string
	Fingerprint string
	// Bounded is the bounded contract, or nil for any other key type.
	Bounded       *boundedmeta.Metadata
	AdminKeyID    string
	CosignerKeyID string
}

// PrepareGenerateKey runs generation's checks without generating anything, so
// an operator can review the resolved request. It creates no key, changes no
// store state, and returns nothing that can sign. Generation repeats every
// check, so this result grants nothing.
func (s Service) PrepareGenerateKey(keyType string, params map[string]string) (*PreparedGeneration, *Error) {
	creation, resolveErr := s.resolveCreation(keyType, params)
	if resolveErr != nil {
		return nil, resolveErr
	}
	unlockMutation, lockErr := s.lockUnlockedMutation()
	if lockErr != nil {
		return nil, lockErr
	}
	defer unlockMutation()
	activeKeyPaths, activeErr := s.Runtime.ActiveKeyPaths()
	if activeErr != nil {
		return nil, mapGenerateError(activeErr)
	}
	canGenerate, stateErr := keytypestate.CanGenerate(activeKeyPaths, creation.keyType)
	if stateErr != nil {
		return nil, &Error{Kind: ErrorInternal, Message: "failed to read key type state"}
	}
	if !canGenerate {
		return nil, unavailableKeyTypeError(activeKeyPaths, creation.keyType)
	}

	prepared := &PreparedGeneration{KeyType: creation.keyType, Parameters: creation.params}
	if provider := lsigprovider.Get(creation.keyType); provider != nil {
		if err := provider.ValidateCreationParams(creation.params); err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
	}
	if creation.instance != nil {
		prepared.Fingerprint = creation.instance.Fingerprint
		prepared.Bounded = boundedmeta.Clone(creation.instance.Bounded)
	}
	if err := prepared.resolveAuthorityIDs(); err != nil {
		return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
	}
	return prepared, nil
}

// resolveAuthorityIDs names the external keys the account would depend on, so a
// reviewer compares identities rather than 1,793-byte public keys.
func (p *PreparedGeneration) resolveAuthorityIDs() error {
	if value := p.Parameters[boundedmeta.AdminPublicKeyParameter]; value != "" {
		publicKey, err := boundedmeta.ParseAdminPublicKey(value)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", boundedmeta.AdminPublicKeyParameter, err)
		}
		if p.AdminKeyID, err = witness.ID(witness.Falcon1024V1, publicKey); err != nil {
			return fmt.Errorf("identify contract admin key: %w", err)
		}
	}
	component, ok := keytypes.CosignerComponentKeyTypeForGuardedAccount(p.KeyType)
	if p.Bounded != nil && p.Bounded.Cosigner != nil {
		component, ok = p.Bounded.Cosigner.ComponentKeyType, true
	}
	value := p.Parameters[boundedmeta.CosignerPublicKeyParameter]
	if !ok || value == "" {
		return nil
	}
	publicKey, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("invalid %s: %w", boundedmeta.CosignerPublicKeyParameter, err)
	}
	if p.CosignerKeyID, err = witness.ID(component, publicKey); err != nil {
		return fmt.Errorf("identify cosigner key: %w", err)
	}
	return nil
}
