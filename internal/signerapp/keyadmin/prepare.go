// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/witness"
)

// PreparedGeneration describes the account a generation request would create.
// It has no address: that depends on a spending key that does not exist yet.
type PreparedGeneration struct {
	KeyType string
	// BaseKeyType is the signature base the spending key uses, when the key
	// type composes over one: the plain hosts are their own base, and a
	// composed template names one. Empty for any other key type.
	BaseKeyType string
	Parameters  map[string]string
	// Fingerprint is the provenance the account would record.
	Fingerprint string
	// ReviewFingerprint is what the operator approves here and generation checks.
	ReviewFingerprint string
	// BoundaryDigest is set only for general-provider accounts.
	BoundaryDigest string
	// Bounded is the bounded contract, or nil for any other key type.
	Bounded       *boundedmeta.Metadata
	CosignerKeyID string
	// Warnings are the provider's notes for the reviewer. They refuse nothing.
	Warnings []string
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
	if err := checkGenerationAllowed(activeKeyPaths, creation.keyType); err != nil {
		return nil, err
	}
	if err := s.checkGenerationRequirements(creation); err != nil {
		return nil, err
	}

	prepared := &PreparedGeneration{KeyType: creation.keyType, Parameters: creation.params, Warnings: slices.Clone(creation.warnings)}
	if provider := lsigprovider.Get(creation.keyType); provider != nil {
		if err := provider.ValidateCreationParams(creation.params); err != nil {
			return nil, &Error{Kind: ErrorInvalidInput, Message: err.Error()}
		}
		if based, ok := provider.(interface{ BaseKeyType() string }); ok {
			prepared.BaseKeyType = based.BaseKeyType()
		}
	}
	if creation.instance != nil {
		prepared.Fingerprint = creation.instance.Fingerprint
		prepared.ReviewFingerprint = creation.instance.ReviewFingerprint
		prepared.BoundaryDigest = creation.instance.BoundaryDigest
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
	if p.Bounded == nil || p.Bounded.Cosigner == nil {
		return nil
	}
	component := p.Bounded.Cosigner.ComponentKeyType
	value := p.Parameters[boundedmeta.CosignerPublicKeyParameter]
	if value == "" {
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
