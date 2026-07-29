// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SavePayload validates and saves a canonical payload under the selector
// derived from its authoritative key material.
func SavePayload(paths storepaths.Paths, identityID string, payload *Payload, masterKey []byte) (*ImportKeyResult, error) {
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		return nil, err
	}
	return SavePayloadActive(active, payload, masterKey)
}

// SavePayloadActive is SavePayload against resolved active-store paths
// (generational or legacy); the caller resolved the layout once for the
// whole operation.
func SavePayloadActive(active storepaths.ActivePaths, payload *Payload, masterKey []byte) (*ImportKeyResult, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key is required to save key file")
	}
	if payload == nil {
		return nil, fmt.Errorf("key payload is required")
	}
	selector, err := payload.Selector()
	if err != nil {
		return nil, fmt.Errorf("failed to derive canonical key selector: %w", err)
	}

	keyJSON, err := MarshalPayload(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	defer crypto.ZeroBytes(keyJSON)

	ctx, err := CredentialContext(selector, payload.Category)
	if err != nil {
		return nil, err
	}
	dataToWrite, err := crypto.EncryptWithTermKey(keyJSON, masterKey, crypto.FirstTerm, ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}
	if err := fsutil.MkdirAll(active.KeysDir()); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	privateFile, err := CanonicalManagedCredentialPathActive(active, selector, payload.Category)
	if err != nil {
		return nil, fmt.Errorf("failed to derive canonical managed credential path: %w", err)
	}
	// Durable, never in-place: a credential write must survive a crash and
	// must not be able to reach an inode a sealed generation shares
	// (docs/ARCH_GENERATIONS.md §4).
	if err := fsutil.WriteFileDurable(privateFile, dataToWrite); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	if err := writeWitnessPublicMetadataFromPayload(active, selector, payload); err != nil {
		return nil, err
	}

	return &ImportKeyResult{
		Address:     selector,
		PrivateFile: privateFile,
	}, nil
}
