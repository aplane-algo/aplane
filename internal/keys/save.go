// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SavePayload validates and saves a canonical payload under the selector
// derived from its authoritative key material.
func SavePayload(paths storepaths.Paths, identityID string, payload *Payload, masterKey []byte) (*ImportKeyResult, error) {
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

	dataToWrite, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}
	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	privateFile := paths.KeyFilePath(identityID, selector)
	if err := fsutil.WriteFile(privateFile, dataToWrite); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	if err := writeComponentPublicMetadataFromPayload(paths, identityID, selector, payload); err != nil {
		return nil, err
	}

	return &ImportKeyResult{
		Address:     selector,
		PrivateFile: privateFile,
	}, nil
}
