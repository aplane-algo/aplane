// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SaveKeyFile saves a KeyPair to disk with master key encryption.
func SaveKeyFile(paths storepaths.Paths, keyPair *KeyPair, identityID, address string, masterKey []byte) (*ImportKeyResult, error) {
	if len(masterKey) == 0 {
		return nil, fmt.Errorf("master key is required to save key file")
	}
	if keyPair.FormatVersion == 0 {
		keyPair.FormatVersion = CurrentKeyFormatVersion
	}
	if keyPair.CreatedAt == "" {
		keyPair.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}

	keyJSON, err := json.MarshalIndent(keyPair, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	defer crypto.ZeroBytes(keyJSON)

	privFile := paths.KeyFilePath(identityID, address)
	dataToWrite, err := crypto.EncryptWithMasterKey(keyJSON, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	if err := fsutil.MkdirAll(paths.KeysDir(identityID)); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %w", err)
	}

	if err := fsutil.WriteFile(privFile, dataToWrite); err != nil {
		return nil, fmt.Errorf("failed to write key file: %w", err)
	}
	if err := writeComponentPublicMetadataIfNeeded(paths, identityID, address, keyPair); err != nil {
		return nil, err
	}

	return &ImportKeyResult{
		Address:     address,
		PrivateFile: privFile,
		LsigFile:    "",
		PublicFile:  "",
	}, nil
}
