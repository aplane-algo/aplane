// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SaveWitnessKey persists a generated witness keypair under its Witness Key ID
// and returns the generation result.
func SaveWitnessKey(paths storepaths.Paths, identityID, keyType string, publicKey, privateKey []byte, masterKey []byte) (*GenerationResult, error) {
	payload := keys.NewWitnessPayload(keyType, publicKey, privateKey)
	defer payload.ZeroSecrets()
	// Boundary adapter: see saveEd25519Keys.
	kr, err := crypto.KeyringFromMasterKeyForMigration(masterKey)
	if err != nil {
		return nil, err
	}
	defer kr.Zero()
	keyFiles, err := keys.SavePayload(paths, identityID, payload, kr)
	if err != nil {
		return nil, fmt.Errorf("failed to save witness key: %w", err)
	}

	return &GenerationResult{
		Address:      keyFiles.Address,
		KeyType:      keyType,
		PublicKeyHex: hex.EncodeToString(publicKey),
		KeyFiles:     keyFiles,
	}, nil
}
