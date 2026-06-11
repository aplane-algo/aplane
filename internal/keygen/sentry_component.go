// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keygen

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// SaveSentryComponentKey persists a generated sentry component keypair under
// its Sentry Key ID and returns the generation result. It is shared by the
// sentry component generators (ed25519 here, families like Falcon-1024 in
// their lsig packages).
func SaveSentryComponentKey(paths storepaths.Paths, identityID, keyType string, publicKey, privateKey []byte, masterKey []byte) (*GenerationResult, error) {
	componentKey, err := keytypes.ComponentKeySelector(keyType, publicKey)
	if err != nil {
		return nil, err
	}

	keyPair := &keys.KeyPair{
		Category:      keys.CategoryComponent,
		KeyType:       keyType,
		PublicKeyHex:  fmt.Sprintf("%x", publicKey),
		PrivateKeyHex: fmt.Sprintf("%x", privateKey),
	}
	keyFiles, err := keys.SaveKeyFile(paths, keyPair, identityID, componentKey, masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to save sentry key: %w", err)
	}

	return &GenerationResult{
		Address:      componentKey,
		KeyType:      keyType,
		PublicKeyHex: keyPair.PublicKeyHex,
		KeyFiles:     keyFiles,
	}, nil
}
