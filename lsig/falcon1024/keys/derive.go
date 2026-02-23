// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package falconkeys

import (
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

// DeriveFalconAddressForType derives an Algorand address using the specified key type.
// The key type should be a versioned type like "falcon1024-v1".
func DeriveFalconAddressForType(publicKeyHex string, keyType string, params map[string]string) (string, error) {
	// Look up the DSA for this key type
	dsa := logicsigdsa.Get(keyType)
	if dsa == nil {
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}

	// Decode public key
	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// Derive address using the DSA (version is implicit)
	_, address, err := dsa.DeriveLsig(pubBytes, params)
	if err != nil {
		return "", fmt.Errorf("failed to derive LogicSig: %w", err)
	}

	return address, nil
}
