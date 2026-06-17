// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keys

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

type AddressDeriver struct {
	keyType string
}

func NewAddressDeriver(keyType string) *AddressDeriver {
	return &AddressDeriver{keyType: keyType}
}

func (d *AddressDeriver) DeriveAddress(publicKeyHex string, params map[string]string) (string, error) {
	dsa := logicsigdsa.Get(d.keyType)
	if dsa == nil {
		return "", fmt.Errorf("unsupported key type: %s", d.keyType)
	}

	pubBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	_, address, err := dsa.DeriveLsig(context.Background(), pubBytes, params)
	if err != nil {
		return "", fmt.Errorf("failed to derive LogicSig: %w", err)
	}
	return address, nil
}
