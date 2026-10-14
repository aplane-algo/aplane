// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/storepaths"
	hybridsignerreg "github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerreg"
)

// generator creates WOTS hybrid rotating accounts. It takes the same single
// network parameter as the rotating hybrid's generator.
type generator struct{}

func (generator) RoutingFamily() string { return rotatingkey.RotatingWotsHybridFamily }

func (generator) GenerateRandom(_ context.Context, paths storepaths.Paths, kr *crypto.Keyring, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	if keyType != rotatingkey.RotatingWotsHybridV1 {
		return nil, fmt.Errorf("unsupported rotating key type %q", keyType)
	}
	genesisHash, err := hybridsignerreg.GenesisHashParameter(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", keygen.ErrInvalidParams, err)
	}
	words, seed, err := rotatinghybrid.NewMnemonic()
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	payload, address, err := NewKeyPayload(&seed, genesisHash)
	if err != nil {
		return nil, err
	}
	defer payload.ZeroSecrets()
	saved, err := keys.SavePayload(paths, payload, kr)
	if err != nil {
		return nil, err
	}
	return &keygen.GenerationResult{
		Address:  address,
		KeyType:  keyType,
		Mnemonic: strings.Join(words, " "),
		KeyFiles: saved,
	}, nil
}

func (generator) GenerateFromSeed(context.Context, storepaths.Paths, []byte, *crypto.Keyring, string, map[string]string) (*keygen.GenerationResult, error) {
	return nil, fmt.Errorf("rotating accounts cannot be generated from a raw seed")
}

func (generator) GenerateFromMnemonic(context.Context, storepaths.Paths, string, *crypto.Keyring, string, map[string]string) (*keygen.GenerationResult, error) {
	return nil, fmt.Errorf("rotating accounts cannot yet be generated from a mnemonic")
}
