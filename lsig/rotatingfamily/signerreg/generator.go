// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strings"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// generator creates accounts of one rotating key type from a fresh mnemonic
// and the single network parameter. The signer keeps no durable state for
// them; the stage address table is built in the background. Mnemonic import
// is not supported in this phase.
type generator struct {
	keyType       string
	family        string
	newKeyPayload func(*rotatinghybrid.Seed, [rotatinghybrid.GenesisHashSize]byte) (*keys.Payload, string, error)
}

func (g generator) RoutingFamily() string { return g.family }

func (g generator) GenerateRandom(_ context.Context, paths storepaths.Paths, kr *crypto.Keyring, keyType string, params map[string]string) (*keygen.GenerationResult, error) {
	if keyType != g.keyType {
		return nil, fmt.Errorf("unsupported rotating key type %q", keyType)
	}
	genesisHash, err := GenesisHashParameter(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", keygen.ErrInvalidParams, err)
	}
	words, seed, err := rotatinghybrid.NewMnemonic()
	if err != nil {
		return nil, err
	}
	defer seed.Zero()
	payload, address, err := g.newKeyPayload(&seed, genesisHash)
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

// GenesisHashParameter reads the network parameter
// (rotatingkey.RotatingNetworkParameter): a built-in network name (mainnet,
// testnet, betanet) or the network's base64 genesis hash, as LocalNet and
// other custom networks require. It accepts exactly that one parameter.
func GenesisHashParameter(params map[string]string) ([rotatinghybrid.GenesisHashSize]byte, error) {
	var genesis [rotatinghybrid.GenesisHashSize]byte
	for name := range params {
		if name != rotatingkey.RotatingNetworkParameter {
			return genesis, fmt.Errorf("unknown parameter %q", name)
		}
	}
	value := strings.TrimSpace(params[rotatingkey.RotatingNetworkParameter])
	if value == "" {
		return genesis, fmt.Errorf("%s is required: a network configured on the signer (built in: %s) or a base64 genesis hash", rotatingkey.RotatingNetworkParameter, strings.Join(builtinNetworks(), ", "))
	}
	for hash, token := range apconfig.BuiltinGenesisHashNetworks() {
		if token == value {
			value = hash
			break
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(genesis) {
		return genesis, fmt.Errorf("%s %q is not a network configured on the signer or a 32-byte base64 genesis hash", rotatingkey.RotatingNetworkParameter, params[rotatingkey.RotatingNetworkParameter])
	}
	copy(genesis[:], decoded)
	return genesis, nil
}

func builtinNetworks() []string {
	var names []string
	for _, token := range apconfig.BuiltinGenesisHashNetworks() {
		names = append(names, token)
	}
	sort.Strings(names)
	return names
}
