// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const genesisHashSize = 32

const (
	NetworkMainnet = "mainnet"
	NetworkTestnet = "testnet"
	NetworkBetanet = "betanet"

	AlgorandMainnetGenesisHash = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
	AlgorandTestnetGenesisHash = "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="
	AlgorandBetanetGenesisHash = "mFgazF+2uRS1tMiL9dsj01hJGySEmPN28B/TjjvpVW0="
)

var reservedNetworkIDs = map[string]struct{}{
	NetworkMainnet: {},
	NetworkTestnet: {},
	NetworkBetanet: {},
}

var builtinGenesisHashNetworks = map[string]string{
	AlgorandMainnetGenesisHash: NetworkMainnet,
	AlgorandTestnetGenesisHash: NetworkTestnet,
	AlgorandBetanetGenesisHash: NetworkBetanet,
}

// IsReservedNetworkID reports whether id is a built-in Algorand network token.
func IsReservedNetworkID(id string) bool {
	_, ok := reservedNetworkIDs[id]
	return ok
}

// BuiltinGenesisHashNetworks returns the built-in genesis-hash-to-network map.
func BuiltinGenesisHashNetworks() map[string]string {
	return cloneStringMap(builtinGenesisHashNetworks)
}

// CanonicalGenesisHash normalizes a base64 or hex-encoded 32-byte genesis hash
// to base64.
func CanonicalGenesisHash(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("genesis hash is required")
	}

	var base64LengthErr error
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		if len(decoded) != genesisHashSize {
			base64LengthErr = fmt.Errorf("genesis hash must decode to %d bytes, got %d", genesisHashSize, len(decoded))
		} else {
			return base64.StdEncoding.EncodeToString(decoded), nil
		}
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		if base64LengthErr != nil {
			return "", base64LengthErr
		}
		return "", fmt.Errorf("genesis hash must be base64 or hex")
	}
	if len(decoded) != genesisHashSize {
		return "", fmt.Errorf("genesis hash must decode to %d bytes, got %d", genesisHashSize, len(decoded))
	}
	return base64.StdEncoding.EncodeToString(decoded), nil
}

// GenesisHashNetworkResolver resolves transaction genesis hashes to network
// context tokens.
type GenesisHashNetworkResolver struct {
	hashToNetwork map[string]string
}

// NewGenesisHashNetworkResolver merges built-in Algorand genesis hash mappings
// with custom mappings from config.
func NewGenesisHashNetworkResolver(custom map[string]string) (GenesisHashNetworkResolver, error) {
	merged := BuiltinGenesisHashNetworks()
	tokenToHash := make(map[string]string, len(merged))
	for hash, token := range merged {
		tokenToHash[token] = hash
	}

	for rawHash, rawToken := range custom {
		hash, err := CanonicalGenesisHash(rawHash)
		if err != nil {
			return GenesisHashNetworkResolver{}, fmt.Errorf("invalid genesis hash mapping key %q: %w", rawHash, err)
		}
		if err := ValidateNetworkID(rawToken); err != nil {
			return GenesisHashNetworkResolver{}, fmt.Errorf("invalid genesis hash mapping value for %q: %w", rawHash, err)
		}
		if IsReservedNetworkID(rawToken) {
			return GenesisHashNetworkResolver{}, fmt.Errorf("custom genesis hash mappings cannot use reserved network %q", rawToken)
		}
		if builtinToken, ok := builtinGenesisHashNetworks[hash]; ok {
			return GenesisHashNetworkResolver{}, fmt.Errorf("custom genesis hash mappings cannot remap built-in %s genesis hash to %q", builtinToken, rawToken)
		}
		if existingToken, ok := merged[hash]; ok && existingToken != rawToken {
			return GenesisHashNetworkResolver{}, fmt.Errorf("genesis hash %q maps to both %q and %q", rawHash, existingToken, rawToken)
		}
		if existingHash, ok := tokenToHash[rawToken]; ok && existingHash != hash {
			return GenesisHashNetworkResolver{}, fmt.Errorf("network %q maps to multiple genesis hashes", rawToken)
		}
		merged[hash] = rawToken
		tokenToHash[rawToken] = hash
	}

	return GenesisHashNetworkResolver{hashToNetwork: merged}, nil
}

// DefaultGenesisHashNetworkResolver returns a resolver with only built-in
// Algorand genesis hash mappings.
func DefaultGenesisHashNetworkResolver() GenesisHashNetworkResolver {
	resolver, _ := NewGenesisHashNetworkResolver(nil)
	return resolver
}

// Map returns a copy of the resolver mapping.
func (r GenesisHashNetworkResolver) Map() map[string]string {
	return cloneStringMap(r.hashToNetwork)
}

// NetworkForGenesisHashBytes resolves a raw 32-byte genesis hash to a network token.
func (r GenesisHashNetworkResolver) NetworkForGenesisHashBytes(hash []byte) (string, bool) {
	if len(hash) != genesisHashSize {
		return "", false
	}
	if r.hashToNetwork == nil {
		r = DefaultGenesisHashNetworkResolver()
	}
	token, ok := r.hashToNetwork[base64.StdEncoding.EncodeToString(hash)]
	return token, ok
}

func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
