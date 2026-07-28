// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package sourcecontext defines the non-secret, advisory source-setting
// projection carried by backup archives and inactive recovered batches.
package sourcecontext

import (
	"fmt"
	"slices"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
)

const (
	// MaxGenesisHashMappings bounds advisory custom-network metadata.
	MaxGenesisHashMappings = 1024
)

// GenesisHashMapping binds one canonical custom genesis hash to its network
// context token.
type GenesisHashMapping struct {
	GenesisHash string `json:"genesis_hash"`
	Network     string `json:"network"`
}

// Projection is the validated non-secret source-setting snapshot.
type Projection struct {
	UserAutoApprove     *bool                `json:"user_auto_approve,omitempty"`
	GenesisHashMappings []GenesisHashMapping `json:"genesis_hash_mappings,omitempty"`
}

// NormalizeProjection validates role and customMappings and returns a
// canonical, independently owned projection.
func NormalizeProjection(
	role noderole.Role,
	userAutoApprove *bool,
	customMappings map[string]string,
) (Projection, error) {
	if _, err := noderole.ParseRole(string(role)); err != nil {
		return Projection{}, err
	}
	if len(customMappings) > MaxGenesisHashMappings {
		return Projection{}, fmt.Errorf(
			"source genesis-hash mappings exceed limit %d",
			MaxGenesisHashMappings,
		)
	}
	mappings := make([]GenesisHashMapping, 0, len(customMappings))
	seenHashes := make(map[string]struct{}, len(customMappings))
	seenNetworks := make(map[string]struct{}, len(customMappings))
	builtins := apconfig.BuiltinGenesisHashNetworks()
	for rawHash, network := range customMappings {
		hash, err := apconfig.CanonicalGenesisHash(rawHash)
		if err != nil {
			return Projection{}, fmt.Errorf("invalid source genesis hash %q: %w", rawHash, err)
		}
		if err := apconfig.ValidateNetworkID(network); err != nil {
			return Projection{}, fmt.Errorf("invalid source network %q: %w", network, err)
		}
		if apconfig.IsReservedNetworkID(network) {
			return Projection{}, fmt.Errorf("source custom mapping uses reserved network %q", network)
		}
		if builtinNetwork, ok := builtins[hash]; ok {
			return Projection{}, fmt.Errorf(
				"source custom mapping remaps built-in %s genesis hash",
				builtinNetwork,
			)
		}
		if _, ok := seenHashes[hash]; ok {
			return Projection{}, fmt.Errorf("duplicate canonical source genesis hash %q", hash)
		}
		if _, ok := seenNetworks[network]; ok {
			return Projection{}, fmt.Errorf("duplicate source network mapping %q", network)
		}
		seenHashes[hash] = struct{}{}
		seenNetworks[network] = struct{}{}
		mappings = append(mappings, GenesisHashMapping{
			GenesisHash: hash,
			Network:     network,
		})
	}
	slices.SortFunc(mappings, compareMappings)

	projection := Projection{
		UserAutoApprove:     cloneBool(userAutoApprove),
		GenesisHashMappings: mappings,
	}
	if err := ValidateProjection(role, projection); err != nil {
		return Projection{}, err
	}
	return projection, nil
}

// ValidateProjection validates a canonical source-setting projection.
func ValidateProjection(role noderole.Role, projection Projection) error {
	if _, err := noderole.ParseRole(string(role)); err != nil {
		return err
	}
	switch role {
	case noderole.RoleSigner:
		if projection.UserAutoApprove == nil {
			return fmt.Errorf("signer source settings require user_auto_approve")
		}
	case noderole.RoleSentry:
		if projection.UserAutoApprove != nil {
			return fmt.Errorf("sentry source settings must not carry user_auto_approve")
		}
	}
	if len(projection.GenesisHashMappings) > MaxGenesisHashMappings {
		return fmt.Errorf(
			"source genesis-hash mappings exceed limit %d",
			MaxGenesisHashMappings,
		)
	}
	builtins := apconfig.BuiltinGenesisHashNetworks()
	for i, mapping := range projection.GenesisHashMappings {
		canonical, err := apconfig.CanonicalGenesisHash(mapping.GenesisHash)
		if err != nil {
			return fmt.Errorf("invalid source genesis hash at index %d: %w", i, err)
		}
		if canonical != mapping.GenesisHash {
			return fmt.Errorf("non-canonical source genesis hash at index %d", i)
		}
		if err := apconfig.ValidateNetworkID(mapping.Network); err != nil {
			return fmt.Errorf("invalid source network at index %d: %w", i, err)
		}
		if apconfig.IsReservedNetworkID(mapping.Network) {
			return fmt.Errorf("source custom mapping uses reserved network %q", mapping.Network)
		}
		if builtinNetwork, ok := builtins[canonical]; ok {
			return fmt.Errorf(
				"source custom mapping remaps built-in %s genesis hash",
				builtinNetwork,
			)
		}
		if i > 0 {
			previous := projection.GenesisHashMappings[i-1]
			if compareMappings(previous, mapping) >= 0 {
				return fmt.Errorf("source genesis-hash mappings are not canonical and unique")
			}
			if previous.GenesisHash == mapping.GenesisHash {
				return fmt.Errorf("duplicate source genesis hash %q", mapping.GenesisHash)
			}
		}
		for j := 0; j < i; j++ {
			if projection.GenesisHashMappings[j].GenesisHash == mapping.GenesisHash {
				return fmt.Errorf("duplicate source genesis hash %q", mapping.GenesisHash)
			}
			if projection.GenesisHashMappings[j].Network == mapping.Network {
				return fmt.Errorf("duplicate source network mapping %q", mapping.Network)
			}
		}
	}
	return nil
}

// CloneProjection returns an independently owned projection.
func CloneProjection(projection Projection) Projection {
	return Projection{
		UserAutoApprove:     cloneBool(projection.UserAutoApprove),
		GenesisHashMappings: slices.Clone(projection.GenesisHashMappings),
	}
}

func compareMappings(a, b GenesisHashMapping) int {
	if a.Network < b.Network {
		return -1
	}
	if a.Network > b.Network {
		return 1
	}
	if a.GenesisHash < b.GenesisHash {
		return -1
	}
	if a.GenesisHash > b.GenesisHash {
		return 1
	}
	return 0
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}
