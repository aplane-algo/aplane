// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyruntime

import (
	"fmt"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
)

// DefaultConfig returns the signer-runtime default policy with process
// genesis-hash mappings and local ASA amount formatting installed.
func DefaultConfig(dataDir string, serverCfg *apconfig.ServerConfig) (*policy.Config, error) {
	resolver := apconfig.DefaultGenesisHashNetworkResolver()
	if serverCfg != nil {
		configured, err := apconfig.NewGenesisHashNetworkResolver(serverCfg.GenesisHashNetworks)
		if err != nil {
			return nil, err
		}
		resolver = configured
	}
	cfg := policy.DefaultConfigWithGenesisHashResolver(resolver)
	cfg.FormatASAAmount = asametadata.NewStore(dataDir).Formatter()
	return cfg, nil
}

// ApplyStoredConfig resolves a stored policy overlay into an effective signer
// policy using the runtime defaults for this process.
func ApplyStoredConfig(dataDir string, serverCfg *apconfig.ServerConfig, stored *policy.StoredConfig) (*policy.Config, error) {
	defaultPolicy, err := DefaultConfig(dataDir, serverCfg)
	if err != nil {
		return nil, err
	}
	effectivePolicy, err := stored.ApplySigning(defaultPolicy)
	if err != nil {
		return nil, err
	}
	return effectivePolicy, nil
}

// ApplyAttestationStoredConfig resolves a stored attestor policy overlay into
// an effective attestor component policy using the runtime defaults for this
// process.
func ApplyAttestationStoredConfig(dataDir string, serverCfg *apconfig.ServerConfig, stored *policy.StoredConfig) (*policy.Config, error) {
	defaultPolicy, err := DefaultConfig(dataDir, serverCfg)
	if err != nil {
		return nil, err
	}
	effectivePolicy, err := stored.ApplyAttestation(defaultPolicy)
	if err != nil {
		return nil, err
	}
	return effectivePolicy, nil
}

// LoadVerified loads policy.yaml only after verifying its integrity sidecar
// with the identity master key, then applies runtime defaults.
func LoadVerified(dataDir, identityID string, serverCfg *apconfig.ServerConfig, masterKey []byte) (*policy.Config, error) {
	_, effective, err := LoadVerifiedWithStored(dataDir, identityID, serverCfg, masterKey)
	return effective, err
}

// LoadVerifiedWithStored loads policy.yaml only after verifying its integrity
// sidecar with the identity master key, then returns both the stored policy
// snapshot and the applied runtime policy.
func LoadVerifiedWithStored(dataDir, identityID string, serverCfg *apconfig.ServerConfig, masterKey []byte) (*policy.StoredConfig, *policy.Config, error) {
	stored, err := policy.LoadVerifiedStoredConfigWithMasterKey(dataDir, identityID, masterKey)
	if err != nil {
		return nil, nil, err
	}
	effective, err := ApplyStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, nil, err
	}
	return stored, effective, nil
}

// LoadVerifiedAttestationWithStored loads policy.yaml for an attestor node only
// after verifying its integrity sidecar with the identity master key, then
// returns both the stored policy snapshot and the applied runtime attestor
// policy.
func LoadVerifiedAttestationWithStored(dataDir, identityID string, serverCfg *apconfig.ServerConfig, masterKey []byte) (*policy.StoredConfig, *policy.Config, error) {
	stored, err := policy.LoadVerifiedAttestationConfigWithMasterKey(dataDir, identityID, masterKey)
	if err != nil {
		return nil, nil, err
	}
	effective, err := ApplyAttestationStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, nil, err
	}
	return stored, effective, nil
}

// LoadVerifiedForNodeRoleWithStored loads and applies the active policy domain
// for role. Single-mode nodes store the selected role policy in policy.yaml;
// role decides which schema and runtime defaults are used.
func LoadVerifiedForNodeRoleWithStored(role noderole.Role, dataDir, identityID string, serverCfg *apconfig.ServerConfig, masterKey []byte) (*policy.StoredConfig, *policy.Config, error) {
	if role == "" {
		role = noderole.DefaultRole()
	}
	switch role {
	case noderole.RoleSentry:
		return LoadVerifiedAttestationWithStored(dataDir, identityID, serverCfg, masterKey)
	case noderole.RoleSigner:
		return LoadVerifiedWithStored(dataDir, identityID, serverCfg, masterKey)
	default:
		return nil, nil, fmt.Errorf("unsupported node role %q", role)
	}
}

// SaveStoredConfigWithMasterKey writes policy.yaml plus policy.yaml.hmac and
// returns the effective runtime policy for the stored content.
func SaveStoredConfigWithMasterKey(dataDir, identityID string, serverCfg *apconfig.ServerConfig, stored *policy.StoredConfig, masterKey []byte, signedAt time.Time) (*policy.Config, error) {
	effective, err := ApplyStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, err
	}
	if err := policy.SaveStoredConfigWithMasterKey(dataDir, identityID, stored, masterKey, signedAt); err != nil {
		return nil, fmt.Errorf("failed to save policy.yaml: %w", err)
	}
	return effective, nil
}

// SaveStoredAttestationConfigWithMasterKey writes policy.yaml plus
// policy.yaml.hmac and returns the effective runtime attestor policy for the
// stored content.
func SaveStoredAttestationConfigWithMasterKey(dataDir, identityID string, serverCfg *apconfig.ServerConfig, stored *policy.StoredConfig, masterKey []byte, signedAt time.Time) (*policy.Config, error) {
	effective, err := ApplyAttestationStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, err
	}
	if err := policy.SaveStoredAttestationConfigWithMasterKey(dataDir, identityID, stored, masterKey, signedAt); err != nil {
		return nil, fmt.Errorf("failed to save policy.yaml: %w", err)
	}
	return effective, nil
}
