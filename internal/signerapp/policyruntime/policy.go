// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyruntime

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"time"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/asametadata"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// DefaultConfig returns the signer-runtime default policy with process
// genesis-hash mappings and local ASA amount formatting installed.
func DefaultConfig(dataDir string, serverCfg *serverconfig.ServerConfig) (*policy.Config, error) {
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
func ApplyStoredConfig(dataDir string, serverCfg *serverconfig.ServerConfig, stored *policy.StoredConfig) (*policy.Config, error) {
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

// ApplySentryStoredConfig resolves a stored sentry policy overlay into
// an effective sentry component policy using the runtime defaults for this
// process.
func ApplySentryStoredConfig(dataDir string, serverCfg *serverconfig.ServerConfig, stored *policy.StoredConfig) (*policy.Config, error) {
	defaultPolicy, err := DefaultConfig(dataDir, serverCfg)
	if err != nil {
		return nil, err
	}
	effectivePolicy, err := stored.ApplySentry(defaultPolicy)
	if err != nil {
		return nil, err
	}
	return effectivePolicy, nil
}

// LoadVerified loads policy.yaml only after verifying its integrity sidecar
// with the identity keyring, then applies runtime defaults.
func LoadVerified(dataDir string, serverCfg *serverconfig.ServerConfig, kr *crypto.Keyring) (*policy.Config, error) {
	_, effective, err := LoadVerifiedWithStored(dataDir, serverCfg, kr)
	return effective, err
}

// LoadVerifiedWithStored loads policy.yaml only after verifying its integrity
// sidecar with the identity keyring, then returns both the stored policy
// snapshot and the applied runtime policy.
func LoadVerifiedWithStored(dataDir string, serverCfg *serverconfig.ServerConfig, kr *crypto.Keyring) (*policy.StoredConfig, *policy.Config, error) {
	stored, err := policy.LoadVerifiedStoredConfigWithKeyring(dataDir, kr)
	if err != nil {
		return nil, nil, err
	}
	effective, err := ApplyStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, nil, err
	}
	return stored, effective, nil
}

// LoadVerifiedWithStoredActive loads and applies a signer policy from one
// already-resolved generation.
func LoadVerifiedWithStoredActive(dataDir string, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, kr *crypto.Keyring) (*policy.StoredConfig, *policy.Config, error) {
	stored, err := policy.LoadVerifiedStoredConfigActive(active, kr)
	if err != nil {
		return nil, nil, err
	}
	effective, err := ApplyStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, nil, err
	}
	return stored, effective, nil
}

// LoadVerifiedSentryWithStored loads policy.yaml for a sentry node only
// after verifying its integrity sidecar with the identity keyring, then
// returns both the stored policy snapshot and the applied runtime sentry
// policy.
func LoadVerifiedSentryWithStored(dataDir string, serverCfg *serverconfig.ServerConfig, kr *crypto.Keyring) (*policy.StoredConfig, *policy.Config, error) {
	stored, err := policy.LoadVerifiedSentryConfigWithKeyring(dataDir, kr)
	if err != nil {
		return nil, nil, err
	}
	effective, err := ApplySentryStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, nil, err
	}
	return stored, effective, nil
}

// LoadVerifiedSentryWithStoredActive loads and applies a sentry policy from
// one already-resolved generation.
func LoadVerifiedSentryWithStoredActive(dataDir string, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, kr *crypto.Keyring) (*policy.StoredConfig, *policy.Config, error) {
	stored, err := policy.LoadVerifiedSentryConfigActive(active, kr)
	if err != nil {
		return nil, nil, err
	}
	effective, err := ApplySentryStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, nil, err
	}
	return stored, effective, nil
}

// LoadVerifiedForNodeRoleWithStored loads and applies the active policy domain
// for role. Single-mode nodes store the selected role policy in policy.yaml;
// role decides which schema and runtime defaults are used.
func LoadVerifiedForNodeRoleWithStored(role noderole.Role, dataDir string, serverCfg *serverconfig.ServerConfig, kr *crypto.Keyring) (*policy.StoredConfig, *policy.Config, error) {
	if role == "" {
		role = noderole.DefaultRole()
	}
	switch role {
	case noderole.RoleSentry:
		return LoadVerifiedSentryWithStored(dataDir, serverCfg, kr)
	case noderole.RoleSigner:
		return LoadVerifiedWithStored(dataDir, serverCfg, kr)
	default:
		return nil, nil, fmt.Errorf("unsupported node role %q", role)
	}
}

// LoadVerifiedForNodeRoleWithStoredActive loads the role-selected policy from
// one already-resolved generation.
func LoadVerifiedForNodeRoleWithStoredActive(role noderole.Role, dataDir string, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, kr *crypto.Keyring) (*policy.StoredConfig, *policy.Config, error) {
	if role == "" {
		role = noderole.DefaultRole()
	}
	switch role {
	case noderole.RoleSentry:
		return LoadVerifiedSentryWithStoredActive(dataDir, serverCfg, active, kr)
	case noderole.RoleSigner:
		return LoadVerifiedWithStoredActive(dataDir, serverCfg, active, kr)
	default:
		return nil, nil, fmt.Errorf("unsupported node role %q", role)
	}
}

// SaveStoredConfigWithKeyring writes policy.yaml plus policy.yaml.hmac and
// returns the effective runtime policy for the stored content.
func SaveStoredConfigWithKeyring(dataDir string, serverCfg *serverconfig.ServerConfig, stored *policy.StoredConfig, kr *crypto.Keyring, signedAt time.Time) (*policy.Config, error) {
	effective, err := ApplyStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, err
	}
	if err := policy.SaveStoredConfigWithKeyring(dataDir, stored, kr, signedAt); err != nil {
		return nil, fmt.Errorf("failed to save policy.yaml: %w", err)
	}
	return effective, nil
}

// SaveStoredConfigActiveWithKeyring validates and writes a signer policy into
// one already-resolved generation.
func SaveStoredConfigActiveWithKeyring(dataDir string, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, stored *policy.StoredConfig, kr *crypto.Keyring, signedAt time.Time) (*policy.Config, error) {
	effective, err := ApplyStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, err
	}
	if err := policy.SaveStoredConfigActiveWithKeyring(active, stored, kr, signedAt); err != nil {
		return nil, fmt.Errorf("failed to save policy.yaml: %w", err)
	}
	return effective, nil
}

// SaveStoredSentryConfigWithKeyring writes policy.yaml plus
// policy.yaml.hmac and returns the effective runtime sentry policy for the
// stored content.
func SaveStoredSentryConfigWithKeyring(dataDir string, serverCfg *serverconfig.ServerConfig, stored *policy.StoredConfig, kr *crypto.Keyring, signedAt time.Time) (*policy.Config, error) {
	effective, err := ApplySentryStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, err
	}
	if err := policy.SaveStoredSentryConfigWithKeyring(dataDir, stored, kr, signedAt); err != nil {
		return nil, fmt.Errorf("failed to save policy.yaml: %w", err)
	}
	return effective, nil
}

// SaveStoredSentryConfigActiveWithKeyring validates and writes a sentry policy
// into one already-resolved generation.
func SaveStoredSentryConfigActiveWithKeyring(dataDir string, serverCfg *serverconfig.ServerConfig, active storepaths.ActivePaths, stored *policy.StoredConfig, kr *crypto.Keyring, signedAt time.Time) (*policy.Config, error) {
	effective, err := ApplySentryStoredConfig(dataDir, serverCfg, stored)
	if err != nil {
		return nil, err
	}
	if err := policy.SaveStoredSentryConfigActiveWithKeyring(active, stored, kr, signedAt); err != nil {
		return nil, fmt.Errorf("failed to save policy.yaml: %w", err)
	}
	return effective, nil
}
