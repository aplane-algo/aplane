// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

type storedConfigParser func([]byte) (*StoredConfig, error)

// LoadVerifiedStoredConfig reads policy.yaml and policy.yaml.hmac, verifies the
// sidecar against the policy bytes, then parses the stored policy.
func LoadVerifiedStoredConfig(dataRoot string, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedStoredConfigDocument(dataRoot, kr)
	return stored, err
}

// LoadVerifiedStoredConfigDocument reads, authenticates, and parses policy.yaml,
// returning the exact document bytes covered by the verified sidecar.
func LoadVerifiedStoredConfigDocument(dataRoot string, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		PolicyPath(dataRoot),
		kr,
		ParseStoredConfig,
		"policy",
		"policy config",
	)
}

// LoadVerifiedStoredConfigDocumentActive reads the signer policy from one
// already-resolved generation. The caller is responsible for resolving the
// generation once under the applicable mutation or runtime lock.
func LoadVerifiedStoredConfigDocumentActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		active.PolicyPath(),
		kr,
		ParseStoredConfig,
		"policy",
		"policy config",
	)
}

// LoadVerifiedStoredConfigActive verifies and parses the signer policy in one
// already-resolved generation.
func LoadVerifiedStoredConfigActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedStoredConfigDocumentActive(active, kr)
	return stored, err
}

// LoadVerifiedCosignerConfig reads policy.yaml for a cosigner node, verifies
// policy.yaml.hmac against the document bytes, then parses the stored cosigner
// policy.
func LoadVerifiedCosignerConfig(dataRoot string, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedCosignerConfigDocument(dataRoot, kr)
	return stored, err
}

// LoadVerifiedCosignerConfigDocument reads, authenticates, and parses the
// cosigner-domain policy.yaml, returning the exact verified document bytes.
func LoadVerifiedCosignerConfigDocument(dataRoot string, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		CosignerPath(dataRoot),
		kr,
		ParseStoredCosignerConfig,
		"cosigner policy",
		"cosigner policy config",
	)
}

// LoadVerifiedCosignerConfigDocumentActive reads the cosigner policy from one
// already-resolved generation.
func LoadVerifiedCosignerConfigDocumentActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		active.PolicyPath(),
		kr,
		ParseStoredCosignerConfig,
		"cosigner policy",
		"cosigner policy config",
	)
}

// LoadVerifiedCosignerConfigActive verifies and parses the cosigner policy in one
// already-resolved generation.
func LoadVerifiedCosignerConfigActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedCosignerConfigDocumentActive(active, kr)
	return stored, err
}

func loadVerifiedStoredConfigAtPath(path string, kr *crypto.Keyring, parser storedConfigParser, docLabel, parseLabel string) (*StoredConfig, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, policyIntegrityWrap(ErrPolicyIntegrityMissingFile, err, "%s %s", docLabel, path)
		}
		return nil, nil, policyIntegrityWrap(ErrPolicyIntegrityUnreadable, err, "failed to read %s %s", docLabel, path)
	}
	sidecar, err := LoadPolicyIntegritySidecar(PolicyIntegritySidecarPath(path))
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyPolicyIntegrity(data, sidecar, kr); err != nil {
		return nil, nil, err
	}
	cfg, err := parser(data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse %s: %w", parseLabel, err)
	}
	return cfg, data, nil
}

// LoadVerifiedStoredConfigWithKeyring verifies policy.yaml with the identity
// keyring and parses it.
func LoadVerifiedStoredConfigWithKeyring(dataRoot string, kr *crypto.Keyring) (*StoredConfig, error) {
	return LoadVerifiedStoredConfig(dataRoot, kr)
}

// LoadVerifiedCosignerConfigWithKeyring verifies policy.yaml with the identity
// keyring as a cosigner policy and parses it.
func LoadVerifiedCosignerConfigWithKeyring(dataRoot string, kr *crypto.Keyring) (*StoredConfig, error) {
	return LoadVerifiedCosignerConfig(dataRoot, kr)
}

// SaveStoredConfigWithIntegrity writes policy.yaml and policy.yaml.hmac. The
// sidecar authenticates the exact policy bytes written to policy.yaml.
//
// This is a two-path write. Both files are prepared before either is published,
// so signing, marshaling, and staging failures preserve the old pair. Crash
// recovery remains fail-closed: callers may observe a valid old pair, a valid
// new pair, or a mismatch after interruption between the two renames.
func SaveStoredConfigWithIntegrity(dataRoot string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	policyBytes, err := MarshalStoredConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}
	return SavePolicyBytesWithIntegrity(dataRoot, policyBytes, kr, signedAt)
}

// SaveStoredCosignerConfigWithIntegrity writes policy.yaml and
// policy.yaml.hmac for a cosigner node.
func SaveStoredCosignerConfigWithIntegrity(dataRoot string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	cosignerBytes, err := MarshalStoredCosignerConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal cosigner policy config: %w", err)
	}
	return SaveCosignerBytesWithIntegrity(dataRoot, cosignerBytes, kr, signedAt)
}

// SaveStoredConfigActiveWithKeyring writes the signer policy and integrity
// sidecar into one already-resolved generation.
func SaveStoredConfigActiveWithKeyring(active storepaths.ActivePaths, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	policyBytes, err := MarshalStoredConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}
	return savePolicyBytesWithIntegrityAtPath(
		active.PolicyPath(),
		policyBytes,
		kr,
		signedAt,
		"policy config",
		"policy integrity sidecar",
	)
}

// SaveStoredCosignerConfigActiveWithKeyring writes the cosigner policy and
// integrity sidecar into one already-resolved generation.
func SaveStoredCosignerConfigActiveWithKeyring(active storepaths.ActivePaths, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	policyBytes, err := MarshalStoredCosignerConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal cosigner policy config: %w", err)
	}
	return savePolicyBytesWithIntegrityAtPath(
		active.PolicyPath(),
		policyBytes,
		kr,
		signedAt,
		"cosigner policy config",
		"policy integrity sidecar",
	)
}

// SavePolicyBytesActiveWithKeyring writes exact signer-policy bytes and their
// integrity sidecar into one already-resolved generation.
func SavePolicyBytesActiveWithKeyring(active storepaths.ActivePaths, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(
		active.PolicyPath(),
		policyBytes,
		kr,
		signedAt,
		"policy config",
		"policy integrity sidecar",
	)
}

// SaveCosignerBytesActiveWithKeyring writes exact cosigner-policy bytes and their
// integrity sidecar into one already-resolved generation.
func SaveCosignerBytesActiveWithKeyring(active storepaths.ActivePaths, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(
		active.PolicyPath(),
		policyBytes,
		kr,
		signedAt,
		"cosigner policy config",
		"policy integrity sidecar",
	)
}

// SavePolicyBytesWithIntegrity writes exact policy.yaml bytes plus
// policy.yaml.hmac. The caller owns parsing and runtime validation before
// calling this lower-level primitive.
func SavePolicyBytesWithIntegrity(dataRoot string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(PolicyPath(dataRoot), policyBytes, kr, signedAt, "policy config", "policy integrity sidecar")
}

// SaveCosignerBytesWithIntegrity writes exact cosigner-policy bytes to
// policy.yaml plus policy.yaml.hmac. The caller owns parsing and runtime
// validation before calling this lower-level primitive.
func SaveCosignerBytesWithIntegrity(dataRoot string, cosignerBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(CosignerPath(dataRoot), cosignerBytes, kr, signedAt, "cosigner policy config", "policy integrity sidecar")
}

func savePolicyBytesWithIntegrityAtPath(path string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time, configLabel, sidecarLabel string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", configLabel, err)
	}

	sidecarPath := PolicyIntegritySidecarPath(path)
	sidecar, err := SignPolicyIntegrity(policyBytes, kr, signedAt)
	if err != nil {
		return err
	}
	sidecarBytes, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileSetDurable(
		fsutil.DurableFileWrite{Path: path, Data: policyBytes, Profile: fsutil.PrivateStoreFileProfile},
		fsutil.DurableFileWrite{Path: sidecarPath, Data: sidecarBytes, Profile: fsutil.PrivateStoreFileProfile},
	); err != nil {
		return fmt.Errorf("failed to write %s and %s: %w", configLabel, sidecarLabel, err)
	}
	return nil
}

// SaveStoredConfigWithKeyring writes policy.yaml plus policy.yaml.hmac with
// the identity keyring.
func SaveStoredConfigWithKeyring(dataRoot string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveStoredConfigWithIntegrity(dataRoot, cfg, kr, signedAt)
}

// SaveStoredCosignerConfigWithKeyring writes cosigner policy.yaml plus
// policy.yaml.hmac with the identity keyring.
func SaveStoredCosignerConfigWithKeyring(dataRoot string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveStoredCosignerConfigWithIntegrity(dataRoot, cfg, kr, signedAt)
}

// SavePolicyBytesWithKeyring writes exact policy.yaml bytes plus
// policy.yaml.hmac with the identity keyring.
func SavePolicyBytesWithKeyring(dataRoot string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return SavePolicyBytesWithIntegrity(dataRoot, policyBytes, kr, signedAt)
}

// SaveCosignerBytesWithKeyring writes exact cosigner-policy bytes plus
// policy.yaml.hmac with the identity keyring.
func SaveCosignerBytesWithKeyring(dataRoot string, cosignerBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveCosignerBytesWithIntegrity(dataRoot, cosignerBytes, kr, signedAt)
}

// SignPolicyFileIntegrity writes policy.yaml.hmac for the current policy.yaml
// bytes. It preserves the YAML exactly as edited and rejects malformed policy
// before creating a trusted sidecar.
func SignPolicyFileIntegrity(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(PolicyPath(dataRoot), kr, signedAt, ParseStoredConfig, "policy", "policy config", "policy integrity sidecar")
}

// SignCosignerFileIntegrity writes policy.yaml.hmac for the current
// cosigner-policy bytes in policy.yaml.
func SignCosignerFileIntegrity(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(CosignerPath(dataRoot), kr, signedAt, ParseStoredCosignerConfig, "cosigner policy", "cosigner policy config", "policy integrity sidecar")
}

func signPolicyFileIntegrityAtPath(path string, kr *crypto.Keyring, signedAt time.Time, parser storedConfigParser, docLabel, configLabel, sidecarLabel string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return policyIntegrityWrap(ErrPolicyIntegrityMissingFile, err, "%s %s", docLabel, path)
		}
		return policyIntegrityWrap(ErrPolicyIntegrityUnreadable, err, "failed to read %s %s", docLabel, path)
	}
	if _, err := parser(data); err != nil {
		return fmt.Errorf("failed to parse %s: %w", configLabel, err)
	}
	sidecar, err := SignPolicyIntegrity(data, kr, signedAt)
	if err != nil {
		return err
	}
	sidecarBytes, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		return err
	}
	sidecarPath := PolicyIntegritySidecarPath(path)
	if err := fsutil.WriteFileDurableWithProfile(sidecarPath, sidecarBytes, fsutil.PrivateStoreFileProfile); err != nil {
		return fmt.Errorf("failed to write %s: %w", sidecarLabel, err)
	}
	return nil
}

// SignPolicyFileIntegrityWithKeyring signs the current policy.yaml bytes with
// the identity keyring.
func SignPolicyFileIntegrityWithKeyring(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return SignPolicyFileIntegrity(dataRoot, kr, signedAt)
}

// SignCosignerFileIntegrityWithKeyring signs the current cosigner-policy bytes in
// policy.yaml with the identity keyring.
func SignCosignerFileIntegrityWithKeyring(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return SignCosignerFileIntegrity(dataRoot, kr, signedAt)
}

// SignPolicyFileIntegrityActiveWithKeyring signs the current signer-policy
// bytes in one already-resolved generation.
func SignPolicyFileIntegrityActiveWithKeyring(active storepaths.ActivePaths, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(
		active.PolicyPath(),
		kr,
		signedAt,
		ParseStoredConfig,
		"policy",
		"policy config",
		"policy integrity sidecar",
	)
}

// SignCosignerFileIntegrityActiveWithKeyring signs the current cosigner-policy
// bytes in one already-resolved generation.
func SignCosignerFileIntegrityActiveWithKeyring(active storepaths.ActivePaths, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(
		active.PolicyPath(),
		kr,
		signedAt,
		ParseStoredCosignerConfig,
		"cosigner policy",
		"cosigner policy config",
		"policy integrity sidecar",
	)
}
