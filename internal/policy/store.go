// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
)

type storedConfigParser func([]byte) (*StoredConfig, error)

// LoadVerifiedStoredConfig reads policy.yaml and policy.yaml.hmac, verifies the
// sidecar against the policy bytes, then parses the stored policy.
func LoadVerifiedStoredConfig(dataRoot, identityID string, key []byte) (*StoredConfig, error) {
	return loadVerifiedStoredConfigAtPath(
		PolicyPath(dataRoot, identityID),
		key,
		ParseStoredConfig,
		"policy",
		"policy config",
	)
}

// LoadVerifiedAttestationConfig reads attestation.yaml and
// attestation.yaml.hmac, verifies the sidecar against the document bytes, then
// parses the stored attestation policy.
func LoadVerifiedAttestationConfig(dataRoot, identityID string, key []byte) (*StoredConfig, error) {
	return loadVerifiedStoredConfigAtPath(
		AttestationPath(dataRoot, identityID),
		key,
		ParseStoredAttestationConfig,
		"attestation policy",
		"attestation config",
	)
}

func loadVerifiedStoredConfigAtPath(path string, key []byte, parser storedConfigParser, docLabel, parseLabel string) (*StoredConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, policyIntegrityWrap(ErrPolicyIntegrityMissingFile, err, "%s %s", docLabel, path)
		}
		return nil, policyIntegrityWrap(ErrPolicyIntegrityUnreadable, err, "failed to read %s %s", docLabel, path)
	}
	sidecar, err := LoadPolicyIntegritySidecar(PolicyIntegritySidecarPath(path))
	if err != nil {
		return nil, err
	}
	if err := VerifyPolicyIntegrity(data, sidecar, key); err != nil {
		return nil, err
	}
	cfg, err := parser(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", parseLabel, err)
	}
	return cfg, nil
}

// LoadVerifiedStoredConfigWithMasterKey derives the policy integrity key from
// the identity master key, verifies policy.yaml, and parses it.
func LoadVerifiedStoredConfigWithMasterKey(dataRoot, identityID string, masterKey []byte) (*StoredConfig, error) {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)
	return LoadVerifiedStoredConfig(dataRoot, identityID, key)
}

// LoadVerifiedAttestationConfigWithMasterKey derives the policy integrity key
// from the identity master key, verifies attestation.yaml, and parses it.
func LoadVerifiedAttestationConfigWithMasterKey(dataRoot, identityID string, masterKey []byte) (*StoredConfig, error) {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)
	return LoadVerifiedAttestationConfig(dataRoot, identityID, key)
}

// SaveStoredConfigWithIntegrity writes policy.yaml and policy.yaml.hmac. The
// sidecar authenticates the exact policy bytes written to policy.yaml.
//
// This is a two-path write. Crash recovery is fail-closed: callers may observe
// either a valid old pair, a valid new pair, or a mismatch that must be repaired
// explicitly.
func SaveStoredConfigWithIntegrity(dataRoot, identityID string, cfg *StoredConfig, key []byte, signedAt time.Time) error {
	policyBytes, err := MarshalStoredConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}
	return SavePolicyBytesWithIntegrity(dataRoot, identityID, policyBytes, key, signedAt)
}

// SaveStoredAttestationConfigWithIntegrity writes attestation.yaml and
// attestation.yaml.hmac.
func SaveStoredAttestationConfigWithIntegrity(dataRoot, identityID string, cfg *StoredConfig, key []byte, signedAt time.Time) error {
	attestationBytes, err := MarshalStoredAttestationConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation config: %w", err)
	}
	return SaveAttestationBytesWithIntegrity(dataRoot, identityID, attestationBytes, key, signedAt)
}

// SavePolicyBytesWithIntegrity writes exact policy.yaml bytes plus
// policy.yaml.hmac. The caller owns parsing and runtime validation before
// calling this lower-level primitive.
func SavePolicyBytesWithIntegrity(dataRoot, identityID string, policyBytes []byte, key []byte, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(PolicyPath(dataRoot, identityID), policyBytes, key, signedAt, "policy config", "policy integrity sidecar")
}

// SaveAttestationBytesWithIntegrity writes exact attestation.yaml bytes plus
// attestation.yaml.hmac. The caller owns parsing and runtime validation before
// calling this lower-level primitive.
func SaveAttestationBytesWithIntegrity(dataRoot, identityID string, attestationBytes []byte, key []byte, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(AttestationPath(dataRoot, identityID), attestationBytes, key, signedAt, "attestation config", "attestation integrity sidecar")
}

func savePolicyBytesWithIntegrityAtPath(path string, policyBytes []byte, key []byte, signedAt time.Time, configLabel, sidecarLabel string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create %s directory: %w", configLabel, err)
	}

	policyTmp := path + ".tmp"
	sidecarPath := PolicyIntegritySidecarPath(path)
	sidecarTmp := sidecarPath + ".tmp"
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(policyTmp)
			_ = os.Remove(sidecarTmp)
		}
	}()

	if err := writeSyncedPolicyFile(policyTmp, policyBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", configLabel, err)
	}
	info, err := os.Stat(policyTmp)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", configLabel, err)
	}
	sidecar, err := SignPolicyIntegrity(policyBytes, key, signedAt, info.ModTime().UnixNano())
	if err != nil {
		return err
	}
	sidecarBytes, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		return err
	}
	if err := writeSyncedPolicyFile(sidecarTmp, sidecarBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", sidecarLabel, err)
	}

	if err := os.Rename(policyTmp, path); err != nil {
		return fmt.Errorf("failed to rename %s: %w", configLabel, err)
	}
	if err := os.Rename(sidecarTmp, sidecarPath); err != nil {
		return fmt.Errorf("failed to rename %s: %w", sidecarLabel, err)
	}
	if err := syncPolicyDir(dir); err != nil {
		return fmt.Errorf("failed to sync %s directory: %w", configLabel, err)
	}
	cleanup = false
	return nil
}

// SaveStoredConfigWithMasterKey derives the policy integrity key from the
// identity master key and writes policy.yaml plus policy.yaml.hmac.
func SaveStoredConfigWithMasterKey(dataRoot, identityID string, cfg *StoredConfig, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SaveStoredConfigWithIntegrity(dataRoot, identityID, cfg, key, signedAt)
}

// SaveStoredAttestationConfigWithMasterKey derives the policy integrity key
// from the identity master key and writes attestation.yaml plus
// attestation.yaml.hmac.
func SaveStoredAttestationConfigWithMasterKey(dataRoot, identityID string, cfg *StoredConfig, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SaveStoredAttestationConfigWithIntegrity(dataRoot, identityID, cfg, key, signedAt)
}

// SavePolicyBytesWithMasterKey derives the policy integrity key from the
// identity master key and writes exact policy.yaml bytes plus policy.yaml.hmac.
func SavePolicyBytesWithMasterKey(dataRoot, identityID string, policyBytes []byte, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SavePolicyBytesWithIntegrity(dataRoot, identityID, policyBytes, key, signedAt)
}

// SaveAttestationBytesWithMasterKey derives the policy integrity key from the
// identity master key and writes exact attestation.yaml bytes plus
// attestation.yaml.hmac.
func SaveAttestationBytesWithMasterKey(dataRoot, identityID string, attestationBytes []byte, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SaveAttestationBytesWithIntegrity(dataRoot, identityID, attestationBytes, key, signedAt)
}

// SignPolicyFileIntegrity writes policy.yaml.hmac for the current policy.yaml
// bytes. It preserves the YAML exactly as edited and rejects malformed policy
// before creating a trusted sidecar.
func SignPolicyFileIntegrity(dataRoot, identityID string, key []byte, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(PolicyPath(dataRoot, identityID), key, signedAt, ParseStoredConfig, "policy", "policy config", "policy integrity sidecar")
}

// SignAttestationFileIntegrity writes attestation.yaml.hmac for the current
// attestation.yaml bytes.
func SignAttestationFileIntegrity(dataRoot, identityID string, key []byte, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(AttestationPath(dataRoot, identityID), key, signedAt, ParseStoredAttestationConfig, "attestation policy", "attestation config", "attestation integrity sidecar")
}

func signPolicyFileIntegrityAtPath(path string, key []byte, signedAt time.Time, parser storedConfigParser, docLabel, configLabel, sidecarLabel string) error {
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
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", configLabel, err)
	}
	sidecar, err := SignPolicyIntegrity(data, key, signedAt, info.ModTime().UnixNano())
	if err != nil {
		return err
	}
	sidecarBytes, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		return err
	}
	sidecarPath := PolicyIntegritySidecarPath(path)
	sidecarTmp := sidecarPath + ".tmp"
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(sidecarTmp)
		}
	}()
	if err := writeSyncedPolicyFile(sidecarTmp, sidecarBytes, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", sidecarLabel, err)
	}
	if err := os.Rename(sidecarTmp, sidecarPath); err != nil {
		return fmt.Errorf("failed to rename %s: %w", sidecarLabel, err)
	}
	if err := syncPolicyDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed to sync %s directory: %w", configLabel, err)
	}
	cleanup = false
	return nil
}

// SignPolicyFileIntegrityWithMasterKey derives the policy integrity key from
// the identity master key and signs the current policy.yaml bytes.
func SignPolicyFileIntegrityWithMasterKey(dataRoot, identityID string, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SignPolicyFileIntegrity(dataRoot, identityID, key, signedAt)
}

// SignAttestationFileIntegrityWithMasterKey derives the policy integrity key
// from the identity master key and signs the current attestation.yaml bytes.
func SignAttestationFileIntegrityWithMasterKey(dataRoot, identityID string, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SignAttestationFileIntegrity(dataRoot, identityID, key, signedAt)
}

func writeSyncedPolicyFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	closeFile := true
	defer func() {
		if closeFile {
			_ = f.Close()
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	closeFile = false
	return f.Close()
}

func syncPolicyDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
