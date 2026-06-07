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

// LoadVerifiedSentryConfig reads policy.yaml for a sentry node, verifies
// policy.yaml.hmac against the document bytes, then parses the stored sentry
// policy.
func LoadVerifiedSentryConfig(dataRoot, identityID string, key []byte) (*StoredConfig, error) {
	return loadVerifiedStoredConfigAtPath(
		SentryPath(dataRoot, identityID),
		key,
		ParseStoredSentryConfig,
		"sentry policy",
		"sentry policy config",
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

// LoadVerifiedSentryConfigWithMasterKey derives the policy integrity key
// from the identity master key, verifies policy.yaml as a sentry policy, and
// parses it.
func LoadVerifiedSentryConfigWithMasterKey(dataRoot, identityID string, masterKey []byte) (*StoredConfig, error) {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(key)
	return LoadVerifiedSentryConfig(dataRoot, identityID, key)
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

// SaveStoredSentryConfigWithIntegrity writes policy.yaml and
// policy.yaml.hmac for a sentry node.
func SaveStoredSentryConfigWithIntegrity(dataRoot, identityID string, cfg *StoredConfig, key []byte, signedAt time.Time) error {
	sentryBytes, err := MarshalStoredSentryConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal sentry policy config: %w", err)
	}
	return SaveSentryBytesWithIntegrity(dataRoot, identityID, sentryBytes, key, signedAt)
}

// SavePolicyBytesWithIntegrity writes exact policy.yaml bytes plus
// policy.yaml.hmac. The caller owns parsing and runtime validation before
// calling this lower-level primitive.
func SavePolicyBytesWithIntegrity(dataRoot, identityID string, policyBytes []byte, key []byte, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(PolicyPath(dataRoot, identityID), policyBytes, key, signedAt, "policy config", "policy integrity sidecar")
}

// SaveSentryBytesWithIntegrity writes exact sentry-policy bytes to
// policy.yaml plus policy.yaml.hmac. The caller owns parsing and runtime
// validation before calling this lower-level primitive.
func SaveSentryBytesWithIntegrity(dataRoot, identityID string, sentryBytes []byte, key []byte, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(SentryPath(dataRoot, identityID), sentryBytes, key, signedAt, "sentry policy config", "policy integrity sidecar")
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

// SaveStoredSentryConfigWithMasterKey derives the policy integrity key
// from the identity master key and writes sentry policy.yaml plus
// policy.yaml.hmac.
func SaveStoredSentryConfigWithMasterKey(dataRoot, identityID string, cfg *StoredConfig, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SaveStoredSentryConfigWithIntegrity(dataRoot, identityID, cfg, key, signedAt)
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

// SaveSentryBytesWithMasterKey derives the policy integrity key from the
// identity master key and writes exact sentry-policy bytes plus
// policy.yaml.hmac.
func SaveSentryBytesWithMasterKey(dataRoot, identityID string, sentryBytes []byte, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SaveSentryBytesWithIntegrity(dataRoot, identityID, sentryBytes, key, signedAt)
}

// SignPolicyFileIntegrity writes policy.yaml.hmac for the current policy.yaml
// bytes. It preserves the YAML exactly as edited and rejects malformed policy
// before creating a trusted sidecar.
func SignPolicyFileIntegrity(dataRoot, identityID string, key []byte, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(PolicyPath(dataRoot, identityID), key, signedAt, ParseStoredConfig, "policy", "policy config", "policy integrity sidecar")
}

// SignSentryFileIntegrity writes policy.yaml.hmac for the current
// sentry-policy bytes in policy.yaml.
func SignSentryFileIntegrity(dataRoot, identityID string, key []byte, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(SentryPath(dataRoot, identityID), key, signedAt, ParseStoredSentryConfig, "sentry policy", "sentry policy config", "policy integrity sidecar")
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

// SignSentryFileIntegrityWithMasterKey derives the policy integrity key
// from the identity master key and signs the current sentry-policy bytes in
// policy.yaml.
func SignSentryFileIntegrityWithMasterKey(dataRoot, identityID string, masterKey []byte, signedAt time.Time) error {
	key, err := crypto.DerivePolicyIntegrityKey(masterKey)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(key)
	return SignSentryFileIntegrity(dataRoot, identityID, key, signedAt)
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
