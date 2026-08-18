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
)

type storedConfigParser func([]byte) (*StoredConfig, error)

// LoadVerifiedStoredConfig reads policy.yaml and policy.yaml.hmac, verifies the
// sidecar against the policy bytes, then parses the stored policy.
func LoadVerifiedStoredConfig(dataRoot, identityID string, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedStoredConfigDocument(dataRoot, identityID, kr)
	return stored, err
}

// LoadVerifiedStoredConfigDocument reads, authenticates, and parses policy.yaml,
// returning the exact document bytes covered by the verified sidecar.
func LoadVerifiedStoredConfigDocument(dataRoot, identityID string, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		PolicyPath(dataRoot, identityID),
		kr,
		ParseStoredConfig,
		"policy",
		"policy config",
	)
}

// LoadVerifiedSentryConfig reads policy.yaml for a sentry node, verifies
// policy.yaml.hmac against the document bytes, then parses the stored sentry
// policy.
func LoadVerifiedSentryConfig(dataRoot, identityID string, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedSentryConfigDocument(dataRoot, identityID, kr)
	return stored, err
}

// LoadVerifiedSentryConfigDocument reads, authenticates, and parses the
// sentry-domain policy.yaml, returning the exact verified document bytes.
func LoadVerifiedSentryConfigDocument(dataRoot, identityID string, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		SentryPath(dataRoot, identityID),
		kr,
		ParseStoredSentryConfig,
		"sentry policy",
		"sentry policy config",
	)
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
func LoadVerifiedStoredConfigWithKeyring(dataRoot, identityID string, kr *crypto.Keyring) (*StoredConfig, error) {
	return LoadVerifiedStoredConfig(dataRoot, identityID, kr)
}

// LoadVerifiedSentryConfigWithKeyring verifies policy.yaml with the identity
// keyring as a sentry policy and parses it.
func LoadVerifiedSentryConfigWithKeyring(dataRoot, identityID string, kr *crypto.Keyring) (*StoredConfig, error) {
	return LoadVerifiedSentryConfig(dataRoot, identityID, kr)
}

// SaveStoredConfigWithIntegrity writes policy.yaml and policy.yaml.hmac. The
// sidecar authenticates the exact policy bytes written to policy.yaml.
//
// This is a two-path write. Both files are prepared before either is published,
// so signing, marshaling, and staging failures preserve the old pair. Crash
// recovery remains fail-closed: callers may observe a valid old pair, a valid
// new pair, or a mismatch after interruption between the two renames.
func SaveStoredConfigWithIntegrity(dataRoot, identityID string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	policyBytes, err := MarshalStoredConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy config: %w", err)
	}
	return SavePolicyBytesWithIntegrity(dataRoot, identityID, policyBytes, kr, signedAt)
}

// SaveStoredSentryConfigWithIntegrity writes policy.yaml and
// policy.yaml.hmac for a sentry node.
func SaveStoredSentryConfigWithIntegrity(dataRoot, identityID string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	sentryBytes, err := MarshalStoredSentryConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal sentry policy config: %w", err)
	}
	return SaveSentryBytesWithIntegrity(dataRoot, identityID, sentryBytes, kr, signedAt)
}

// SavePolicyBytesWithIntegrity writes exact policy.yaml bytes plus
// policy.yaml.hmac. The caller owns parsing and runtime validation before
// calling this lower-level primitive.
func SavePolicyBytesWithIntegrity(dataRoot, identityID string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(PolicyPath(dataRoot, identityID), policyBytes, kr, signedAt, "policy config", "policy integrity sidecar")
}

// SaveSentryBytesWithIntegrity writes exact sentry-policy bytes to
// policy.yaml plus policy.yaml.hmac. The caller owns parsing and runtime
// validation before calling this lower-level primitive.
func SaveSentryBytesWithIntegrity(dataRoot, identityID string, sentryBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(SentryPath(dataRoot, identityID), sentryBytes, kr, signedAt, "sentry policy config", "policy integrity sidecar")
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
func SaveStoredConfigWithKeyring(dataRoot, identityID string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveStoredConfigWithIntegrity(dataRoot, identityID, cfg, kr, signedAt)
}

// SaveStoredSentryConfigWithKeyring writes sentry policy.yaml plus
// policy.yaml.hmac with the identity keyring.
func SaveStoredSentryConfigWithKeyring(dataRoot, identityID string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveStoredSentryConfigWithIntegrity(dataRoot, identityID, cfg, kr, signedAt)
}

// SavePolicyBytesWithKeyring writes exact policy.yaml bytes plus
// policy.yaml.hmac with the identity keyring.
func SavePolicyBytesWithKeyring(dataRoot, identityID string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return SavePolicyBytesWithIntegrity(dataRoot, identityID, policyBytes, kr, signedAt)
}

// SaveSentryBytesWithKeyring writes exact sentry-policy bytes plus
// policy.yaml.hmac with the identity keyring.
func SaveSentryBytesWithKeyring(dataRoot, identityID string, sentryBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveSentryBytesWithIntegrity(dataRoot, identityID, sentryBytes, kr, signedAt)
}

// SignPolicyFileIntegrity writes policy.yaml.hmac for the current policy.yaml
// bytes. It preserves the YAML exactly as edited and rejects malformed policy
// before creating a trusted sidecar.
func SignPolicyFileIntegrity(dataRoot, identityID string, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(PolicyPath(dataRoot, identityID), kr, signedAt, ParseStoredConfig, "policy", "policy config", "policy integrity sidecar")
}

// SignSentryFileIntegrity writes policy.yaml.hmac for the current
// sentry-policy bytes in policy.yaml.
func SignSentryFileIntegrity(dataRoot, identityID string, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(SentryPath(dataRoot, identityID), kr, signedAt, ParseStoredSentryConfig, "sentry policy", "sentry policy config", "policy integrity sidecar")
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
func SignPolicyFileIntegrityWithKeyring(dataRoot, identityID string, kr *crypto.Keyring, signedAt time.Time) error {
	return SignPolicyFileIntegrity(dataRoot, identityID, kr, signedAt)
}

// SignSentryFileIntegrityWithKeyring signs the current sentry-policy bytes in
// policy.yaml with the identity keyring.
func SignSentryFileIntegrityWithKeyring(dataRoot, identityID string, kr *crypto.Keyring, signedAt time.Time) error {
	return SignSentryFileIntegrity(dataRoot, identityID, kr, signedAt)
}
