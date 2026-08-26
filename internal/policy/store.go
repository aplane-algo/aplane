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

// LoadVerifiedSentryConfig reads policy.yaml for a sentry node, verifies
// policy.yaml.hmac against the document bytes, then parses the stored sentry
// policy.
func LoadVerifiedSentryConfig(dataRoot string, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedSentryConfigDocument(dataRoot, kr)
	return stored, err
}

// LoadVerifiedSentryConfigDocument reads, authenticates, and parses the
// sentry-domain policy.yaml, returning the exact verified document bytes.
func LoadVerifiedSentryConfigDocument(dataRoot string, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		SentryPath(dataRoot),
		kr,
		ParseStoredSentryConfig,
		"sentry policy",
		"sentry policy config",
	)
}

// LoadVerifiedSentryConfigDocumentActive reads the sentry policy from one
// already-resolved generation.
func LoadVerifiedSentryConfigDocumentActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*StoredConfig, []byte, error) {
	return loadVerifiedStoredConfigAtPath(
		active.PolicyPath(),
		kr,
		ParseStoredSentryConfig,
		"sentry policy",
		"sentry policy config",
	)
}

// LoadVerifiedSentryConfigActive verifies and parses the sentry policy in one
// already-resolved generation.
func LoadVerifiedSentryConfigActive(active storepaths.ActivePaths, kr *crypto.Keyring) (*StoredConfig, error) {
	stored, _, err := LoadVerifiedSentryConfigDocumentActive(active, kr)
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

// LoadVerifiedSentryConfigWithKeyring verifies policy.yaml with the identity
// keyring as a sentry policy and parses it.
func LoadVerifiedSentryConfigWithKeyring(dataRoot string, kr *crypto.Keyring) (*StoredConfig, error) {
	return LoadVerifiedSentryConfig(dataRoot, kr)
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

// SaveStoredSentryConfigWithIntegrity writes policy.yaml and
// policy.yaml.hmac for a sentry node.
func SaveStoredSentryConfigWithIntegrity(dataRoot string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	sentryBytes, err := MarshalStoredSentryConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal sentry policy config: %w", err)
	}
	return SaveSentryBytesWithIntegrity(dataRoot, sentryBytes, kr, signedAt)
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

// SaveStoredSentryConfigActiveWithKeyring writes the sentry policy and
// integrity sidecar into one already-resolved generation.
func SaveStoredSentryConfigActiveWithKeyring(active storepaths.ActivePaths, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	policyBytes, err := MarshalStoredSentryConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal sentry policy config: %w", err)
	}
	return savePolicyBytesWithIntegrityAtPath(
		active.PolicyPath(),
		policyBytes,
		kr,
		signedAt,
		"sentry policy config",
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

// SaveSentryBytesActiveWithKeyring writes exact sentry-policy bytes and their
// integrity sidecar into one already-resolved generation.
func SaveSentryBytesActiveWithKeyring(active storepaths.ActivePaths, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(
		active.PolicyPath(),
		policyBytes,
		kr,
		signedAt,
		"sentry policy config",
		"policy integrity sidecar",
	)
}

// SavePolicyBytesWithIntegrity writes exact policy.yaml bytes plus
// policy.yaml.hmac. The caller owns parsing and runtime validation before
// calling this lower-level primitive.
func SavePolicyBytesWithIntegrity(dataRoot string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(PolicyPath(dataRoot), policyBytes, kr, signedAt, "policy config", "policy integrity sidecar")
}

// SaveSentryBytesWithIntegrity writes exact sentry-policy bytes to
// policy.yaml plus policy.yaml.hmac. The caller owns parsing and runtime
// validation before calling this lower-level primitive.
func SaveSentryBytesWithIntegrity(dataRoot string, sentryBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return savePolicyBytesWithIntegrityAtPath(SentryPath(dataRoot), sentryBytes, kr, signedAt, "sentry policy config", "policy integrity sidecar")
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

// SaveStoredSentryConfigWithKeyring writes sentry policy.yaml plus
// policy.yaml.hmac with the identity keyring.
func SaveStoredSentryConfigWithKeyring(dataRoot string, cfg *StoredConfig, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveStoredSentryConfigWithIntegrity(dataRoot, cfg, kr, signedAt)
}

// SavePolicyBytesWithKeyring writes exact policy.yaml bytes plus
// policy.yaml.hmac with the identity keyring.
func SavePolicyBytesWithKeyring(dataRoot string, policyBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return SavePolicyBytesWithIntegrity(dataRoot, policyBytes, kr, signedAt)
}

// SaveSentryBytesWithKeyring writes exact sentry-policy bytes plus
// policy.yaml.hmac with the identity keyring.
func SaveSentryBytesWithKeyring(dataRoot string, sentryBytes []byte, kr *crypto.Keyring, signedAt time.Time) error {
	return SaveSentryBytesWithIntegrity(dataRoot, sentryBytes, kr, signedAt)
}

// SignPolicyFileIntegrity writes policy.yaml.hmac for the current policy.yaml
// bytes. It preserves the YAML exactly as edited and rejects malformed policy
// before creating a trusted sidecar.
func SignPolicyFileIntegrity(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(PolicyPath(dataRoot), kr, signedAt, ParseStoredConfig, "policy", "policy config", "policy integrity sidecar")
}

// SignSentryFileIntegrity writes policy.yaml.hmac for the current
// sentry-policy bytes in policy.yaml.
func SignSentryFileIntegrity(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(SentryPath(dataRoot), kr, signedAt, ParseStoredSentryConfig, "sentry policy", "sentry policy config", "policy integrity sidecar")
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

// SignSentryFileIntegrityWithKeyring signs the current sentry-policy bytes in
// policy.yaml with the identity keyring.
func SignSentryFileIntegrityWithKeyring(dataRoot string, kr *crypto.Keyring, signedAt time.Time) error {
	return SignSentryFileIntegrity(dataRoot, kr, signedAt)
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

// SignSentryFileIntegrityActiveWithKeyring signs the current sentry-policy
// bytes in one already-resolved generation.
func SignSentryFileIntegrityActiveWithKeyring(active storepaths.ActivePaths, kr *crypto.Keyring, signedAt time.Time) error {
	return signPolicyFileIntegrityAtPath(
		active.PolicyPath(),
		kr,
		signedAt,
		ParseStoredSentryConfig,
		"sentry policy",
		"sentry policy config",
		"policy integrity sidecar",
	)
}
