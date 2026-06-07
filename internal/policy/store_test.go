// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apcrypto "github.com/aplane-algo/aplane/internal/crypto"
)

func TestSaveAndLoadVerifiedStoredConfig(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	wantReject := false
	wantFee := uint64(7000)
	want := &StoredConfig{
		RejectForeignRekey: &wantReject,
		MaxFeeMicroAlgos:   &wantFee,
	}

	if err := SaveStoredConfigWithIntegrity(root, "alice", want, key, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v", err)
	}
	if _, err := os.Stat(PolicyIntegritySidecarPath(PolicyPath(root, "alice"))); err != nil {
		t.Fatalf("sidecar stat error = %v", err)
	}

	got, err := LoadVerifiedStoredConfig(root, "alice", key)
	if err != nil {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v", err)
	}
	if got.RejectForeignRekey == nil || *got.RejectForeignRekey != wantReject {
		t.Fatalf("RejectForeignRekey = %#v, want %v", got.RejectForeignRekey, wantReject)
	}
	if got.MaxFeeMicroAlgos == nil || *got.MaxFeeMicroAlgos != wantFee {
		t.Fatalf("MaxFeeMicroAlgos = %#v, want %d", got.MaxFeeMicroAlgos, wantFee)
	}
}

func TestSaveAndLoadVerifiedStoredConfigWithMasterKey(t *testing.T) {
	root := t.TempDir()
	masterKey := []byte("test master key")
	wantReject := false
	want := &StoredConfig{RejectForeignRekey: &wantReject}

	if err := SaveStoredConfigWithMasterKey(root, "alice", want, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredConfigWithMasterKey() error = %v", err)
	}
	got, err := LoadVerifiedStoredConfigWithMasterKey(root, "alice", masterKey)
	if err != nil {
		t.Fatalf("LoadVerifiedStoredConfigWithMasterKey() error = %v", err)
	}
	if got.RejectForeignRekey == nil || *got.RejectForeignRekey != wantReject {
		t.Fatalf("RejectForeignRekey = %#v, want %v", got.RejectForeignRekey, wantReject)
	}
}

func TestSaveAndLoadVerifiedSentryConfigWithMasterKey(t *testing.T) {
	root := t.TempDir()
	masterKey := []byte("test master key")
	rejectRekey := true
	want := &StoredConfig{RejectRekey: &rejectRekey}

	if err := SaveStoredSentryConfigWithMasterKey(root, "alice", want, masterKey, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredSentryConfigWithMasterKey() error = %v", err)
	}
	got, err := LoadVerifiedSentryConfigWithMasterKey(root, "alice", masterKey)
	if err != nil {
		t.Fatalf("LoadVerifiedSentryConfigWithMasterKey() error = %v", err)
	}
	if got.RejectRekey == nil || !*got.RejectRekey {
		t.Fatalf("RejectRekey = %#v, want true", got.RejectRekey)
	}
}

func TestSignPolicyFileIntegrityPreservesPolicyBytes(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	path := PolicyPath(root, "alice")
	policyBytes := []byte("# direct edit\nreject_foreign_rekey: false\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(path, policyBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}

	if err := SignPolicyFileIntegrity(root, "alice", key, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SignPolicyFileIntegrity() error = %v", err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(policyBytes) {
		t.Fatalf("policy bytes changed during signing:\ngot  %q\nwant %q", string(gotBytes), string(policyBytes))
	}
	got, err := LoadVerifiedStoredConfig(root, "alice", key)
	if err != nil {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v", err)
	}
	if got.RejectForeignRekey == nil || *got.RejectForeignRekey {
		t.Fatalf("RejectForeignRekey = %#v, want false", got.RejectForeignRekey)
	}
}

func TestSignPolicyFileIntegrityRejectsMalformedPolicy(t *testing.T) {
	root := t.TempDir()
	path := PolicyPath(root, "alice")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: [\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}

	err := SignPolicyFileIntegrity(root, "alice", policyIntegrityTestKey(t), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "failed to parse policy config") {
		t.Fatalf("SignPolicyFileIntegrity() error = %v, want parse failure", err)
	}
	if errors.Is(err, ErrPolicyIntegrity) {
		t.Fatalf("SignPolicyFileIntegrity() error = %v, want parse failure not integrity sentinel", err)
	}
}

func TestLoadVerifiedStoredConfigMissingPolicy(t *testing.T) {
	_, err := LoadVerifiedStoredConfig(t.TempDir(), "alice", policyIntegrityTestKey(t))
	if !errors.Is(err, ErrPolicyIntegrityMissingFile) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMissingFile", err)
	}
}

func TestLoadVerifiedStoredConfigUnreadablePolicyWrapsIntegrityError(t *testing.T) {
	root := t.TempDir()
	path := PolicyPath(root, "alice")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll(policy path) error = %v", err)
	}

	_, err := LoadVerifiedStoredConfig(root, "alice", policyIntegrityTestKey(t))
	if !errors.Is(err, ErrPolicyIntegrity) || !errors.Is(err, ErrPolicyIntegrityUnreadable) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want integrity unreadable error", err)
	}
}

func TestLoadVerifiedStoredConfigMissingSidecar(t *testing.T) {
	root := t.TempDir()
	if err := SaveStoredConfig(root, "alice", &StoredConfig{}); err != nil {
		t.Fatalf("SaveStoredConfig() error = %v", err)
	}
	_, err := LoadVerifiedStoredConfig(root, "alice", policyIntegrityTestKey(t))
	if !errors.Is(err, ErrPolicyIntegrityMissingSidecar) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMissingSidecar", err)
	}
}

func TestLoadVerifiedStoredConfigRejectsTamperedPolicy(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	if err := SaveStoredConfigWithIntegrity(root, "alice", &StoredConfig{}, key, time.Time{}); err != nil {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v", err)
	}
	if err := os.WriteFile(PolicyPath(root, "alice"), []byte("reject_foreign_rekey: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadVerifiedStoredConfig(root, "alice", key)
	if !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}

func TestLoadVerifiedStoredConfigRejectsMalformedSignedPolicy(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	policyBytes := []byte("reject_foreign_rekey: [\n")
	path := PolicyPath(root, "alice")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(path, policyBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	sidecar, err := SignPolicyIntegrity(policyBytes, key, time.Time{}, 0)
	if err != nil {
		t.Fatalf("SignPolicyIntegrity() error = %v", err)
	}
	sidecarBytes, err := MarshalPolicyIntegritySidecar(sidecar)
	if err != nil {
		t.Fatalf("MarshalPolicyIntegritySidecar() error = %v", err)
	}
	if err := os.WriteFile(PolicyIntegritySidecarPath(path), sidecarBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(sidecar) error = %v", err)
	}

	_, err = LoadVerifiedStoredConfig(root, "alice", key)
	if err == nil {
		t.Fatal("LoadVerifiedStoredConfig() error = nil, want parse failure")
	}
	if errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want parse failure not mismatch", err)
	}
}

func TestSignPolicyFileIntegrityUnreadablePolicyWrapsIntegrityError(t *testing.T) {
	root := t.TempDir()
	path := PolicyPath(root, "alice")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll(policy path) error = %v", err)
	}

	err := SignPolicyFileIntegrity(root, "alice", policyIntegrityTestKey(t), time.Time{})
	if !errors.Is(err, ErrPolicyIntegrity) || !errors.Is(err, ErrPolicyIntegrityUnreadable) {
		t.Fatalf("SignPolicyFileIntegrity() error = %v, want integrity unreadable error", err)
	}
}

func TestLoadVerifiedStoredConfigRejectsWrongKey(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	if err := SaveStoredConfigWithIntegrity(root, "alice", &StoredConfig{}, key, time.Time{}); err != nil {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v", err)
	}
	wrongKey, err := apcrypto.DerivePolicyIntegrityKey([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if err != nil {
		t.Fatalf("DerivePolicyIntegrityKey(wrong) error = %v", err)
	}
	defer apcrypto.ZeroBytes(wrongKey)

	_, err = LoadVerifiedStoredConfig(root, "alice", wrongKey)
	if !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}
