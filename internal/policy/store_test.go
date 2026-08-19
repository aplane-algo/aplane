// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/fsutil"
)

func TestSaveAndLoadVerifiedStoredConfig(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	wantReject := false
	wantFee := uint64(7000)
	want := &StoredConfig{StoredPolicyCore: StoredPolicyCore{RejectForeignRekey: &wantReject, MaxFeeMicroAlgos: &wantFee}}

	if err := SaveStoredConfigWithIntegrity(root, want, key, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v", err)
	}
	if _, err := os.Stat(PolicyIntegritySidecarPath(PolicyPath(root))); err != nil {
		t.Fatalf("sidecar stat error = %v", err)
	}

	got, err := LoadVerifiedStoredConfig(root, key)
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

func TestSaveAndLoadVerifiedStoredConfigWithKeyring(t *testing.T) {
	root := t.TempDir()
	// A real term key length: the keyring requires 32 bytes where the
	// bare HKDF helper accepted anything non-empty.
	masterKey := bytes.Repeat([]byte{0x7B}, 32)
	wantReject := false
	want := &StoredConfig{StoredPolicyCore: StoredPolicyCore{RejectForeignRekey: &wantReject}}

	if err := SaveStoredConfigWithKeyring(root, want, cryptotest.Keyring(t, masterKey), time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredConfigWithKeyring() error = %v", err)
	}
	got, err := LoadVerifiedStoredConfigWithKeyring(root, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("LoadVerifiedStoredConfigWithKeyring() error = %v", err)
	}
	if got.RejectForeignRekey == nil || *got.RejectForeignRekey != wantReject {
		t.Fatalf("RejectForeignRekey = %#v, want %v", got.RejectForeignRekey, wantReject)
	}
}

func TestSavePolicyPreparationFailureLeavesExistingPairUntouched(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	oldConfig := &StoredConfig{}
	if err := SaveStoredConfigWithIntegrity(root, oldConfig, key, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	policyPath := PolicyPath(root)
	sidecarPath := PolicyIntegritySidecarPath(policyPath)
	oldPolicy, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	oldSidecar, err := os.ReadFile(sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected sidecar sync")
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpFileSync && path == sidecarPath {
			return injected
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	reject := false
	err = SaveStoredConfigWithIntegrity(root, &StoredConfig{
		StoredPolicyCore: StoredPolicyCore{RejectForeignRekey: &reject},
	}, key, time.Unix(1800000000, 0))
	if !errors.Is(err, injected) {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v, want %v", err, injected)
	}
	for path, want := range map[string][]byte{policyPath: oldPolicy, sidecarPath: oldSidecar} {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s changed after preparation failure", path)
		}
	}
}

func TestSaveAndLoadVerifiedSentryConfigWithKeyring(t *testing.T) {
	root := t.TempDir()
	// A real term key length: the keyring requires 32 bytes where the
	// bare HKDF helper accepted anything non-empty.
	masterKey := bytes.Repeat([]byte{0x7B}, 32)
	rejectRekey := true
	want := &StoredConfig{StoredPolicyCore: StoredPolicyCore{RejectRekey: &rejectRekey}}

	if err := SaveStoredSentryConfigWithKeyring(root, want, cryptotest.Keyring(t, masterKey), time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SaveStoredSentryConfigWithKeyring() error = %v", err)
	}
	got, err := LoadVerifiedSentryConfigWithKeyring(root, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("LoadVerifiedSentryConfigWithKeyring() error = %v", err)
	}
	if got.RejectRekey == nil || !*got.RejectRekey {
		t.Fatalf("RejectRekey = %#v, want true", got.RejectRekey)
	}
}

func TestSignPolicyFileIntegrityPreservesPolicyBytes(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	path := PolicyPath(root)
	policyBytes := []byte("# direct edit\nreject_foreign_rekey: false\n")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(path, policyBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}

	if err := SignPolicyFileIntegrity(root, key, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("SignPolicyFileIntegrity() error = %v", err)
	}
	gotBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(policyBytes) {
		t.Fatalf("policy bytes changed during signing:\ngot  %q\nwant %q", string(gotBytes), string(policyBytes))
	}
	got, err := LoadVerifiedStoredConfig(root, key)
	if err != nil {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v", err)
	}
	if got.RejectForeignRekey == nil || *got.RejectForeignRekey {
		t.Fatalf("RejectForeignRekey = %#v, want false", got.RejectForeignRekey)
	}
}

func TestSignPolicyFileIntegrityRejectsMalformedPolicy(t *testing.T) {
	root := t.TempDir()
	path := PolicyPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: [\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}

	err := SignPolicyFileIntegrity(root, policyIntegrityTestKey(t), time.Time{})
	if err == nil || !strings.Contains(err.Error(), "failed to parse policy config") {
		t.Fatalf("SignPolicyFileIntegrity() error = %v, want parse failure", err)
	}
	if errors.Is(err, ErrPolicyIntegrity) {
		t.Fatalf("SignPolicyFileIntegrity() error = %v, want parse failure not integrity sentinel", err)
	}
}

func TestLoadVerifiedStoredConfigMissingPolicy(t *testing.T) {
	_, err := LoadVerifiedStoredConfig(t.TempDir(), policyIntegrityTestKey(t))
	if !errors.Is(err, ErrPolicyIntegrityMissingFile) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMissingFile", err)
	}
}

func TestLoadVerifiedStoredConfigUnreadablePolicyWrapsIntegrityError(t *testing.T) {
	root := t.TempDir()
	path := PolicyPath(root)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll(policy path) error = %v", err)
	}

	_, err := LoadVerifiedStoredConfig(root, policyIntegrityTestKey(t))
	if !errors.Is(err, ErrPolicyIntegrity) || !errors.Is(err, ErrPolicyIntegrityUnreadable) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want integrity unreadable error", err)
	}
}

func TestLoadVerifiedStoredConfigMissingSidecar(t *testing.T) {
	root := t.TempDir()
	if err := SaveStoredConfig(root, &StoredConfig{}); err != nil {
		t.Fatalf("SaveStoredConfig() error = %v", err)
	}
	_, err := LoadVerifiedStoredConfig(root, policyIntegrityTestKey(t))
	if !errors.Is(err, ErrPolicyIntegrityMissingSidecar) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMissingSidecar", err)
	}
}

func TestLoadVerifiedStoredConfigRejectsTamperedPolicy(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	if err := SaveStoredConfigWithIntegrity(root, &StoredConfig{}, key, time.Time{}); err != nil {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v", err)
	}
	if err := os.WriteFile(PolicyPath(root), []byte("reject_foreign_rekey: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := LoadVerifiedStoredConfig(root, key)
	if !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}

func TestLoadVerifiedStoredConfigRejectsMalformedSignedPolicy(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	policyBytes := []byte("reject_foreign_rekey: [\n")
	path := PolicyPath(root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(identity) error = %v", err)
	}
	if err := os.WriteFile(path, policyBytes, 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	sidecar, err := SignPolicyIntegrity(policyBytes, key, time.Time{})
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

	_, err = LoadVerifiedStoredConfig(root, key)
	if err == nil {
		t.Fatal("LoadVerifiedStoredConfig() error = nil, want parse failure")
	}
	if errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want parse failure not mismatch", err)
	}
}

func TestSignPolicyFileIntegrityUnreadablePolicyWrapsIntegrityError(t *testing.T) {
	root := t.TempDir()
	path := PolicyPath(root)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll(policy path) error = %v", err)
	}

	err := SignPolicyFileIntegrity(root, policyIntegrityTestKey(t), time.Time{})
	if !errors.Is(err, ErrPolicyIntegrity) || !errors.Is(err, ErrPolicyIntegrityUnreadable) {
		t.Fatalf("SignPolicyFileIntegrity() error = %v, want integrity unreadable error", err)
	}
}

func TestLoadVerifiedStoredConfigRejectsWrongKey(t *testing.T) {
	root := t.TempDir()
	key := policyIntegrityTestKey(t)
	if err := SaveStoredConfigWithIntegrity(root, &StoredConfig{}, key, time.Time{}); err != nil {
		t.Fatalf("SaveStoredConfigWithIntegrity() error = %v", err)
	}
	wrongKeyring := cryptotest.Keyring(t, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	_, err := LoadVerifiedStoredConfig(root, wrongKeyring)
	if !errors.Is(err, ErrPolicyIntegrityMismatch) {
		t.Fatalf("LoadVerifiedStoredConfig() error = %v, want ErrPolicyIntegrityMismatch", err)
	}
}
