// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestOfflineStoreLoadVerifiesPolicy(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)

	stored, err := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
	}.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if stored == nil {
		t.Fatal("Load() returned nil policy")
	}
}

func TestOfflineStoreLoadVerifiesAttestationTarget(t *testing.T) {
	dataDir, passphrase := initializedPolicyStoreWithRole(t, noderole.RoleAttestor)
	store := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Target:     TargetAttestation,
		Passphrase: passphrase,
	}
	attestationBytes := []byte("reject_rekey: true\n")
	if err := store.SaveYAML(context.Background(), attestationBytes); err != nil {
		t.Fatalf("SaveYAML(attestation target) error = %v", err)
	}

	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(attestation target) error = %v", err)
	}
	if stored.RejectRekey == nil || !*stored.RejectRekey {
		t.Fatalf("RejectRekey = %v, want true", stored.RejectRekey)
	}
}

func TestResolveTargetUsesNodeRole(t *testing.T) {
	signerDir, _ := initializedPolicyStoreWithRole(t, noderole.RoleSigner)
	attestorDir, _ := initializedPolicyStoreWithRole(t, noderole.RoleAttestor)

	if got, err := ResolveTarget(signerDir, TargetAuto); err != nil || got != TargetSigner {
		t.Fatalf("ResolveTarget(signer) = %q, %v; want %q", got, err, TargetSigner)
	}
	if got, err := ResolveTarget(attestorDir, TargetAuto); err != nil || got != TargetAttestation {
		t.Fatalf("ResolveTarget(attestor) = %q, %v; want %q", got, err, TargetAttestation)
	}
}

func TestOfflineStoreLoadRejectsTamperedPolicy(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	path := policy.PolicyPath(dataDir, DefaultIdentityID)
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	_, err := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
	}.Load(context.Background())
	if err == nil {
		t.Fatal("Load() error = nil, want integrity failure")
	}
}

func TestOfflineStoreSaveWritesVerifiedPolicy(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	maxFee := uint64(1234)
	when := time.Unix(1700000000, 0)
	store := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
		Now:        func() time.Time { return when },
	}

	if err := store.Save(context.Background(), &policy.StoredConfig{
		MaxFeeMicroAlgos: &maxFee,
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() after Save() error = %v", err)
	}
	if stored.MaxFeeMicroAlgos == nil || *stored.MaxFeeMicroAlgos != maxFee {
		t.Fatalf("MaxFeeMicroAlgos = %v, want %d", stored.MaxFeeMicroAlgos, maxFee)
	}
}

func TestOfflineStoreValidateDoesNotUsePassphraseProvider(t *testing.T) {
	calls := 0
	store := OfflineStore{
		IdentityID: DefaultIdentityID,
		PassphraseProvider: func(context.Context) ([]byte, error) {
			calls++
			return []byte("unused"), nil
		},
	}

	if err := store.Validate(context.Background(), &policy.StoredConfig{}); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("passphrase provider calls = %d, want 0", calls)
	}
}

func TestOfflineStoreSaveUsesPassphraseProvider(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	maxFee := uint64(1234)
	calls := 0
	store := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		PassphraseProvider: func(context.Context) ([]byte, error) {
			calls++
			return append([]byte(nil), passphrase...), nil
		},
	}

	if err := store.Save(context.Background(), &policy.StoredConfig{
		MaxFeeMicroAlgos: &maxFee,
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("passphrase provider calls = %d, want 1", calls)
	}
}

func TestOfflineStoreSaveYAMLPreservesPolicyBytes(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	policyBytes := []byte("# replacement policy\nreject_foreign_rekey: false\n")
	store := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
	}

	if err := store.SaveYAML(context.Background(), policyBytes); err != nil {
		t.Fatalf("SaveYAML() error = %v", err)
	}
	gotBytes, err := os.ReadFile(policy.PolicyPath(dataDir, DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(policyBytes) {
		t.Fatalf("policy bytes changed during SaveYAML:\ngot:\n%s\nwant:\n%s", gotBytes, policyBytes)
	}
	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() after SaveYAML() error = %v", err)
	}
	if stored.RejectForeignRekey == nil || *stored.RejectForeignRekey {
		t.Fatalf("RejectForeignRekey = %v, want false", stored.RejectForeignRekey)
	}
}

func TestOfflineStoreSaveAttestationYAMLPreservesPolicyBytes(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	attestationBytes := []byte(`# replacement attestation
reject_rekey: true
transfer_policy:
  schema_version: 1
  enabled: true
  routes:
    - id: allow_algo
      networks: [testnet]
      sources: ["*"]
      assets: [algo]
      destinations: ["*"]
`)
	store := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
	}

	if err := store.SaveAttestationYAML(context.Background(), attestationBytes); err != nil {
		t.Fatalf("SaveAttestationYAML() error = %v", err)
	}
	gotBytes, err := os.ReadFile(policy.AttestationPath(dataDir, DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(attestation) error = %v", err)
	}
	if string(gotBytes) != string(attestationBytes) {
		t.Fatalf("attestation bytes changed during SaveAttestationYAML:\ngot:\n%s\nwant:\n%s", gotBytes, attestationBytes)
	}
	masterKey, clear, err := store.unlock(context.Background())
	if err != nil {
		t.Fatalf("unlock() error = %v", err)
	}
	defer clear()
	stored, err := policy.LoadVerifiedAttestationConfigWithMasterKey(dataDir, DefaultIdentityID, masterKey)
	if err != nil {
		t.Fatalf("LoadVerifiedAttestationConfigWithMasterKey() after SaveAttestationYAML() error = %v", err)
	}
	if stored.RejectRekey == nil || !*stored.RejectRekey {
		t.Fatalf("RejectRekey = %v, want true", stored.RejectRekey)
	}
}

func TestOfflineStoreSaveRejectsInvalidPolicyWithoutWriting(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	path := policy.PolicyPath(dataDir, DefaultIdentityID)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	enabled := true
	store := OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
	}

	err = store.Save(context.Background(), &policy.StoredConfig{
		TransferPolicy: &policy.StoredTransferPolicy{
			SchemaVersion: 1,
			Enabled:       &enabled,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "on_no_route is required") {
		t.Fatalf("Save() error = %v, want on_no_route validation failure", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() after Save() error = %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("policy.yaml changed after rejected Save()\nbefore:\n%s\nafter:\n%s", before, after)
	}
}

func TestOfflineStoreSaveLockedStoreErrorHasOperatorHint(t *testing.T) {
	dataDir, passphrase := initializedPolicyStore(t)
	guard, err := storelock.AcquireShared(dataDir)
	if err != nil {
		t.Fatalf("AcquireShared() error = %v", err)
	}
	defer func() { _ = guard.Close() }()

	err = OfflineStore{
		DataDir:    dataDir,
		IdentityID: DefaultIdentityID,
		Passphrase: passphrase,
	}.Save(context.Background(), &policy.StoredConfig{})
	if err == nil {
		t.Fatal("Save() error = nil, want locked-store error")
	}
	msg := err.Error()
	for _, want := range []string{
		"store is locked by another process",
		"stop apsigner",
		"before editing policy offline",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("Save() error = %q, want substring %q", msg, want)
		}
	}
}

func initializedPolicyStore(t *testing.T) (string, []byte) {
	t.Helper()
	return initializedPolicyStoreWithRole(t, noderole.RoleSigner)
}

func initializedPolicyStoreWithRole(t *testing.T, role noderole.Role) (string, []byte) {
	t.Helper()
	dataDir := t.TempDir()
	passphrase := []byte("policyeditor-passphrase")
	_, err := storeinit.Initialize(passphrase, storeinit.Options{
		DataDir:    dataDir,
		Paths:      storepaths.NewPaths(dataDir),
		IdentityID: DefaultIdentityID,
		Role:       role,
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return dataDir, passphrase
}
