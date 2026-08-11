// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig"
)

type fakeOnlinePolicyAuthenticator struct {
	status      string
	authErr     error
	statusErr   error
	unlock      protocol.UnlockResultMessage
	unlockErr   error
	authCalls   int
	statusCalls int
	unlockCalls int
	passphrase  string
}

func (f *fakeOnlinePolicyAuthenticator) Authenticate(passphrase string, _ time.Duration) error {
	f.authCalls++
	f.passphrase = passphrase
	return f.authErr
}

func (f *fakeOnlinePolicyAuthenticator) WaitForStatus(time.Duration) (*protocol.StatusMessage, error) {
	f.statusCalls++
	return &protocol.StatusMessage{State: f.status}, f.statusErr
}

func (f *fakeOnlinePolicyAuthenticator) Unlock(passphrase string, _ time.Duration) (*protocol.UnlockResultMessage, error) {
	f.unlockCalls++
	f.passphrase = passphrase
	return &f.unlock, f.unlockErr
}

func TestAuthenticateAndUnlockOnlinePolicyUnlocksLockedSigner(t *testing.T) {
	conn := &fakeOnlinePolicyAuthenticator{status: "locked", unlock: protocol.UnlockResultMessage{Success: true}}
	if err := authenticateAndUnlockOnlinePolicy(conn, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if conn.authCalls != 1 || conn.statusCalls != 1 || conn.unlockCalls != 1 || conn.passphrase != "secret" {
		t.Fatalf("calls auth/status/unlock = %d/%d/%d, passphrase %q", conn.authCalls, conn.statusCalls, conn.unlockCalls, conn.passphrase)
	}
}

func TestAuthenticateAndUnlockOnlinePolicyDoesNotUnlockRecoverySigner(t *testing.T) {
	conn := &fakeOnlinePolicyAuthenticator{status: "recovery"}
	if err := authenticateAndUnlockOnlinePolicy(conn, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if conn.unlockCalls != 0 {
		t.Fatalf("Unlock() calls = %d, want 0", conn.unlockCalls)
	}
}

func TestAuthenticateAndUnlockOnlinePolicyReportsUnlockFailure(t *testing.T) {
	conn := &fakeOnlinePolicyAuthenticator{status: "locked", unlock: protocol.UnlockResultMessage{Error: "policy integrity failed"}}
	err := authenticateAndUnlockOnlinePolicy(conn, []byte("secret"))
	if err == nil || !strings.Contains(err.Error(), "policy integrity failed") {
		t.Fatalf("authenticateAndUnlockOnlinePolicy() error = %v", err)
	}
}

type failingPolicyReader struct{ err error }

func (r failingPolicyReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadOnlinePolicyYAMLReportsReadFailure(t *testing.T) {
	want := errors.New("input device failed")
	_, err := readOnlinePolicyYAML(failingPolicyReader{err: want})
	if !errors.Is(err, want) {
		t.Fatalf("readOnlinePolicyYAML() error = %v, want wrapped input failure", err)
	}
}

func TestReadPolicyYAMLFileRejectsWhitespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-policy.yaml")
	if err := os.WriteFile(path, []byte(" \n\t"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readPolicyYAMLFile(path)
	if err == nil || !strings.Contains(err.Error(), "policy YAML file is empty") {
		t.Fatalf("readPolicyYAMLFile() error = %v, want empty-file rejection", err)
	}
}

type fakeOnlinePolicyClient struct {
	snapshotCalls int
}

func (f *fakeOnlinePolicyClient) GetPolicySnapshot(context.Context, policyeditor.Target) (policyeditor.AdminPolicySnapshot, error) {
	f.snapshotCalls++
	return policyeditor.AdminPolicySnapshot{
		Success:      true,
		Target:       policyeditor.TargetSigner,
		IdentityID:   policyeditor.DefaultIdentityID,
		PolicyYAML:   "reject_foreign_rekey: false\n",
		PolicySHA256: "active-sha",
	}, nil
}

func (f *fakeOnlinePolicyClient) ValidatePolicy(context.Context, policyeditor.Target, string) (policyeditor.AdminPolicyValidation, error) {
	return policyeditor.AdminPolicyValidation{Success: true, Target: policyeditor.TargetSigner}, nil
}

func (f *fakeOnlinePolicyClient) ReplacePolicy(context.Context, policyeditor.Target, string, string) (policyeditor.AdminPolicySnapshot, error) {
	return policyeditor.AdminPolicySnapshot{}, errors.New("unexpected replacement")
}

func TestEditOnlinePolicyFileReportsValidationBeforeTUI(t *testing.T) {
	client := &fakeOnlinePolicyClient{}
	store := &policyeditor.AdminStore{Client: client, Target: policyeditor.TargetSigner}
	draft, err := policy.ParseStoredConfig([]byte("reject_foreign_rekey: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	originalLauncher := launchPolicyEditor
	t.Cleanup(func() { launchPolicyEditor = originalLauncher })
	launched := false
	var stdout bytes.Buffer
	launchPolicyEditor = func(gotStore policyeditor.Store, gotDraft *policy.StoredConfig, _, _ string, target policyeditor.Target) error {
		launched = true
		if got := stdout.String(); got != "policy OK: draft.yaml\n" {
			t.Fatalf("stdout when TUI launched = %q, want validation status", got)
		}
		if gotStore != store || gotDraft != draft || target != policyeditor.TargetSigner {
			t.Fatalf("launcher args store=%T draft=%p target=%q", gotStore, gotDraft, target)
		}
		if store.LastSHA256() != "active-sha" {
			t.Fatalf("LastSHA256() = %q, want active snapshot seeded before TUI", store.LastSHA256())
		}
		return nil
	}

	if err := editOnlinePolicyFile(context.Background(), store, draft, policyeditor.TargetSigner, "draft.yaml", &stdout); err != nil {
		t.Fatalf("editOnlinePolicyFile() error = %v", err)
	}
	if client.snapshotCalls != 1 || !launched {
		t.Fatalf("snapshot calls/launched = %d/%t, want 1/true", client.snapshotCalls, launched)
	}
}

func TestRunYAMLPrintsVerifiedPolicyOnly(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--yaml) code = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "policy OK") {
		t.Fatalf("--yaml stdout included status text:\n%s", stdout.String())
	}
	if _, err := policy.ParseStoredConfig(stdout.Bytes()); err != nil {
		t.Fatalf("--yaml stdout is not valid policy YAML: %v\n%s", err, stdout.String())
	}
}

func TestRunSHA256PrintsVerifiedPolicyDigestOnly(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	policyBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}

	code := run(context.Background(), []string{"-d", dataDir, "--sha256"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--sha256) code = %d, stderr = %q", code, stderr.String())
	}
	want := policy.PolicySHA256(policyBytes) + "\n"
	if stdout.String() != want {
		t.Fatalf("--sha256 stdout = %q, want %q", stdout.String(), want)
	}
}

func TestRunSaveReadsPolicyFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	policyBytes := []byte("# saved through appolicy\nreject_foreign_rekey: false\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(policyBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy saved:") {
		t.Fatalf("--save stdout = %q, want saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(policyBytes) {
		t.Fatalf("--save changed policy bytes:\ngot:\n%s\nwant:\n%s", gotBytes, policyBytes)
	}
}

func TestRunTargetSentrySaveReadsSentryFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleSentry)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	sentryBytes := []byte(`# saved through appolicy
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
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--target", "sentry", "--save"}, bytes.NewReader(sentryBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--target sentry --save) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "sentry policy saved:") {
		t.Fatalf("--target sentry --save stdout = %q, want saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(sentryBytes) {
		t.Fatalf("--target sentry --save changed sentry bytes:\ngot:\n%s\nwant:\n%s", gotBytes, sentryBytes)
	}
	if _, err := policy.ParseStoredSentryConfig(gotBytes); err != nil {
		t.Fatalf("saved sentry YAML does not parse: %v", err)
	}
}

func TestRunCheckCanReadPassphraseFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--check"}, strings.NewReader(passphrase+"\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--check) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy OK:") {
		t.Fatalf("--check stdout = %q, want policy OK", stdout.String())
	}
}

func TestRunCheckPolicyFileDoesNotRequireStorePassphrase(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: false\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--check", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--check file) code = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "passphrase") {
		t.Fatalf("--check file unexpectedly asked for passphrase: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy OK: "+path) {
		t.Fatalf("--check file stdout = %q, want policy OK for file", stdout.String())
	}
}

func TestRunCheckPolicyFileRejectsSentryBlock(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("sentry: {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--check", path}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run(--check invalid sentry) code = 0, stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "signer policy sentry is not supported") {
		t.Fatalf("stderr = %q, want sentry block rejection", stderr.String())
	}
}

func TestRunToSentryPolicyFilePrintsDirectSentryYAML(t *testing.T) {
	t.Setenv("APPOLICY_PASSPHRASE", "")
	t.Setenv("APSIGNER_PASSPHRASE", "")
	t.Setenv("APSIGNER_DATA", "")
	path := filepath.Join(t.TempDir(), "policy.yaml")
	raw := `
transfer_policy:
  schema_version: 1
  enabled: true
  on_no_route: reject
  routes:
    - id: route
      networks: [testnet]
      sources: ["*"]
      assets: [algo]
      destinations: ["*"]
      limits:
        review_above: 10
        reject_above: 20
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile(policy) error = %v", err)
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--to-sentry", path}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--to-sentry file) code = %d, stderr = %q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "policy OK") || strings.Contains(stdout.String(), "sentry:") || strings.Contains(stdout.String(), "review_above") {
		t.Fatalf("--to-sentry stdout contains status, wrapper, or review threshold:\n%s", stdout.String())
	}
	if _, err := policy.ParseStoredSentryConfig(stdout.Bytes()); err != nil {
		t.Fatalf("--to-sentry stdout is not valid sentry YAML: %v\n%s", err, stdout.String())
	}
	if !strings.Contains(stdout.String(), "reject_above: 20") {
		t.Fatalf("--to-sentry stdout missing reject_above:\n%s", stdout.String())
	}
}

func TestRunSavePolicyAliasReadsPolicyFromStdin(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	policyBytes := []byte("reject_foreign_rekey: false\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(policyBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save alias) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "policy saved:") {
		t.Fatalf("--save alias stdout = %q, want policy saved status", stdout.String())
	}
}

func TestRunSaveAutoTargetsSentryOnSentryNode(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleSentry)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	sentryBytes := []byte("reject_rekey: true\n")
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(sentryBytes), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(sentry --save) code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "sentry policy saved:") {
		t.Fatalf("sentry --save stdout = %q, want sentry saved status", stdout.String())
	}
	gotBytes, err := os.ReadFile(policy.PolicyPath(dataDir, policyeditor.DefaultIdentityID))
	if err != nil {
		t.Fatalf("ReadFile(policy) error = %v", err)
	}
	if string(gotBytes) != string(sentryBytes) {
		t.Fatalf("sentry bytes changed during auto --save:\ngot:\n%s\nwant:\n%s", gotBytes, sentryBytes)
	}
}

func TestRunYAMLAutoTargetsSentryOnSentryNode(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleSentry)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	sentryBytes := []byte("reject_rekey: true\n")
	var saveOut, saveErr bytes.Buffer
	if code := run(context.Background(), []string{"-d", dataDir, "--save"}, bytes.NewReader(sentryBytes), &saveOut, &saveErr); code != 0 {
		t.Fatalf("run(sentry --save) code = %d, stderr = %q", code, saveErr.String())
	}
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(sentry --yaml) code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != string(sentryBytes) {
		t.Fatalf("sentry --yaml stdout:\ngot:\n%s\nwant:\n%s", stdout.String(), sentryBytes)
	}
	if _, err := policy.ParseStoredSentryConfig(stdout.Bytes()); err != nil {
		t.Fatalf("sentry --yaml stdout is not valid sentry YAML: %v\n%s", err, stdout.String())
	}
}

func TestRunTargetOverrideRejectsSignerPolicyOnSentryNode(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStoreWithRole(t, noderole.RoleSentry)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--target", "signer", "--yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run(--target signer --yaml) code = 0, stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), `policy target "signer" is not allowed on sentry nodes`) {
		t.Fatalf("run(--target signer --yaml) stderr = %q, want role-target rejection", stderr.String())
	}
}

func TestRunSaveRejectsPolicyFileArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"--save", "policy.yaml"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(--save file) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "does not accept a file argument") {
		t.Fatalf("stderr = %q, want file argument rejection", stderr.String())
	}
}

func TestRunRejectsCombinedCLIModes(t *testing.T) {
	dataDir, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	var stdout, stderr bytes.Buffer

	code := run(context.Background(), []string{"-d", dataDir, "--yaml", "--to-sentry"}, strings.NewReader(""), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run(combined modes) code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "choose only one") {
		t.Fatalf("stderr = %q, want mode conflict", stderr.String())
	}
}

func TestOfflinePolicyMutationUsesManagedPrincipal(t *testing.T) {
	oldEUID := appolicyEUID
	oldManaged := isManagedPolicyStore
	oldOwner := managedPolicyOwner
	oldLoad := loadPolicyConfig
	oldResolve := resolvePolicySocket
	oldMigrate := migrateOfflinePolicyStore
	oldAcquire := acquirePolicyStoreLock
	t.Cleanup(func() {
		appolicyEUID = oldEUID
		isManagedPolicyStore = oldManaged
		managedPolicyOwner = oldOwner
		loadPolicyConfig = oldLoad
		resolvePolicySocket = oldResolve
		migrateOfflinePolicyStore = oldMigrate
		acquirePolicyStoreLock = oldAcquire
	})

	appolicyEUID = func() int { return 0 }
	isManagedPolicyStore = func(string) (bool, error) { return true, nil }
	managedPolicyOwner = func(string) (int, int, error) { return 123, 456, nil }
	loadPolicyConfig = func(string) (serverconfig.ServerConfig, error) {
		return serverconfig.ServerConfig{IPCPath: "run/custom.sock"}, nil
	}
	resolvePolicySocket = func(root, configured string) (string, error) {
		if root != "/srv/apsigner" || configured != "run/custom.sock" {
			t.Fatalf("resolvePolicySocket(%q, %q)", root, configured)
		}
		return "/srv/apsigner/run/custom.sock", nil
	}
	lockCalls := 0
	acquirePolicyStoreLock = func(root string) (*storelock.Guard, error) {
		lockCalls++
		if root != "/srv/apsigner" {
			t.Fatalf("acquirePolicyStoreLock(%q)", root)
		}
		return &storelock.Guard{}, nil
	}
	migrateOfflinePolicyStore = func(root string, uid, gid int, socketPath string) error {
		if root != "/srv/apsigner" || uid != 123 || gid != 456 || socketPath != "/srv/apsigner/run/custom.sock" {
			t.Fatalf("migration args = %q %d:%d %q", root, uid, gid, socketPath)
		}
		return nil
	}

	guard, err := acquireOfflinePolicyMutation("/srv/apsigner")
	if err != nil {
		t.Fatalf("acquireOfflinePolicyMutation() error = %v", err)
	}
	defer guard.Close()
	if err := guard.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if lockCalls != 1 {
		t.Fatalf("exclusive lock calls = %d, want 1", lockCalls)
	}
}

func TestOfflinePolicyMutationRefusesConcurrentDaemonBeforeNormalization(t *testing.T) {
	root := t.TempDir()
	shared, err := storelock.AcquireShared(root)
	if err != nil {
		t.Fatalf("AcquireShared() error = %v", err)
	}
	defer func() { _ = shared.Close() }()

	oldEUID := appolicyEUID
	oldManaged := isManagedPolicyStore
	oldMigrate := migrateOfflinePolicyStore
	t.Cleanup(func() {
		appolicyEUID = oldEUID
		isManagedPolicyStore = oldManaged
		migrateOfflinePolicyStore = oldMigrate
	})
	appolicyEUID = func() int { return 0 }
	isManagedPolicyStore = func(string) (bool, error) { return true, nil }
	migrateOfflinePolicyStore = func(string, int, int, string) error {
		t.Fatal("migration ran while the daemon held the store lock")
		return nil
	}

	_, err = acquireOfflinePolicyMutation(root)
	if !errors.Is(err, storelock.ErrBusy) {
		t.Fatalf("acquireOfflinePolicyMutation() error = %v, want storelock.ErrBusy", err)
	}
	if !strings.Contains(err.Error(), "stop apsigner") {
		t.Fatalf("acquireOfflinePolicyMutation() error = %q, want operator guidance", err)
	}
}

func TestRunSaveRefusesBusyManagedStoreBeforeWrite(t *testing.T) {
	root, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)
	policyPath := policy.PolicyPath(root, policyeditor.DefaultIdentityID)
	before, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}

	oldEUID := appolicyEUID
	oldManaged := isManagedPolicyStore
	oldAcquire := acquirePolicyStoreLock
	t.Cleanup(func() {
		appolicyEUID = oldEUID
		isManagedPolicyStore = oldManaged
		acquirePolicyStoreLock = oldAcquire
	})
	appolicyEUID = func() int { return 0 }
	isManagedPolicyStore = func(string) (bool, error) { return true, nil }
	acquirePolicyStoreLock = func(string) (*storelock.Guard, error) { return nil, storelock.ErrBusy }

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-d", root, "--save"},
		strings.NewReader("reject_foreign_rekey: false\n"), &stdout, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), "before editing") {
		t.Fatalf("run(--save busy) code=%d stderr=%q", code, stderr.String())
	}
	after, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("policy changed before the exclusive store lock was acquired")
	}
}

func TestRunSaveManagedStoreReusesOneRealExclusiveLock(t *testing.T) {
	root, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)

	oldEUID := appolicyEUID
	oldManaged := isManagedPolicyStore
	oldOwner := managedPolicyOwner
	oldMigrate := migrateOfflinePolicyStore
	t.Cleanup(func() {
		appolicyEUID = oldEUID
		isManagedPolicyStore = oldManaged
		managedPolicyOwner = oldOwner
		migrateOfflinePolicyStore = oldMigrate
	})
	appolicyEUID = func() int { return 0 }
	isManagedPolicyStore = func(string) (bool, error) { return true, nil }
	managedPolicyOwner = func(string) (int, int, error) { return os.Geteuid(), os.Getegid(), nil }
	normalized := false
	migrateOfflinePolicyStore = func(dataDir string, _, _ int, _ string) error {
		competing, err := storelock.AcquireExclusive(dataDir)
		if competing != nil {
			_ = competing.Close()
		}
		if !errors.Is(err, storelock.ErrBusy) {
			t.Fatalf("normalization competing lock error = %v, want outer lock still held", err)
		}
		normalized = true
		return nil
	}

	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"-d", root, "--save"},
		strings.NewReader("reject_foreign_rekey: false\n"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--save managed) code=%d stderr=%q", code, stderr.String())
	}
	if !normalized {
		t.Fatal("managed store normalization did not run")
	}
	guard, err := storelock.AcquireExclusive(root)
	if err != nil {
		t.Fatalf("outer lock remains held after run: %v", err)
	}
	_ = guard.Close()
}

func TestRunCheckDoesNotAcquireManagedMutationLock(t *testing.T) {
	root, passphrase := initializedAppolicyStore(t)
	t.Setenv("APPOLICY_PASSPHRASE", passphrase)

	oldEUID := appolicyEUID
	oldManaged := isManagedPolicyStore
	oldAcquire := acquirePolicyStoreLock
	t.Cleanup(func() {
		appolicyEUID = oldEUID
		isManagedPolicyStore = oldManaged
		acquirePolicyStoreLock = oldAcquire
	})
	appolicyEUID = func() int { return 0 }
	isManagedPolicyStore = func(string) (bool, error) { return true, nil }
	acquirePolicyStoreLock = func(string) (*storelock.Guard, error) {
		t.Fatal("read-only policy check acquired the mutation lock")
		return nil, nil
	}

	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"-d", root, "--check"},
		strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("run(--check) code=%d stderr=%q", code, stderr.String())
	}
}

func TestDecodeOnlinePolicyTargetRejectsErrorFrame(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError, ID: "settings"},
		Code:        protocol.ErrCodeAuthorizationDenied,
		Error:       "authorization denied",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeOnlinePolicyTarget(raw)
	if err == nil || !strings.Contains(err.Error(), "authorization denied") {
		t.Fatalf("decodeOnlinePolicyTarget(error) = %v, want server error", err)
	}
}

func TestDecodeOnlinePolicyTargetUsesReportedRole(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.AdminSettingsMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAdminSettings, ID: "settings"},
		NodeRole:    "sentry",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeOnlinePolicyTarget(raw)
	if err != nil || got != policyeditor.TargetSentry {
		t.Fatalf("decodeOnlinePolicyTarget(sentry) = %q, %v", got, err)
	}
}

func initializedAppolicyStore(t *testing.T) (string, string) {
	t.Helper()
	return initializedAppolicyStoreWithRole(t, noderole.RoleSigner)
}

func initializedAppolicyStoreWithRole(t *testing.T, role noderole.Role) (string, string) {
	t.Helper()
	lsig.RegisterClient()

	dataDir := t.TempDir()
	passphrase := "appolicy-test-passphrase"
	_, err := storeinit.Initialize([]byte(passphrase), storeinit.Options{
		DataDir:    dataDir,
		Paths:      storepaths.NewPaths(dataDir),
		IdentityID: policyeditor.DefaultIdentityID,
		Role:       role,
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return dataDir, passphrase
}
