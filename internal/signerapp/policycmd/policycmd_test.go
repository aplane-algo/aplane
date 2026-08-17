// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
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

type fakeOnlineSession struct {
	status           string
	dialCalls        int
	closeCalls       int
	authPassphrase   string
	unlockPassphrase string
	replaceRequest   protocol.ReplacePolicyMessage
	nodeRole         string
	snapshotTarget   string
	authErr          error
	unlockResult     *protocol.UnlockResultMessage
	replaceCalls     int
}

func (f *fakeOnlineSession) Dial() error { f.dialCalls++; return nil }
func (f *fakeOnlineSession) Close()      { f.closeCalls++ }
func (f *fakeOnlineSession) Authenticate(passphrase string, _ time.Duration) error {
	f.authPassphrase = passphrase
	return f.authErr
}
func (f *fakeOnlineSession) WaitForStatus(time.Duration) (*protocol.StatusMessage, error) {
	return &protocol.StatusMessage{State: f.status}, nil
}
func (f *fakeOnlineSession) Unlock(passphrase string, _ time.Duration) (*protocol.UnlockResultMessage, error) {
	f.unlockPassphrase = passphrase
	if f.unlockResult != nil {
		return f.unlockResult, nil
	}
	return &protocol.UnlockResultMessage{Success: true}, nil
}
func (f *fakeOnlineSession) SendAndReceive(message interface{}, _ time.Duration) ([]byte, error) {
	role := f.nodeRole
	if role == "" {
		role = "signer"
	}
	target := f.snapshotTarget
	if target == "" {
		target = role
	}
	policyYAML := "reject_foreign_rekey: true\n"
	if target == "sentry" {
		policyYAML = "reject_rekey: true\n"
	}
	switch request := message.(type) {
	case protocol.GetAdminSettingsMessage:
		return marshalTestMessage(protocol.AdminSettingsMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAdminSettings, ID: request.ID},
			NodeRole:    role,
		})
	case protocol.GetPolicySnapshotMessage:
		return marshalTestMessage(protocol.PolicySnapshotMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypePolicySnapshot, ID: request.ID},
			Success:      true,
			Target:       target,
			IdentityID:   "default",
			PolicyYAML:   policyYAML,
			PolicySHA256: "active-sha",
		})
	case protocol.ValidatePolicyMessage:
		return marshalTestMessage(protocol.ValidatePolicyResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeValidatePolicyResult, ID: request.ID},
			Success:     true,
			Target:      target,
			IdentityID:  "default",
		})
	case protocol.ReplacePolicyMessage:
		f.replaceCalls++
		f.replaceRequest = request
		return marshalTestMessage(protocol.ReplacePolicyResultMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeReplacePolicyResult, ID: request.ID},
			Success:      true,
			Target:       "signer",
			IdentityID:   "default",
			PolicyYAML:   request.PolicyYAML,
			PolicySHA256: "replacement-sha",
		})
	default:
		return nil, errors.New("unexpected request")
	}
}

func TestOnlineReadOnlyAutoTargetsSentryWithoutReplacement(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "secret")
	session := &fakeOnlineSession{status: "unlocked", nodeRole: "sentry"}
	var stdout bytes.Buffer
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{
		Verb: VerbCheck, Target: policyeditor.TargetAuto,
	}, Streams{Stdout: &stdout})
	if err != nil {
		t.Fatal(err)
	}
	if session.unlockPassphrase != "" || session.replaceCalls != 0 {
		t.Fatalf("read-only command unlocked or replaced: unlock=%q replacements=%d", session.unlockPassphrase, session.replaceCalls)
	}
	if !strings.Contains(stdout.String(), "sentry policy OK online") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestOnlineAuthenticationFailureClosesSession(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "secret")
	session := &fakeOnlineSession{authErr: errors.New("denied")}
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{
		Verb: VerbCheck, Target: policyeditor.TargetSigner,
	}, Streams{})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("Run() error = %v", err)
	}
	if session.dialCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("session lifecycle = dial %d close %d", session.dialCalls, session.closeCalls)
	}
}

func marshalTestMessage(message interface{}) ([]byte, error) {
	return protocol.MarshalAdminMessage(message)
}

func TestOnlineApplyUsesActiveSnapshotSHAAndExactBytes(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "secret")
	path := filepath.Join(t.TempDir(), "draft.yaml")
	want := []byte("# exact draft\nreject_foreign_rekey: false\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	session := &fakeOnlineSession{status: "locked"}
	var stdout bytes.Buffer
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{
		Verb: VerbApply, Target: policyeditor.TargetAuto, Source: path,
	}, Streams{Stdout: &stdout, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if session.authPassphrase != "secret" || session.unlockPassphrase != "secret" {
		t.Fatalf("authentication/unlock passphrases = %q/%q", session.authPassphrase, session.unlockPassphrase)
	}
	if session.replaceRequest.ExpectedCurrentSHA256 != "active-sha" {
		t.Fatalf("expected SHA = %q, want active-sha", session.replaceRequest.ExpectedCurrentSHA256)
	}
	if session.replaceRequest.PolicyYAML != string(want) {
		t.Fatalf("replacement changed exact bytes:\n%s", session.replaceRequest.PolicyYAML)
	}
}

func TestRemotePolicyNeverConsumesLocalPassphraseEnvironment(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "local-only-secret")
	originalOpenTTY := OpenTTY
	t.Cleanup(func() { OpenTTY = originalOpenTTY })
	OpenTTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	session := &fakeOnlineSession{}
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{
		Verb: VerbCheck, Target: policyeditor.TargetSigner, Remote: true,
	}, Streams{Stdin: strings.NewReader(""), Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "intentionally local-only") {
		t.Fatalf("Run(remote) error = %v", err)
	}
	if session.dialCalls != 0 || session.authPassphrase != "" {
		t.Fatalf("remote session used local environment: dial=%d passphrase=%q", session.dialCalls, session.authPassphrase)
	}
}

func TestRescueDraftCheckNeedsNoStoreOrPassphrase(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "")
	path := filepath.Join(t.TempDir(), "draft.yaml")
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := (RescueRunner{}).Run(context.Background(), Command{
		Verb: VerbCheck, Target: policyeditor.TargetSigner, Source: path,
	}, Streams{Stdout: &stdout, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "policy OK: "+path) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

type countingReader struct{ calls int }

func (r *countingReader) Read([]byte) (int, error) { r.calls++; return 0, io.EOF }

func TestRescueApplyWithoutIndependentPassphraseDoesNotConsumeYAML(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "")
	originalOpenTTY := OpenTTY
	t.Cleanup(func() { OpenTTY = originalOpenTTY })
	OpenTTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	stdin := &countingReader{}
	err := (RescueRunner{}).Run(context.Background(), Command{
		Verb: VerbApply, Target: policyeditor.TargetSigner, Source: "-", DataDir: t.TempDir(),
	}, Streams{Stdin: stdin, Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), passphraseEnv) {
		t.Fatalf("Run(rescue apply) error = %v", err)
	}
	if stdin.calls != 0 {
		t.Fatalf("stdin read %d times before authentication", stdin.calls)
	}
}

func TestRetiredPassphraseEnvironmentFailsBeforeSession(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "legacy-secret")
	session := &fakeOnlineSession{}
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{
		Verb: VerbCheck, Target: policyeditor.TargetSigner,
	}, Streams{Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "is retired") {
		t.Fatalf("Run() error = %v", err)
	}
	if session.dialCalls != 0 {
		t.Fatalf("session dialed %d times", session.dialCalls)
	}
}

func TestProductionVerbCatalogIsUnique(t *testing.T) {
	seen := make(map[Verb]bool)
	for _, verb := range ProductionVerbs {
		if seen[verb] {
			t.Fatalf("duplicate production verb %q", verb)
		}
		seen[verb] = true
	}
	if !seen[VerbEdit] || !seen[VerbApply] || len(seen) != 6 {
		t.Fatalf("production verbs = %#v", ProductionVerbs)
	}
}

func TestDraftDigestUsesExactBytes(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	path := filepath.Join(t.TempDir(), "draft.yaml")
	data := []byte("# exact\nreject_foreign_rekey: false\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := (RescueRunner{}).Run(context.Background(), Command{
		Verb: VerbDigest, Target: policyeditor.TargetSigner, Source: path,
	}, Streams{Stdout: &stdout})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), policy.PolicySHA256(data)+"\n"; got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
}

func TestRescueApplyPreservesExactBytesAndProducesVerifiedPolicy(t *testing.T) {
	root, passphrase := initializedPolicyStore(t)
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, passphrase)
	draft := filepath.Join(t.TempDir(), "replacement.yaml")
	want := []byte("# exact rescue replacement\nreject_foreign_rekey: false\n")
	if err := os.WriteFile(draft, want, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := (RescueRunner{}).Run(context.Background(), Command{
		Verb: VerbApply, Target: policyeditor.TargetSigner, Source: draft, DataDir: root,
	}, Streams{Stdout: &stdout, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	path := policy.PolicyPath(root, auth.CurrentProductIdentityID())
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("rescue apply changed bytes:\n%s", got)
	}
	if err := (RescueRunner{}).Run(context.Background(), Command{
		Verb: VerbCheck, Target: policyeditor.TargetSigner, DataDir: root,
	}, Streams{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
		t.Fatalf("saved policy did not verify: %v", err)
	}
}

func TestRescueApplyRefusesBusyStoreBeforeReadingReplacement(t *testing.T) {
	root, passphrase := initializedPolicyStore(t)
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, passphrase)
	shared, err := storelock.AcquireShared(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shared.Close() }()
	path := policy.PolicyPath(root, auth.CurrentProductIdentityID())
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = (RescueRunner{}).Run(context.Background(), Command{
		Verb: VerbApply, Target: policyeditor.TargetSigner, Source: filepath.Join(t.TempDir(), "missing.yaml"), DataDir: root,
	}, Streams{Stdout: io.Discard, Stderr: io.Discard})
	if !errors.Is(err, storelock.ErrBusy) {
		t.Fatalf("Run(rescue apply busy) error = %v, want ErrBusy", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("busy rescue apply changed production policy")
	}
}

func TestRescueDraftEditWritesOnlyDraftWithoutSidecar(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "draft.yaml")
	if err := os.WriteFile(path, []byte("reject_foreign_rekey: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var editorDataDir string
	editor := func(store policyeditor.Store, _ *policy.StoredConfig, dataDir, _ string, _ policyeditor.Target) error {
		editorDataDir = dataDir
		replacement, err := policy.ParseStoredConfig([]byte("reject_foreign_rekey: false\n"))
		if err != nil {
			return err
		}
		return store.Save(context.Background(), replacement)
	}
	err := (RescueRunner{Editor: editor}).Run(context.Background(), Command{
		Verb: VerbEdit, Target: policyeditor.TargetSigner, Source: path,
	}, Streams{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if editorDataDir != "" {
		t.Fatalf("standalone editor data directory = %q, want empty", editorDataDir)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "reject_foreign_rekey: false" {
		t.Fatalf("draft contents = %q", got)
	}
	if _, err := os.Stat(path + ".hmac"); !os.IsNotExist(err) {
		t.Fatalf("standalone draft created sidecar: %v", err)
	}
}

func TestRescueProductionEditHoldsLockThroughEditorAndNormalizesOnlyOnSuccess(t *testing.T) {
	root, passphrase := initializedPolicyStore(t)
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, passphrase)

	oldEUID, oldManaged := EffectiveUID, IsManagedStore
	oldOwner, oldLoad := ManagedStoreOwner, LoadServerConfig
	oldSocket, oldNormalize := ResolveLegacySocket, NormalizeStore
	t.Cleanup(func() {
		EffectiveUID, IsManagedStore = oldEUID, oldManaged
		ManagedStoreOwner, LoadServerConfig = oldOwner, oldLoad
		ResolveLegacySocket, NormalizeStore = oldSocket, oldNormalize
	})
	EffectiveUID = func() int { return 0 }
	IsManagedStore = func(string) (bool, error) { return true, nil }
	ManagedStoreOwner = func(string) (int, int, error) { return 12, 34, nil }
	LoadServerConfig = func(string) (serverconfig.ServerConfig, error) {
		cfg := serverconfig.DefaultServerConfig()
		return cfg, nil
	}
	ResolveLegacySocket = func(string, string) (string, error) { return "socket", nil }
	normalizeCalls := 0
	NormalizeStore = func(root string, uid, gid int, socket string) error {
		normalizeCalls++
		if uid != 12 || gid != 34 || socket != "socket" {
			t.Fatalf("normalization inputs = %d:%d %q", uid, gid, socket)
		}
		return nil
	}

	editor := func(policyeditor.Store, *policy.StoredConfig, string, string, policyeditor.Target) error {
		guard, err := storelock.AcquireShared(root)
		if err == nil {
			_ = guard.Close()
			t.Fatal("editor did not retain the exclusive mutation lock")
		}
		if !errors.Is(err, storelock.ErrBusy) {
			t.Fatalf("AcquireShared() error = %v", err)
		}
		return nil
	}
	err := (RescueRunner{Editor: editor}).Run(context.Background(), Command{
		Verb: VerbEdit, Target: policyeditor.TargetSigner, DataDir: root,
	}, Streams{})
	if err != nil {
		t.Fatal(err)
	}
	if normalizeCalls != 1 {
		t.Fatalf("normalize calls = %d, want 1", normalizeCalls)
	}

	normalizeCalls = 0
	err = (RescueRunner{Editor: func(policyeditor.Store, *policy.StoredConfig, string, string, policyeditor.Target) error {
		return errors.New("cancelled")
	}}).Run(context.Background(), Command{
		Verb: VerbEdit, Target: policyeditor.TargetSigner, DataDir: root,
	}, Streams{})
	if err == nil || normalizeCalls != 0 {
		t.Fatalf("failed edit error=%v normalize calls=%d", err, normalizeCalls)
	}
}

func initializedPolicyStore(t *testing.T) (string, string) {
	t.Helper()
	lsig.RegisterClient()
	root := t.TempDir()
	passphrase := "policycmd-test-passphrase"
	_, err := storeinit.Initialize([]byte(passphrase), storeinit.Options{
		DataDir: root, Paths: storepaths.NewPaths(root), IdentityID: auth.CurrentProductIdentityID(), Role: noderole.RoleSigner,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, passphrase
}
