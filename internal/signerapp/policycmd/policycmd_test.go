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

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
)

type fakeOnlineSession struct {
	status           string
	dialCalls        int
	closeCalls       int
	authPassphrase   string
	unlockPassphrase string
	replaceRequest   protocol.ReplacePolicyMessage
}

func (f *fakeOnlineSession) Dial() error { f.dialCalls++; return nil }
func (f *fakeOnlineSession) Close()      { f.closeCalls++ }
func (f *fakeOnlineSession) Authenticate(passphrase string, _ time.Duration) error {
	f.authPassphrase = passphrase
	return nil
}
func (f *fakeOnlineSession) WaitForStatus(time.Duration) (*protocol.StatusMessage, error) {
	return &protocol.StatusMessage{State: f.status}, nil
}
func (f *fakeOnlineSession) Unlock(passphrase string, _ time.Duration) (*protocol.UnlockResultMessage, error) {
	f.unlockPassphrase = passphrase
	return &protocol.UnlockResultMessage{Success: true}, nil
}
func (f *fakeOnlineSession) SendAndReceive(message interface{}, _ time.Duration) ([]byte, error) {
	switch request := message.(type) {
	case protocol.GetAdminSettingsMessage:
		return marshalTestMessage(protocol.AdminSettingsMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAdminSettings, ID: request.ID},
			NodeRole:    "signer",
		})
	case protocol.GetPolicySnapshotMessage:
		return marshalTestMessage(protocol.PolicySnapshotMessage{
			BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypePolicySnapshot, ID: request.ID},
			Success:      true,
			Target:       "signer",
			IdentityID:   "default",
			PolicyYAML:   "reject_foreign_rekey: true\n",
			PolicySHA256: "active-sha",
		})
	case protocol.ValidatePolicyMessage:
		return marshalTestMessage(protocol.ValidatePolicyResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeValidatePolicyResult, ID: request.ID},
			Success:     true,
			Target:      "signer",
			IdentityID:  "default",
		})
	case protocol.ReplacePolicyMessage:
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
