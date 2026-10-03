// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig"
)

const (
	testKeyA = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"
	testKeyB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

const testSignerDoc = `{"format":"aplane.signer-policy.v1","max_fee_microalgos":"2000"}`

func testCosignerDoc(key string) string {
	return fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,"transfer_policy":{"routes":[]}}`, key)
}

// fakeOnlineSession plays the daemon side of the policy messages.
type fakeOnlineSession struct {
	status           string
	dialCalls        int
	closeCalls       int
	authPassphrase   string
	unlockPassphrase string
	authErr          error
	policy           protocol.PolicyMessage
	bodies           map[string]string
	checkResult      *protocol.CheckPolicyResultMessage
	applyResult      *protocol.ApplyPolicyResultMessage
	checks           []protocol.CheckPolicyMessage
	applies          []protocol.ApplyPolicyMessage
}

func newFakeSession(role string, docs ...protocol.PolicyDocumentWire) *fakeOnlineSession {
	f := &fakeOnlineSession{status: "unlocked", bodies: map[string]string{}, policy: protocol.PolicyMessage{
		Success: true, NodeRole: role, PolicySetSHA256: "active-set",
	}}
	for _, doc := range docs {
		f.bodies[doc.Key] = doc.Document
		f.policy.Documents = append(f.policy.Documents, protocol.PolicyDocumentInfoWire{
			Key: doc.Key, SHA256: policy.PolicySHA256([]byte(doc.Document)), Size: len(doc.Document),
		})
	}
	return f
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
	return &protocol.UnlockResultMessage{Success: true}, nil
}
func (f *fakeOnlineSession) SendAndReceive(message interface{}, _ time.Duration) ([]byte, error) {
	switch request := message.(type) {
	case protocol.GetPolicyMessage:
		reply := f.policy
		reply.BaseMessage = protocol.BaseMessage{Type: protocol.MsgTypePolicy, ID: request.ID}
		return protocol.MarshalAdminMessage(reply)
	case protocol.GetPolicyDocumentMessage:
		reply := protocol.PolicyDocumentMessage{Code: "policy_document_not_found", Error: "no such policy"}
		if body, ok := f.bodies[request.Key]; ok {
			reply = protocol.PolicyDocumentMessage{Success: true, Key: request.Key, Document: body}
		}
		reply.BaseMessage = protocol.BaseMessage{Type: protocol.MsgTypePolicyDocument, ID: request.ID}
		return protocol.MarshalAdminMessage(reply)
	case protocol.CheckPolicyMessage:
		f.checks = append(f.checks, request)
		reply := protocol.CheckPolicyResultMessage{Success: true, Valid: true}
		if f.checkResult != nil {
			reply = *f.checkResult
		}
		reply.BaseMessage = protocol.BaseMessage{Type: protocol.MsgTypeCheckPolicyResult, ID: request.ID}
		return protocol.MarshalAdminMessage(reply)
	case protocol.ApplyPolicyMessage:
		f.applies = append(f.applies, request)
		reply := protocol.ApplyPolicyResultMessage{Success: true, Policy: &protocol.PolicyMessage{
			Success: true, GenerationID: "gen-new", PolicySetSHA256: "new-set",
		}}
		if f.applyResult != nil {
			reply = *f.applyResult
		}
		reply.BaseMessage = protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicyResult, ID: request.ID}
		return protocol.MarshalAdminMessage(reply)
	default:
		return nil, errors.New("unexpected request")
	}
}

func writePolicyFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func onlineEnv(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "secret")
}

func TestOnlineStatusListsCosignerCoverage(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner", protocol.PolicyDocumentWire{Key: testKeyA, Document: testCosignerDoc(testKeyA)})
	session.policy.Keys = []protocol.PolicyKeyStatusWire{{Key: testKeyA, Status: "active"}, {Key: testKeyB, Status: "no_policy"}}
	var stdout bytes.Buffer
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbStatus}, Streams{Stdout: &stdout}); err != nil {
		t.Fatal(err)
	}
	out := stdout.String()
	for _, want := range []string{"cosigner policies (2 keys)", testKeyA + "  active", testKeyB + "  no policy", "policy_set_sha256 active-set"} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
	if session.unlockPassphrase != "" || len(session.applies) != 0 {
		t.Fatal("status unlocked or applied")
	}
}

func TestOnlineExportWritesExactDocument(t *testing.T) {
	onlineEnv(t)
	signer := newFakeSession("signer", protocol.PolicyDocumentWire{Document: testSignerDoc + "\n"})
	var stdout bytes.Buffer
	if err := (OnlineRunner{Session: signer}).Run(context.Background(), Command{Verb: VerbExport}, Streams{Stdout: &stdout}); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != testSignerDoc+"\n" {
		t.Fatalf("export = %q", stdout.String())
	}

	cosigner := newFakeSession("cosigner", protocol.PolicyDocumentWire{Key: testKeyA, Document: testCosignerDoc(testKeyA)})
	if err := (OnlineRunner{Session: cosigner}).Run(context.Background(), Command{Verb: VerbExport}, Streams{}); err == nil || !strings.Contains(err.Error(), "--key") {
		t.Fatalf("cosigner export without --key error = %v", err)
	}
	stdout.Reset()
	if err := (OnlineRunner{Session: cosigner}).Run(context.Background(), Command{Verb: VerbExport, Key: testKeyA}, Streams{Stdout: &stdout}); err != nil || stdout.String() != testCosignerDoc(testKeyA) {
		t.Fatalf("export --key = %q, %v", stdout.String(), err)
	}
	if err := (OnlineRunner{Session: cosigner}).Run(context.Background(), Command{Verb: VerbExport, Key: testKeyB}, Streams{}); err == nil {
		t.Fatal("export of a key without a policy succeeded")
	}
}

func TestOnlineApplyChecksThenAppliesExactBytesAgainstActiveSet(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner")
	a := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	b := writePolicyFile(t, "b.json", testCosignerDoc(testKeyB))
	var stdout bytes.Buffer
	if err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{a, b}}, Streams{Stdout: &stdout}); err != nil {
		t.Fatal(err)
	}
	if len(session.checks) != 1 || len(session.applies) != 1 {
		t.Fatalf("checks %d applies %d, want 1 each", len(session.checks), len(session.applies))
	}
	apply := session.applies[0]
	if apply.ExpectedPolicySetSHA256 != "active-set" || len(apply.Documents) != 2 ||
		apply.Documents[0].Key != testKeyA || apply.Documents[0].Document != testCosignerDoc(testKeyA) ||
		apply.Documents[1].Key != testKeyB {
		t.Fatalf("apply request = %+v", apply)
	}
	if !strings.Contains(stdout.String(), "policy applied as generation gen-new") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestOnlineCheckReportsProblemsByFileAndStopsApply(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("cosigner")
	session.checkResult = &protocol.CheckPolicyResultMessage{Success: true, Errors: []protocol.PolicyProblemWire{
		{Key: testKeyA, Pointer: "/limits", Message: "bad limit"},
	}}
	file := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	var stderr bytes.Buffer
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{file}}, Streams{Stderr: &stderr})
	if !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("Run() error = %v, want ErrPolicyInvalid", err)
	}
	if !strings.Contains(stderr.String(), "error: "+file+" /limits: bad limit") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if len(session.applies) != 0 {
		t.Fatal("an invalid policy was applied")
	}
}

func TestOnlineApplyReportsDaemonFailureCode(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("signer", protocol.PolicyDocumentWire{Document: testSignerDoc})
	session.applyResult = &protocol.ApplyPolicyResultMessage{Code: "policy_snapshot_changed", Error: "active policy changed"}
	file := writePolicyFile(t, "policy.json", testSignerDoc)
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{file}}, Streams{})
	if err == nil || !strings.Contains(err.Error(), "policy_snapshot_changed") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestReadDocumentsEnforcesRoleShape(t *testing.T) {
	signer := writePolicyFile(t, "policy.json", testSignerDoc)
	if _, _, err := readDocuments([]string{signer, signer}, "signer", nil); err == nil {
		t.Fatal("two signer files accepted")
	}
	noKey := writePolicyFile(t, "nokey.json", `{"format":"aplane.cosigner-policy.v1"}`)
	if _, _, err := readDocuments([]string{noKey}, "cosigner", nil); err == nil || !strings.Contains(err.Error(), `"key"`) {
		t.Fatalf("cosigner file without key error = %v", err)
	}
	a := writePolicyFile(t, "a.json", testCosignerDoc(testKeyA))
	again := writePolicyFile(t, "again.json", testCosignerDoc(testKeyA))
	if _, _, err := readDocuments([]string{a, again}, "cosigner", nil); err == nil || !strings.Contains(err.Error(), "both policies") {
		t.Fatalf("duplicate key error = %v", err)
	}
	empty := writePolicyFile(t, "empty.json", "  \n")
	if _, _, err := readDocuments([]string{empty}, "signer", nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty file error = %v", err)
	}
}

func TestOnlineAuthenticationFailureClosesSession(t *testing.T) {
	onlineEnv(t)
	session := newFakeSession("signer")
	session.authErr = errors.New("denied")
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbStatus}, Streams{})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("Run() error = %v", err)
	}
	if session.dialCalls != 1 || session.closeCalls != 1 {
		t.Fatalf("session lifecycle = dial %d close %d", session.dialCalls, session.closeCalls)
	}
}

func TestPolicyStatusAcceptsPipedPassphrase(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "")
	originalOpenTTY := OpenTTY
	t.Cleanup(func() { OpenTTY = originalOpenTTY })
	ttyCalls := 0
	OpenTTY = func() (*os.File, error) {
		ttyCalls++
		return nil, errors.New("no tty")
	}
	session := newFakeSession("signer", protocol.PolicyDocumentWire{Document: testSignerDoc})
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbStatus},
		Streams{Stdin: strings.NewReader("explicit-secret\n"), Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if session.authPassphrase != "explicit-secret" || ttyCalls != 0 {
		t.Fatalf("passphrase %q, tty opens %d", session.authPassphrase, ttyCalls)
	}
}

func TestLocalNonterminalPassphrasePreservesStdinAutomation(t *testing.T) {
	t.Setenv(passphraseEnv, "")
	originalOpenTTY := OpenTTY
	t.Cleanup(func() { OpenTTY = originalOpenTTY })
	ttyCalls := 0
	OpenTTY = func() (*os.File, error) {
		ttyCalls++
		return nil, errors.New("unexpected tty open")
	}
	passphrase, err := ReadPassphrase(strings.NewReader("piped-secret\n"), io.Discard, false)
	if err != nil {
		t.Fatal(err)
	}
	if string(passphrase) != "piped-secret" || ttyCalls != 0 {
		t.Fatalf("passphrase = %q, tty opens %d", passphrase, ttyCalls)
	}
}

type countingReader struct{ calls int }

func (r *countingReader) Read([]byte) (int, error) { r.calls++; return 0, io.EOF }

func TestHeadlessApplyStdinFailsBeforeReadingDocument(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "")
	originalOpenTTY := OpenTTY
	t.Cleanup(func() { OpenTTY = originalOpenTTY })
	OpenTTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	stdin := &countingReader{}
	session := newFakeSession("signer")
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{"-"}},
		Streams{Stdin: stdin, Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "controlling terminal") {
		t.Fatalf("Run(IPC apply -) error = %v", err)
	}
	if stdin.calls != 0 || session.dialCalls != 0 {
		t.Fatalf("stdin reads %d, dials %d before a passphrase was available", stdin.calls, session.dialCalls)
	}
}

func TestRescueApplyWithoutIndependentPassphraseDoesNotConsumeDocument(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, "")
	originalOpenTTY := OpenTTY
	t.Cleanup(func() { OpenTTY = originalOpenTTY })
	OpenTTY = func() (*os.File, error) { return nil, errors.New("no tty") }
	stdin := &countingReader{}
	err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{"-"}, DataDir: t.TempDir()},
		Streams{Stdin: stdin, Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), passphraseEnv) {
		t.Fatalf("Run(rescue apply) error = %v", err)
	}
	if stdin.calls != 0 {
		t.Fatalf("stdin read %d times before authentication", stdin.calls)
	}
}

func TestRetiredPassphraseEnvironmentFailsBeforeSession(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "legacy-secret")
	session := newFakeSession("signer")
	err := (OnlineRunner{Session: session}).Run(context.Background(), Command{Verb: VerbStatus}, Streams{Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "is retired") || session.dialCalls != 0 {
		t.Fatalf("Run() error = %v, dials %d", err, session.dialCalls)
	}
}

func TestRejectRetiredEnvironmentFailsClosedAtCredentialBoundary(t *testing.T) {
	t.Setenv(retiredPassphraseEnv, "legacy-secret")
	if err := RejectRetiredEnvironment(); err == nil || !strings.Contains(err.Error(), retiredPassphraseEnv+" is retired") {
		t.Fatalf("RejectRetiredEnvironment() error = %v, want retired credential rejection", err)
	}
	t.Setenv(retiredPassphraseEnv, "")
	if err := RejectRetiredEnvironment(); err != nil {
		t.Fatalf("RejectRetiredEnvironment() with empty variable error = %v", err)
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
	if !seen[VerbCheck] || !seen[VerbApply] || len(seen) != 5 {
		t.Fatalf("production verbs = %#v", ProductionVerbs)
	}
}

func TestRescueSignerApplyPreservesExactBytesAndVerifies(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleSigner)
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, passphrase)
	want := "{\n  \"format\": \"aplane.signer-policy.v1\",\n  \"max_fee_microalgos\": \"2000\"\n}\n"
	file := writePolicyFile(t, "policy.json", want)
	var stdout bytes.Buffer
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{file}, DataDir: root},
		Streams{Stdout: &stdout, Stderr: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "policy applied as generation") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	doc := verifiedSignerPolicy(t, root, passphrase)
	if string(doc.Bytes) != want {
		t.Fatalf("stored policy = %q, want exact bytes %q", doc.Bytes, want)
	}

	stdout.Reset()
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbExport, DataDir: root},
		Streams{Stdout: &stdout, Stderr: io.Discard}); err != nil || stdout.String() != want {
		t.Fatalf("rescue export = %q, %v", stdout.String(), err)
	}
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbRemove, Args: []string{testKeyA}, DataDir: root},
		Streams{Stderr: io.Discard}); err == nil || !strings.Contains(err.Error(), "cosigner nodes") {
		t.Fatalf("rescue remove on a signer error = %v", err)
	}
}

func TestRescueCosignerApplyAndRemovePerKey(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleCosigner)
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, passphrase)
	files := []string{writePolicyFile(t, "a.json", testCosignerDoc(testKeyA)), writePolicyFile(t, "b.json", testCosignerDoc(testKeyB))}
	var stderr bytes.Buffer
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbApply, Args: files, DataDir: root},
		Streams{Stdout: io.Discard, Stderr: &stderr}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "policy is for a key this node does not hold") {
		t.Fatalf("apply warnings = %q", stderr.String())
	}
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbRemove, Args: []string{testKeyB}, DataDir: root},
		Streams{Stdout: io.Discard, Stderr: io.Discard}); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := (RescueRunner{}).Run(context.Background(), Command{Verb: VerbStatus, DataDir: root},
		Streams{Stdout: &stdout, Stderr: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), testKeyA+"  key not held") || strings.Contains(stdout.String(), testKeyB) {
		t.Fatalf("status after remove:\n%s", stdout.String())
	}
}

func TestRescueApplyRefusesBusyStoreBeforeReadingReplacement(t *testing.T) {
	root, passphrase := initializedPolicyStore(t, noderole.RoleSigner)
	t.Setenv(retiredPassphraseEnv, "")
	t.Setenv(passphraseEnv, passphrase)
	before := verifiedSignerPolicy(t, root, passphrase)
	shared, err := storelock.AcquireShared(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shared.Close() }()
	err = (RescueRunner{}).Run(context.Background(), Command{Verb: VerbApply, Args: []string{filepath.Join(t.TempDir(), "missing.json")}, DataDir: root},
		Streams{Stdout: io.Discard, Stderr: io.Discard})
	if !errors.Is(err, storelock.ErrBusy) {
		t.Fatalf("Run(rescue apply busy) error = %v, want ErrBusy", err)
	}
	_ = shared.Close()
	if after := verifiedSignerPolicy(t, root, passphrase); !bytes.Equal(before.Bytes, after.Bytes) {
		t.Fatal("busy rescue apply changed production policy")
	}
}

func initializedPolicyStore(t *testing.T, role noderole.Role) (string, string) {
	t.Helper()
	lsig.RegisterClient()
	root := t.TempDir()
	passphrase := "policycmd-test-passphrase"
	_, err := storeinit.Initialize([]byte(passphrase), storeinit.Options{
		DataDir: root, Paths: storepaths.NewPaths(root), Role: role,
	})
	if err != nil {
		t.Fatal(err)
	}
	return root, passphrase
}

func verifiedSignerPolicy(t *testing.T, root, passphrase string) policy.StoredDocument {
	t.Helper()
	active, kr, err := genstore.ResolveStoreRoot(storepaths.NewPaths(root), []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	doc, _, err := policy.LoadVerifiedSignerPolicy(active, kr)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
