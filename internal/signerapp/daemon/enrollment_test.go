// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/clientregistry"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollqueue"
)

func testClientKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A request is queued, announced to the connected operator, and enrolled
// when the operator approves it; a repeat request refreshes the same entry,
// and a request for an enrolled key is answered as such.
func TestEnrollmentRequestQueuesNotifiesAndApproves(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
	server.ipcServer = ipcServer
	adminConn := addActiveProductSession(t, ipcServer)

	key := testClientKey(t)
	fingerprint := ssh.FingerprintSHA256(key)
	svc := server.enrollmentService()
	pending, err := svc.Request(key, "laptop", "10.0.0.1:1")
	if err != nil || !pending {
		t.Fatalf("Request() = %v, %v, want pending", pending, err)
	}

	var messages []map[string]any
	deadline := time.After(2 * time.Second)
	for len(messages) == 0 {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for the enrollment request notification")
		case <-time.After(10 * time.Millisecond):
			messages = adminConn.messages(t)
		}
	}
	if !reflectJSONSubset(messages[0], map[string]any{
		"kind":            string(protocol.MessageKindNotification),
		"type":            protocol.MsgTypeClientEnrollmentRequest,
		"id":              "enroll-" + fingerprint,
		"ssh_fingerprint": fingerprint,
		"label":           "laptop",
		"remote_addr":     "10.0.0.1:1",
	}) {
		t.Fatalf("enrollment request notification shape mismatch: %#v", messages[0])
	}

	if pending, err := svc.Request(key, "", "10.0.0.2:2"); err != nil || !pending {
		t.Fatalf("repeat Request() = %v, %v, want pending", pending, err)
	}
	ir := server.productRuntime()
	queued := ir.PendingEnrollments()
	if len(queued) != 1 || queued[0].Fingerprint != fingerprint || queued[0].Label != "laptop" || queued[0].RemoteAddr != "10.0.0.2:2" {
		t.Fatalf("pending = %+v, want one refreshed request", queued)
	}

	label, err := server.ApproveClientEnrollment(adminserver.SessionContext{}, ir, fingerprint, "")
	if err != nil || label != "laptop" {
		t.Fatalf("ApproveClientEnrollment() = %q, %v", label, err)
	}
	if !ir.HasAuthorizedKey(key) {
		t.Fatal("approved key is not enrolled")
	}
	if got := ir.PendingEnrollments(); len(got) != 0 {
		t.Fatalf("pending after approval = %+v, want none", got)
	}
	if _, err := server.ApproveClientEnrollment(adminserver.SessionContext{}, ir, fingerprint, ""); err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
		t.Fatalf("second approval error = %v, want invalid_request", err)
	}
	if pending, err := svc.Request(key, "", "10.0.0.3:3"); err != nil || pending {
		t.Fatalf("Request() for an enrolled key = %v, %v, want not pending", pending, err)
	}
}

// Rejection drops the request without enrolling; import enrolls a supplied
// key directly, clears a waiting request for it, and refuses bad input.
func TestEnrollmentRejectAndImport(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	svc := server.enrollmentService()

	rejected := testClientKey(t)
	if _, err := svc.Request(rejected, "", "10.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if err := server.RejectClientEnrollment(adminserver.SessionContext{}, ir, ssh.FingerprintSHA256(rejected)); err != nil {
		t.Fatalf("RejectClientEnrollment() error = %v", err)
	}
	if ir.HasAuthorizedKey(rejected) || len(ir.PendingEnrollments()) != 0 {
		t.Fatal("rejected key was enrolled or left pending")
	}
	if err := server.RejectClientEnrollment(adminserver.SessionContext{}, ir, ssh.FingerprintSHA256(rejected)); err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
		t.Fatalf("second rejection error = %v, want invalid_request", err)
	}

	imported := testClientKey(t)
	if _, err := svc.Request(imported, "requested-label", "10.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(imported))) + " ops-laptop"
	fingerprint, label, added, err := server.ImportClientKey(adminserver.SessionContext{}, ir, line, "")
	if err != nil || !added || fingerprint != ssh.FingerprintSHA256(imported) || label != "ops-laptop" {
		t.Fatalf("ImportClientKey() = %q, %q, %v, %v", fingerprint, label, added, err)
	}
	if !ir.HasAuthorizedKey(imported) || len(ir.PendingEnrollments()) != 0 {
		t.Fatal("imported key is not enrolled or its request was left pending")
	}
	if _, _, added, err := server.ImportClientKey(adminserver.SessionContext{}, ir, line, "other"); err != nil || added {
		t.Fatalf("repeat ImportClientKey() added = %v, err = %v, want no change", added, err)
	}
	if _, _, _, err := server.ImportClientKey(adminserver.SessionContext{}, ir, "not a key", ""); err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
		t.Fatalf("invalid import error = %v, want invalid_request", err)
	}
	var coded interface{ Code() string }
	if errors.As(err, &coded) {
		_ = coded
	}
}

// Labels supplied over the admin protocol follow the registry's label rule:
// a line break or an over-long label is refused before anything is written,
// since the registry emits labels verbatim on the key's authorized_keys
// line.
func TestAdminEnrollmentLabelsAreValidated(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	svc := server.enrollmentService()

	requested := testClientKey(t)
	if _, err := svc.Request(requested, "laptop", "10.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(requested)
	for _, label := range []string{"lab\nssh-ed25519 AAAA evil", strings.Repeat("x", clientregistry.MaxLabelBytes+1)} {
		if _, err := server.ApproveClientEnrollment(adminserver.SessionContext{}, ir, fingerprint, label); err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
			t.Fatalf("ApproveClientEnrollment(label %q) error = %v, want invalid_request", label, err)
		}
		if ir.HasAuthorizedKey(requested) || len(ir.PendingEnrollments()) != 1 {
			t.Fatalf("a refused label changed state: authorized = %v, pending = %d", ir.HasAuthorizedKey(requested), len(ir.PendingEnrollments()))
		}
	}
	if _, err := server.ApproveClientEnrollment(adminserver.SessionContext{}, ir, fingerprint, "  ops laptop  "); err != nil {
		t.Fatalf("ApproveClientEnrollment() error = %v", err)
	}
	if entry, ok := ir.EnrolledKey(fingerprint); !ok || entry.Label != "ops laptop" {
		t.Fatalf("enrolled entry = %+v, %v, want the trimmed label", entry, ok)
	}

	imported := testClientKey(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(imported)))
	if _, _, _, err := server.ImportClientKey(adminserver.SessionContext{}, ir, line, "lab\nssh-ed25519 AAAA evil"); err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
		t.Fatalf("ImportClientKey(label with line break) error = %v, want invalid_request", err)
	}
	if _, _, _, err := server.ImportClientKey(adminserver.SessionContext{}, ir, line+" "+strings.Repeat("x", clientregistry.MaxLabelBytes+1), ""); err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest {
		t.Fatalf("ImportClientKey(over-long comment) error = %v, want invalid_request", err)
	}
	if ir.HasAuthorizedKey(imported) {
		t.Fatal("a refused label enrolled the key")
	}
	if reg, err := clientregistry.Load(ir.AuthorizedKeysPath()); err != nil || reg.Len() != 1 {
		t.Fatalf("registry on disk: err = %v, len = %d, want exactly the approved key", err, reg.Len())
	}
}

// Rejecting a request whose key is already enrolled is refused: the request
// is left for a repeat approval to clear, and the key stays enrolled.
func TestRejectClientEnrollmentRefusesEnrolledKey(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	svc := server.enrollmentService()

	key := testClientKey(t)
	if _, err := svc.Request(key, "laptop", "10.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(key)
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && strings.Contains(path, enrollqueue.FileName) {
			return errors.New("injected queue rename failure")
		}
		return nil
	}
	if _, err := server.ApproveClientEnrollment(adminserver.SessionContext{}, ir, fingerprint, ""); err == nil {
		t.Fatal("ApproveClientEnrollment() succeeded despite the queue failure")
	}
	fsutil.TestHook = nil
	if !ir.HasAuthorizedKey(key) || len(ir.PendingEnrollments()) != 1 {
		t.Fatalf("setup: authorized = %v, pending = %d", ir.HasAuthorizedKey(key), len(ir.PendingEnrollments()))
	}
	err := server.RejectClientEnrollment(adminserver.SessionContext{}, ir, fingerprint)
	if err == nil || protocol.CodeForError(err) != protocol.ErrCodeInvalidRequest || !strings.Contains(err.Error(), "already enrolled") {
		t.Fatalf("RejectClientEnrollment() error = %v, want invalid_request naming the enrolled key", err)
	}
	if !ir.HasAuthorizedKey(key) || len(ir.PendingEnrollments()) != 1 {
		t.Fatal("a refused rejection changed state")
	}
}
