// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// A revocation whose registry write fails after the rename has taken
// effect: the key is refused, the revocation is audited, and the durability
// failure is reported to the operator on top of that.
func TestRevokeClientKeyAppliedNotDurableIsAudited(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	ir := productruntime.New(productruntime.Config{KeyPaths: storepaths.NewPaths(t.TempDir())})
	fs := &Signer{auditLog: auditLog, runtime: ir}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ir.EnrollAuthorizedKey(key, "laptop"); err != nil {
		t.Fatal(err)
	}
	fingerprint := ssh.FingerprintSHA256(key)

	fsutil.TestHook = func(op fsutil.HookOp, _ string) error {
		if op == fsutil.OpDirSync {
			return errors.New("injected dir sync failure")
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	_, err = fs.RevokeClientKey(adminserver.SessionContext{}, ir, fingerprint)
	if !errors.Is(err, productruntime.ErrAppliedNotDurable) {
		t.Fatalf("RevokeClientKey() error = %v, want the applied-not-durable failure", err)
	}
	if ir.HasAuthorizedKey(key) {
		t.Fatal("revoked key is still authorized")
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), string(signeraudit.AuditClientKeyRevoked)) || !strings.Contains(string(data), fingerprint) {
		t.Fatalf("audit log lacks the revocation that took effect: %q", data)
	}
}
