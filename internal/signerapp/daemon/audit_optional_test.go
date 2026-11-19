// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/enrollment"
	"github.com/aplane-algo/aplane/internal/signerapp/keyadmin"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	"github.com/aplane-algo/aplane/internal/signerapp/storeadmin"
)

// The daemon keeps running when audit.log cannot be opened, with a nil
// *AuditLogger. A service handed that pointer as an interface sees a non-nil
// logger and panics on its first entry, so every service must see none.
func TestServicesBuiltWithoutAnAuditLogSeeNoLogger(t *testing.T) {
	fs := &Signer{}
	if got := fs.adminServices().storeApp().AuditLog; got != nil {
		t.Errorf("store admin AuditLog = %#v, want nil", got)
	}
	if got := fs.enrollmentService().AuditLog; got != nil {
		t.Errorf("enrollment AuditLog = %#v, want nil", got)
	}
	if got := fs.genericLSigGenerator().AuditLog; got != nil {
		t.Errorf("generic LogicSig AuditLog = %#v, want nil", got)
	}
	if got := fs.restService().Deps.KeyAdmin.AuditLog; got != nil {
		t.Errorf("REST key admin AuditLog = %#v, want nil", got)
	}
	if got := fs.restServiceWithSigningAudit(nil).Deps.KeyAdmin.AuditLog; got != nil {
		t.Errorf("attributed REST key admin AuditLog = %#v, want nil", got)
	}
}

// A passphrase change in that mode completes without a panic after its
// commit.
func TestChangeStorePassphraseWithoutAnAuditLog(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	convertTestSignerToGenerational(t, server)
	server.auditLog = nil

	result := server.adminServices().ChangeStorePassphrase(
		context.Background(),
		adminproto.ChangeStorePassphraseRequest{
			CurrentPassphrase: testPassphrase,
			NewPassphrase:     []byte("new-admin-passphrase"),
		},
	)
	if !result.Success {
		t.Fatalf("ChangeStorePassphrase() = %+v", result)
	}
}

// A clean shutdown in that mode returns without a panic.
func TestLifecycleWithoutAnAuditLogShutsDownCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := signerstartup.RunLifecycle(ctx, signerstartup.LifecyclePlan{
		AuditLog: optionalAuditLog[signerstartup.ServerAuditLogger](nil),
	})
	if err != nil {
		t.Fatalf("RunLifecycle() = %v, want nil", err)
	}
}

// A present logger reaches every service interface.
func TestOptionalAuditLogPassesAPresentLogger(t *testing.T) {
	log, err := NewAuditLogger(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	if optionalAuditLog[keyadmin.AuditLogger](log) == nil {
		t.Error("keyadmin.AuditLogger is nil")
	}
	if optionalAuditLog[enrollment.AuditLogger](log) == nil {
		t.Error("enrollment.AuditLogger is nil")
	}
	if optionalAuditLog[storeadmin.AuditLogger](log) == nil {
		t.Error("storeadmin.AuditLogger is nil")
	}
	if optionalAuditLog[signerstartup.ServerAuditLogger](log) == nil {
		t.Error("ServerAuditLogger is nil")
	}
}
