// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshprovision

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/productmode"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

type auditRecorder struct {
	identityID     string
	sshFingerprint string
	remoteAddr     string
}

func (a *auditRecorder) LogTokenProvisioned(identityID, sshFingerprint, remoteAddr string) {
	a.identityID = identityID
	a.sshFingerprint = sshFingerprint
	a.remoteAddr = remoteAddr
}

func TestServiceApproveUsesCanonicalRequestShape(t *testing.T) {
	called := false
	svc := Service{
		Now: func() time.Time {
			return time.Unix(0, 12345)
		},
		RequestTokenProvisioning: func(requestID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
			called = true
			if requestID != "token-12345" {
				t.Fatalf("requestID = %q, want token-12345", requestID)
			}
			if sshFingerprint != "SHA256:test" || remoteAddr != "10.0.0.1" {
				t.Fatalf("request args = %q %q", sshFingerprint, remoteAddr)
			}
			if timeout != 5*time.Minute {
				t.Fatalf("timeout = %v, want 5m", timeout)
			}
			return true, nil
		},
	}

	ok, err := svc.Approve("SHA256:test", "10.0.0.1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if !ok {
		t.Fatal("Approve() = false, want true")
	}
	if !called {
		t.Fatal("Approve() did not call RequestTokenProvisioning")
	}
}

func TestServiceApproveContextUsesContextRequester(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	svc := Service{
		Now: func() time.Time {
			return time.Unix(0, 12345)
		},
		RequestTokenProvisioningContext: func(gotCtx context.Context, requestID, sshFingerprint, remoteAddr string, timeout time.Duration) (bool, error) {
			called = true
			if gotCtx != ctx {
				t.Fatal("ApproveContext did not pass through caller context")
			}
			if requestID != "token-12345" {
				t.Fatalf("requestID = %q, want token-12345", requestID)
			}
			return false, gotCtx.Err()
		},
	}

	ok, err := svc.ApproveContext(ctx, "SHA256:test", "10.0.0.1")
	if err == nil {
		t.Fatal("ApproveContext() error = nil, want canceled context error")
	}
	if ok {
		t.Fatal("ApproveContext() = true, want false")
	}
	if !called {
		t.Fatal("ApproveContext did not call RequestTokenProvisioningContext")
	}
}

func TestServiceIssueLoadsExistingToken(t *testing.T) {
	root := t.TempDir()
	tokenPath := tokenfile.GetAPlaneTokenPathForRoot(root)
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := tokenfile.WriteToken(tokenPath, "existing-token"); err != nil {
		t.Fatal(err)
	}
	svc := Service{TokenRoot: root}

	token1, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if token1 != "existing-token" {
		t.Fatalf("Issue() token = %q, want existing-token", token1)
	}

	token2, err := svc.Issue()
	if err != nil {
		t.Fatalf("Issue() second call error = %v", err)
	}
	if token2 != token1 {
		t.Fatalf("Issue() second token = %q, want %q", token2, token1)
	}

	stored, err := tokenfile.ReadToken(tokenPath)
	if err != nil {
		t.Fatalf("ReadToken() error = %v", err)
	}
	if stored != token1 {
		t.Fatalf("stored token = %q, want %q", stored, token1)
	}
}

func TestServiceIssueDoesNotGenerateMissingToken(t *testing.T) {
	root := t.TempDir()
	svc := Service{TokenRoot: root}

	if _, err := svc.Issue(); err == nil {
		t.Fatal("Issue() error = nil, want missing-token error")
	}
	if _, err := os.Stat(tokenfile.GetAPlaneTokenPathForRoot(root)); !os.IsNotExist(err) {
		t.Fatalf("Issue() generated a token, stat error = %v", err)
	}
}

func TestServiceAuditProvisionedDelegates(t *testing.T) {
	audit := &auditRecorder{}
	var gotLog string
	svc := Service{
		AuditLog: audit,
		Logf: func(format string, args ...interface{}) {
			gotLog = fmt.Sprintf(format, args...)
		},
	}

	svc.AuditProvisioned("SHA256:test", "10.0.0.1")
	if audit.identityID != productmode.IdentityID || audit.sshFingerprint != "SHA256:test" || audit.remoteAddr != "10.0.0.1" {
		t.Fatalf("audit = %#v", audit)
	}
	if gotLog != `token provisioned for identity "default" to 10.0.0.1 (key: SHA256:test)` {
		t.Fatalf("log format = %q", gotLog)
	}
}
