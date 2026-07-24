// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeadmin

import (
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

type auditEvent struct {
	kind     string
	identity string
	reason   string
}

type recordingAuditLog struct {
	events []auditEvent
}

func (l *recordingAuditLog) LogStoreInitialized(identityID, metadataDir string) {
	l.events = append(l.events, auditEvent{kind: "store_initialized", identity: identityID})
}

func (l *recordingAuditLog) LogStoreInitializeFailed(identityID, reason string) {
	l.events = append(l.events, auditEvent{kind: "store_initialize_failed", identity: identityID, reason: reason})
}

func (l *recordingAuditLog) LogPassphraseChanged(identityID string, _, _, _ int) {
	l.events = append(l.events, auditEvent{kind: "passphrase_changed", identity: identityID})
}

func (l *recordingAuditLog) LogPassphraseChangeFailed(identityID, reason string) {
	l.events = append(l.events, auditEvent{kind: "passphrase_change_failed", identity: identityID, reason: reason})
}

func TestInitializeStoreRejectsNilRuntime(t *testing.T) {
	result := Service{}.InitializeStore(nil, adminproto.InitializeStoreRequest{
		Passphrase: []byte("passphrase"),
	})
	if result.Code != protocol.ErrCodeNoIdentityBound {
		t.Fatalf("Code = %q, want %q", result.Code, protocol.ErrCodeNoIdentityBound)
	}
}

func TestInitializeStoreRejectsEmptyPassphraseAndAudits(t *testing.T) {
	audit := &recordingAuditLog{}
	ir := testIdentityRuntime("alice")

	result := Service{AuditLog: audit}.InitializeStore(ir, adminproto.InitializeStoreRequest{})
	if result.Code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("Code = %q, want %q", result.Code, protocol.ErrCodeInvalidPassphrase)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %#v, want one event", audit.events)
	}
	if got := audit.events[0]; got.kind != "store_initialize_failed" || got.identity != "alice" || got.reason != "passphrase is required" {
		t.Fatalf("audit event = %#v, want store initialize failure for alice", got)
	}
}

func TestChangeStorePassphraseRejectsInvalidInputsAndAudits(t *testing.T) {
	tests := []struct {
		name string
		req  adminproto.ChangeStorePassphraseRequest
		want string
	}{
		{
			name: "missing current",
			req: adminproto.ChangeStorePassphraseRequest{
				NewPassphrase: []byte("new-passphrase"),
			},
			want: "current and new passphrases are required",
		},
		{
			name: "missing new",
			req: adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: []byte("current-passphrase"),
			},
			want: "current and new passphrases are required",
		},
		{
			name: "same passphrase",
			req: adminproto.ChangeStorePassphraseRequest{
				CurrentPassphrase: []byte("same-passphrase"),
				NewPassphrase:     []byte("same-passphrase"),
			},
			want: "new passphrase must be different from current passphrase",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audit := &recordingAuditLog{}
			ir := testIdentityRuntime("alice")

			result := Service{AuditLog: audit}.ChangeStorePassphrase(ir, tt.req)
			if result.Code != "invalid_passphrase" {
				t.Fatalf("Code = %q, want invalid_passphrase", result.Code)
			}
			if result.Error != tt.want {
				t.Fatalf("Error = %q, want %q", result.Error, tt.want)
			}
			if len(audit.events) != 1 {
				t.Fatalf("audit events = %#v, want one event", audit.events)
			}
			if got := audit.events[0]; got.kind != "passphrase_change_failed" || got.identity != "alice" || got.reason != tt.want {
				t.Fatalf("audit event = %#v, want passphrase change failure for alice", got)
			}
		})
	}
}

func TestPassphraseCommandConfigFromUnlock(t *testing.T) {
	if got := passphraseCommandConfigFromUnlock(nil); got != nil {
		t.Fatalf("nil unlock config produced %#v, want nil", got)
	}
	if got := passphraseCommandConfigFromUnlock(&identity.UnlockConfig{}); got != nil {
		t.Fatalf("empty unlock config produced %#v, want nil", got)
	}

	got := passphraseCommandConfigFromUnlock(&identity.UnlockConfig{
		PassphraseCommandArgv: []string{"/bin/helper", "read"},
		PassphraseCommandEnv:  map[string]string{"TOKEN": "abc"},
	})
	if got == nil {
		t.Fatal("passphrase command config = nil, want config")
		return
	}
	if len(got.Argv) != 2 || got.Argv[0] != "/bin/helper" || got.Argv[1] != "read" {
		t.Fatalf("Argv = %#v, want helper argv", got.Argv)
	}
	if got.Env["TOKEN"] != "abc" {
		t.Fatalf("Env = %#v, want TOKEN", got.Env)
	}
}

func testIdentityRuntime(id string) *identity.Runtime {
	return identity.New(identity.Config{
		ID:            id,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ApprovalWait:  serverconfig.DefaultApprovalWait,
	})
}
