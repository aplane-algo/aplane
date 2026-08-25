// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storeadmin

import (
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/lsig"
)

type auditEvent struct {
	kind   string
	reason string
}

type recordingAuditLog struct {
	events []auditEvent
}

func (l *recordingAuditLog) LogStoreInitialized(metadataDir string) {
	l.events = append(l.events, auditEvent{kind: "store_initialized"})
}

func (l *recordingAuditLog) LogStoreInitializeFailed(reason string) {
	l.events = append(l.events, auditEvent{kind: "store_initialize_failed", reason: reason})
}

func (l *recordingAuditLog) LogPassphraseChanged(_, _ int) {
	l.events = append(l.events, auditEvent{kind: "passphrase_changed"})
}

func (l *recordingAuditLog) LogPassphraseChangeFailed(reason string) {
	l.events = append(l.events, auditEvent{kind: "passphrase_change_failed", reason: reason})
}

func TestInitializeStoreRejectsNilRuntime(t *testing.T) {
	result := Service{}.InitializeStore(nil, adminproto.InitializeStoreRequest{
		Passphrase: []byte("passphrase"),
	})
	if result.Code != protocol.ErrCodeNoRuntimeBound {
		t.Fatalf("Code = %q, want %q", result.Code, protocol.ErrCodeNoRuntimeBound)
	}
}

func TestInitializeStoreRejectsEmptyPassphraseAndAudits(t *testing.T) {
	audit := &recordingAuditLog{}
	ir := testIdentityRuntime()

	result := Service{AuditLog: audit}.InitializeStore(ir, adminproto.InitializeStoreRequest{})
	if result.Code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("Code = %q, want %q", result.Code, protocol.ErrCodeInvalidPassphrase)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %#v, want one event", audit.events)
	}
	if got := audit.events[0]; got.kind != "store_initialize_failed" || got.reason != "passphrase is required" {
		t.Fatalf("audit event = %#v, want product store initialize failure", got)
	}
}

type initializeTestDeps struct {
	dataDir string
	paths   storepaths.Paths
	cfg     serverconfig.ServerConfig
	mu      sync.Mutex
}

func (d *initializeTestDeps) DataDir() string                    { return d.dataDir }
func (d *initializeTestDeps) Config() *serverconfig.ServerConfig { return &d.cfg }
func (d *initializeTestDeps) KeyPaths() storepaths.Paths         { return d.paths }
func (d *initializeTestDeps) Logf(string, ...interface{})        {}
func (d *initializeTestDeps) WithStoreMutation(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fn()
}

func TestInitializeStoreReleasesMutationLockBeforeUnlock(t *testing.T) {
	lsig.RegisterClient()
	dataDir := t.TempDir()
	deps := &initializeTestDeps{
		dataDir: dataDir,
		paths:   storepaths.NewPaths(dataDir),
	}
	ir := testIdentityRuntime()
	unlockCalled := false
	service := Service{
		Deps: deps,
		UnlockIdentity: func(
			_ *productruntime.Runtime,
			_ []byte,
		) (bool, int, string, string) {
			unlockCalled = true
			if err := deps.WithStoreMutation(func() error {
				return nil
			}); err != nil {
				return false, 0, err.Error(), ""
			}
			return true, 0, "", ""
		},
	}
	done := make(chan adminproto.InitializeStoreResult, 1)
	go func() {
		done <- service.InitializeStore(ir, adminproto.InitializeStoreRequest{
			Passphrase: []byte("initialize-passphrase"),
		})
	}()

	select {
	case result := <-done:
		if !result.Success {
			t.Fatalf("InitializeStore() result = %#v", result)
		}
		if !unlockCalled {
			t.Fatal("InitializeStore() did not invoke unlock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("InitializeStore() deadlocked by re-entering the store mutation lock")
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
			ir := testIdentityRuntime()

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
			if got := audit.events[0]; got.kind != "passphrase_change_failed" || got.reason != tt.want {
				t.Fatalf("audit event = %#v, want product passphrase change failure", got)
			}
		})
	}
}

func TestPassphraseCommandConfigFromUnlock(t *testing.T) {
	if got := passphraseCommandConfigFromUnlock(nil); got != nil {
		t.Fatalf("nil unlock config produced %#v, want nil", got)
	}
	if got := passphraseCommandConfigFromUnlock(&unlockconfig.UnlockConfig{}); got != nil {
		t.Fatalf("empty unlock config produced %#v, want nil", got)
	}

	got := passphraseCommandConfigFromUnlock(&unlockconfig.UnlockConfig{
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

func testIdentityRuntime() *productruntime.Runtime {
	return productruntime.New(productruntime.Config{

		Authenticator: auth.NewTokenAuthenticator("test-token"),
		ApprovalWait:  serverconfig.DefaultApprovalWait,
	})
}
