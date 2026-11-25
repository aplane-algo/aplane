// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/signerapp/storevalidate"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/storeinit"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// auditedSigner is a characterized signer with an audit log of its own.
func auditedSigner(t *testing.T) (*Signer, string) {
	t.Helper()
	server := characterizedSigner(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	server.auditLog = logger
	return server, path
}

// unlockRecords is the outcome, code and principal of each recorded unlock.
func unlockRecords(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, e := range auditEntries(t, path, "IDENTITY_UNLOCKED") {
		code := ""
		if e["result_code"] != nil {
			code = e["result_code"].(string)
		}
		out = append(out, fmt.Sprintf("%v %s by %v", e["outcome"], code, e["principal"]))
	}
	return out
}

// An unlock request is recorded by how it ended, attributed to the session
// that asked. One that found the signer unlocked changed nothing: only a
// refusal of its passphrase is recorded.
func TestUnlockRequestsAreRecorded(t *testing.T) {
	validation := fmt.Errorf("the store would not load: %w", fmt.Errorf("%w: 1 malformed key file(s)", signertemplates.ErrGenerationValidation))
	for _, tc := range []struct {
		name       string
		unlocked   bool
		passphrase []byte
		load       func(*productruntime.Runtime) error
		want       string
	}{
		{name: "unlocks", want: "unlocked  by admin-principal"},
		{name: "wrong passphrase", passphrase: []byte("not the passphrase"), want: "failed invalid_passphrase by admin-principal"},
		{name: "lost to a lock", load: func(ir *productruntime.Runtime) error { ir.Lock(); return nil }, want: "failed unlock_failed by admin-principal"},
		{name: "enters recovery", load: func(*productruntime.Runtime) error { return validation }, want: "recovery recovery_blocked by admin-principal"},
		{name: "load fails", load: func(*productruntime.Runtime) error { return errors.New("injected") }, want: "failed unlock_failed by admin-principal"},
		{name: "already unlocked", unlocked: true},
		{name: "already unlocked, wrong passphrase", unlocked: true, passphrase: []byte("not the passphrase"), want: "failed invalid_passphrase by admin-principal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, path := auditedSigner(t)
			ir := server.productRuntime()
			if !tc.unlocked {
				ir.Lock()
			}
			if tc.load != nil {
				wireBuildWith(server, func(fromPassphrase bool) error {
					if fromPassphrase {
						return tc.load(ir)
					}
					return nil
				})
			}
			passphrase := tc.passphrase
			if passphrase == nil {
				passphrase = testPassphrase
			}
			ctx := adminserver.WithSessionContext(context.Background(), adminserver.SessionContext{
				SessionID: "s-1", Origin: adminserver.OriginLocal, AdminPrincipal: adminserver.SessionPrincipal{ID: "admin-principal"},
			})
			server.adminServices().UnlockIdentity(ctx, passphrase)
			var want []string
			if tc.want != "" {
				want = []string{tc.want}
			}
			if got := unlockRecords(t, path); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("recorded %v, want %v", got, want)
			}
		})
	}
}

// The unlock at startup has no session: it is the product principal's, and
// recorded whether or not the daemon then starts.
func TestTheStartupUnlockIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		load error
		want string
	}{
		{nil, "[unlocked  by system:product-admin]"},
		{errors.New("injected"), "[failed unlock_failed by system:product-admin]"},
	} {
		server, path := auditedSigner(t)
		server.productRuntime().Lock()
		wireBuildWith(server, func(bool) error { return tc.load })
		if started := server.unlockAtStartup(server.productRuntime(), append([]byte(nil), testPassphrase...)); started != (tc.load == nil) {
			t.Fatalf("unlockAtStartup() = %t with load error %v", started, tc.load)
		}
		if got := fmt.Sprint(unlockRecords(t, path)); got != tc.want {
			t.Fatalf("recorded %s, want %s", got, tc.want)
		}
	}
}

// A startup passphrase is checked before there is a runtime to unlock. One the
// store refuses, or cannot be opened to check, is recorded before the daemon
// exits. A startup that fails for anything else tried no unlock.
func TestAStartupPassphraseTheStoreRefusesIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		damage       bool
		config       string
		want         string
	}{
		{name: "wrong", reason: "TEST_PASSPHRASE does not open the existing keystore", want: "[failed invalid_passphrase by system:product-admin]"},
		{name: "unreadable root", damage: true, reason: "store root could not be opened to check TEST_PASSPHRASE", want: "[failed unlock_failed by system:product-admin]"},
		{name: "another failure", config: "require_memory_protection: true\n", reason: "startup validation failed", want: "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := signerLockDir(t)
			paths := storepaths.NewPaths(dir)
			if _, err := storeinit.Initialize([]byte("startup-passphrase"), storeinit.Options{
				ValidateCandidate: storevalidate.FirstGeneration, DataDir: dir, Paths: paths,
			}); err != nil {
				t.Fatal(err)
			}
			if tc.damage {
				if err := os.WriteFile(paths.StoreRootPath(), []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			config, err := os.OpenFile(filepath.Join(dir, "config.yaml"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := config.WriteString(tc.config); err != nil {
				t.Fatal(err)
			}
			if err := config.Close(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("DISABLE_MEMORY_LOCK", "1")
			t.Setenv("TEST_PASSPHRASE", "not the passphrase")
			requireRunRefuses(t, dir, tc.reason)
			if got := fmt.Sprint(unlockRecords(t, filepath.Join(dir, "audit.log"))); got != tc.want {
				t.Fatalf("recorded %s, want %s", got, tc.want)
			}
		})
	}
}

// An admin login records a wrong passphrase, with nobody to attribute it to,
// and then the unlock its right one makes, attributed to the principal that
// login is for, which the session does not hold yet.
func TestAnAdminLoginRecordsItsFailuresAndItsUnlock(t *testing.T) {
	server, path := auditedSigner(t)
	ir := server.productRuntime()
	ir.Lock()
	frame := func(passphrase string) []byte {
		raw, err := json.Marshal(protocol.AuthMessage{
			BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeAuth},
			Passphrase:      protocol.NewSensitiveBytes(passphrase),
			ProtocolVersion: protocol.AdminProtocolVersion,
		})
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	input := append(frame("not the passphrase"), frame(string(testPassphrase))...)
	conn := adminproto.NewUnixAdminConnWithReader(&hubStubConn{}, protocol.NewFrameReader(bytes.NewReader(input)))
	session := adminserver.NewSession(conn, server.adminSessionDeps(), adminserver.OriginLocal)
	if got := session.AuthenticateOutcome(); got != adminserver.AuthOutcomeAuthenticated {
		t.Fatalf("AuthenticateOutcome() = %v, want authenticated", got)
	}
	failed := auditEntries(t, path, "ADMIN_LOGIN_FAILED")
	if len(failed) != 1 || failed[0]["reason"] != "wrong passphrase" || failed[0]["principal"] != nil || failed[0]["transport"] != "ipc" {
		t.Fatalf("login failures = %v", failed)
	}
	if got := fmt.Sprint(unlockRecords(t, path)); got != "[unlocked  by system:product-admin]" {
		t.Fatalf("unlocks = %s", got)
	}
	if id := session.SessionContext().SessionID; failed[0]["admin_session_id"] != id || auditEntries(t, path, "IDENTITY_UNLOCKED")[0]["admin_session_id"] != id {
		t.Fatalf("the entries do not name session %s", id)
	}
}
