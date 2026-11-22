// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

// A reload without a passphrase, the watcher's or an in-place write's, that
// finds the selected generation failing validation once published an empty
// key snapshot and entered nothing: the signer said unlocked and could sign
// with none of its keys. It now enters recovery, as an unlock that finds the
// defect does: signing is refused, the keyring stays for the reconcile, and
// once the defect is gone the reconcile lifts recovery. The entry is pushed
// to the admin session as a status, which takes apadmin to its recovery
// screen and so to the reconcile, and the log names its cause.

// defectSigner is an unlocked test signer with one key it signs with, an
// admin session whose messages are recorded, and a stray file in the
// selected generation's keys/, which fails that generation's validation. The
// file's name is one the watcher ignores, so nothing reloads until the test
// does. It returns the key's address, the stray path and the session's
// recorder.
func defectSigner(t *testing.T) (server *Signer, address, stray string, session *ipcJSONRecorderConn) {
	t.Helper()
	server, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	session = &ipcJSONRecorderConn{}
	server.ipcServer = newIPCServerWithActiveConn(session)
	server.hub = server.ipcServer
	ir := server.productRuntime()
	t.Cleanup(ir.StopKeyWatcher)
	server.config.UserAutoApprove = true
	ir.Config().SetUserAutoApprove(true)
	address = generateTestKey(t, server, "ed25519")
	if code := signPaymentForTest(t, server, address); code != http.StatusOK {
		t.Fatalf("/sign before the defect = %d, want 200", code)
	}
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	stray = filepath.Join(active.KeysDir(), "junk.txt")
	if err := os.WriteFile(stray, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return server, address, stray, session
}

// requireRecoveryPushed checks that the admin session was told of the entry
// into recovery: a status naming the recovery state, with no keys.
func requireRecoveryPushed(t *testing.T, session *ipcJSONRecorderConn) {
	t.Helper()
	for _, msg := range session.messages(t) {
		if msg["type"] == protocol.MsgTypeStatus && msg["state"] == signerruntime.SignerStateRecovery.String() {
			if count, _ := msg["key_count"].(float64); count != 0 {
				t.Fatalf("pushed status = %v, want no keys", msg)
			}
			return
		}
	}
	t.Fatalf("the admin session was sent %v, want a status in recovery", session.messages(t))
}

// requireRecoveryWithKeyring checks what a reload that found the defect
// leaves: recovery with no keys published, the keyring open, and /sign
// refused as a signer that is not unlocked refuses it.
func requireRecoveryWithKeyring(t *testing.T, server *Signer, address string) {
	t.Helper()
	ir := server.productRuntime()
	if got := ir.GetState(); got != signerruntime.SignerStateRecovery {
		t.Fatalf("state = %v after a reload that found a defect, want recovery", got)
	}
	if ir.KeyCount() != 0 {
		t.Fatalf("KeyCount() = %d in recovery, want 0", ir.KeyCount())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("the keyring is closed in recovery: %v", err)
	}
	if code := signPaymentForTest(t, server, address); code != http.StatusForbidden {
		t.Fatalf("/sign in recovery = %d, want 403", code)
	}
}

// requireRepairLiftsRecovery removes the stray file and runs the reconcile
// recovery needs, which lifts it with wantKeys keys published and signing.
func requireRepairLiftsRecovery(t *testing.T, server *Signer, stray, address string, wantKeys int) {
	t.Helper()
	ir := server.productRuntime()
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	if result := server.adminServices().backupServices().ReconcileStore(); !result.Success {
		t.Fatalf("ReconcileStore() = %+v, want a success", result)
	}
	if !ir.IsUnlocked() || ir.KeyCount() != wantKeys {
		t.Fatalf("after the reconcile: state %v, %d key(s); want unlocked with %d", ir.GetState(), ir.KeyCount(), wantKeys)
	}
	if code := signPaymentForTest(t, server, address); code != http.StatusOK {
		t.Fatalf("/sign after the reconcile = %d, want 200", code)
	}
}

// The reload enters recovery itself, before its caller releases the store
// mutation lock (RB2's order), so no request between the release and a later
// entry sees the empty snapshot as unlocked.
func TestAReloadThatFindsADefectEntersRecoveryUnderTheLock(t *testing.T) {
	server, address, stray, session := defectSigner(t)
	ir := server.productRuntime()

	var underLock signerruntime.SignerState
	err := server.adminServices().withStoreMutation(func() error {
		_, err := ir.Reload()
		underLock = ir.GetState()
		return err
	})
	if !signertemplates.IsGenerationValidationErr(err) {
		t.Fatalf("Reload() error = %v, want a generation validation failure", err)
	}
	if underLock != signerruntime.SignerStateRecovery {
		t.Fatalf("state = %v before the store mutation lock was released, want recovery", underLock)
	}
	requireRecoveryPushed(t, session)
	requireRecoveryWithKeyring(t, server, address)
	requireRepairLiftsRecovery(t, server, stray, address, 1)
}

// The watcher's reload, run as a change in keys/ runs it.
func TestAWatcherReloadThatFindsADefectEntersRecovery(t *testing.T) {
	server, address, stray, session := defectSigner(t)
	ir := server.productRuntime()
	var onChange func() error
	ir.EnsureKeyWatcher(func(_ []string, _ context.Context, reload func() error) error {
		onChange = reload
		return nil
	})
	if onChange == nil {
		t.Fatal("the watcher did not start")
	}

	if err := onChange(); !signertemplates.IsGenerationValidationErr(err) {
		t.Fatalf("watcher reload error = %v, want a generation validation failure", err)
	}
	requireRecoveryPushed(t, session)
	requireRecoveryWithKeyring(t, server, address)
	// In recovery a change marks the store dirty and reloads nothing.
	if err := onChange(); err != nil || !ir.IsRecovery() {
		t.Fatalf("a change in recovery = %v, state %v; want it marked dirty in recovery", err, ir.GetState())
	}
	requireRepairLiftsRecovery(t, server, stray, address, 1)
}

// Key administration's reload, after it wrote a key, the review's trigger:
// a key generation over a stray file nothing had reloaded for. The answer
// says the signer entered recovery and names the defect, where it once said
// only "failed to refresh signer key cache", and the log names it once. The
// write stands: the reconcile publishes the new key with the old one.
func TestAKeyWriteWhoseReloadFindsADefectEntersRecovery(t *testing.T) {
	server, address, stray, session := defectSigner(t)
	logs := &syncBuffer{}
	appLogger.SetOutput(logs)
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })

	result := server.adminServices().keyApp().GenerateKey(context.Background(), adminproto.GenerateKeyRequest{KeyType: "ed25519"})
	const wantPrefix = "the change was written, but the reload after it found a content defect in the selected generation, and the signer entered recovery: generation validation failed: "
	if result.Success || result.Code != protocol.ResultCodeRecoveryBlocked || !strings.HasPrefix(result.Error, wantPrefix) || !strings.Contains(result.Error, "junk.txt") {
		t.Fatalf("GenerateKey() = %+v, want recovery_blocked naming the stray file", result)
	}
	if got := logs.String(); strings.Count(got, "[WARN] identity is recovery-blocked: generation validation failed: ") != 1 || !strings.Contains(got, "junk.txt") {
		t.Fatalf("logs = %q, want one line naming the entry and its cause", got)
	}
	requireRecoveryPushed(t, session)
	requireRecoveryWithKeyring(t, server, address)
	requireRepairLiftsRecovery(t, server, stray, address, 2)
}

// Template administration's reload, after it installed a template: the
// answer is recovery_blocked with the defect, where it was reload_failed,
// so apadmin's KeyType Library ends on its recovery screen with the cause.
// The install rolls its own files back; the defect it met stays, and the
// reconcile lifts recovery once it is gone.
func TestATemplateInstallWhoseReloadFindsADefectEntersRecovery(t *testing.T) {
	server, address, stray, session := defectSigner(t)
	family := fmt.Sprintf("ipc-defect-install-%d", time.Now().UnixNano())

	result := server.adminServices().templateServices().ImportInstalledTemplate(adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: renderGenericTemplateYAML(family, 1, "Defect Install", "installed over a stray file"),
	})
	if result.Success || result.Code != protocol.ResultCodeRecoveryBlocked || !signertemplates.IsGenerationValidationError(result.Error) || !strings.Contains(result.Error, "junk.txt") {
		t.Fatalf("ImportInstalledTemplate() = %+v, want recovery_blocked naming the stray file", result)
	}
	requireRecoveryPushed(t, session)
	requireRecoveryWithKeyring(t, server, address)
	assertInstalledTemplateRemoved(t, server, testTemplateKeyType(family), templatestore.TemplateTypeGeneric)
	requireRepairLiftsRecovery(t, server, stray, address, 1)
}
