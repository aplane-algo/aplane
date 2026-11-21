// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/sourcetokens"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// convertTestSignerToGenerational remains as a test-call-site compatibility
// helper while all daemon fixtures are initialized directly in the atomic
// store-root layout.
func convertTestSignerToGenerational(t *testing.T, server *Signer) string {
	t.Helper()
	selection, kr, err := genstore.OpenStoreRootSelection(server.keyPaths, testPassphrase)
	if err != nil {
		t.Fatalf("OpenStoreRootSelection: %v", err)
	}
	kr.Zero()
	return selection.GenerationID()
}

func TestReconcileGenerationQuarantineRequiresAndRecordsDurableAudit(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	selection, keyring, err := genstore.OpenStoreRootSelection(server.keyPaths, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Zero()
	current := selection.GenerationID()
	successor, err := genstore.NewGenerationID(time.Unix(1_753_800_001, 0))
	if err != nil {
		t.Fatal(err)
	}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if op == fsutil.OpRename && path == server.keyPaths.StoreRootPath() {
			return errors.New("injected pre-flip crash")
		}
		return nil
	}
	_, mintErr := genstore.Mint(server.keyPaths, genstore.MintRequest{
		SkipCandidateValidation: true,
		GenerationID:            successor,
		Parent:                  current,
		Integrity:               keyring,
		Operation:               "test-quarantine-audit",
		OperationID:             "op-" + successor,
		CreatedAt:               time.Unix(1_753_800_001, 0),
	})
	fsutil.TestHook = nil
	if mintErr == nil {
		t.Fatal("Mint succeeded despite injected pre-flip crash")
	}

	if err := server.adminServices().reconcileGenerations(server.runtime, testPassphrase); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(server.keyPaths.QuarantinedGenerationDir(successor)); err != nil {
		t.Fatalf("successor was not quarantined: %v", err)
	}
	auditBytes, err := os.ReadFile(filepath.Join(server.dataDir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	auditText := string(auditBytes)
	intent := strings.Index(auditText, "GENERATION_QUARANTINE_INTENT")
	outcome := strings.Index(auditText, "GENERATION_QUARANTINED")
	if intent < 0 || outcome < 0 || intent >= outcome {
		t.Fatalf("quarantine audit intent/outcome ordering missing: %s", auditText)
	}
	if !strings.Contains(auditText, `"generation_id":"`+successor+`"`) {
		t.Fatalf("quarantine audit missing generation ID %s: %s", successor, auditText)
	}
}

func TestUnlockFailsClosedOnMalformedGenerationContent(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()
	generationID := convertTestSignerToGenerational(t, server)

	// A malformed credential inside the selected generation: structural
	// validation passes (regular file), content validation must fail closed.
	gen := server.keyPaths.GenerationPaths(generationID)
	garbage := filepath.Join(gen.KeysDir(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.key")
	if err := os.WriteFile(garbage, []byte("not-an-encrypted-credential"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery (signing blocked)", ir.IsRecovery(), ir.IsUnlocked())
	}

	// Removing the defect and unlocking again succeeds normally.
	if err := os.Remove(garbage); err != nil {
		t.Fatalf("remove garbage: %v", err)
	}
	ir.Lock()
	success, _, errMsg, code = svc.UnlockIdentity(testPassphrase)
	if !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
	if !ir.IsUnlocked() {
		t.Fatal("identity not unlocked after repair")
	}
}

func TestUnlockFailsClosedOnMalformedKeyTypeRecord(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()
	generationID := convertTestSignerToGenerational(t, server)

	// A corrupt key-type state record inside the selected generation: the
	// keytypes namespace is generation content and validates fail-closed
	// exactly like keys.
	gen := server.keyPaths.GenerationPaths(generationID)
	garbage := filepath.Join(gen.KeyTypeRecordsDir(), "broken.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o660); err != nil {
		t.Fatalf("WriteFile(garbage record): %v", err)
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}

	if err := os.Remove(garbage); err != nil {
		t.Fatalf("remove garbage record: %v", err)
	}
	ir.Lock()
	if success, _, errMsg, code := svc.UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
}

func TestUnlockFailsClosedOnUnexpectedEntriesInGeneration(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if ir == nil {
		t.Fatal("expected default product runtime")
	}
	svc := server.adminServices()
	generationID := convertTestSignerToGenerational(t, server)

	// Files that are neither managed credentials nor witness artifacts are
	// unaccounted-for content: strict validation treats them as defects, in
	// either namespace of the selected generation.
	gen := server.keyPaths.GenerationPaths(generationID)
	strays := []string{
		filepath.Join(gen.KeysDir(), "notes.txt"),
		filepath.Join(gen.KeyTypeRecordsDir(), "backup.tar"),
	}
	for _, stray := range strays {
		if err := os.WriteFile(stray, []byte("stray"), 0o660); err != nil {
			t.Fatalf("WriteFile(%s): %v", stray, err)
		}
	}
	ir.Lock()

	success, keyCount, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
		t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery entry", success, keyCount, errMsg, code)
	}
	if !ir.IsRecovery() || ir.IsUnlocked() {
		t.Fatalf("runtime state = recovery %v unlocked %v, want recovery", ir.IsRecovery(), ir.IsUnlocked())
	}

	for _, stray := range strays {
		if err := os.Remove(stray); err != nil {
			t.Fatalf("remove %s: %v", stray, err)
		}
	}
	ir.Lock()
	if success, _, errMsg, code := svc.UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity(repaired) = (%v, %q, %q), want clean unlock", success, errMsg, code)
	}
}

// A reconcile that fails enters recovery before it releases the store
// mutation lock (RB2), not after: until then the runtime may still serve a
// generation behind the store root, and another mutation could take the lock.
func TestAFailedReconcileEntersRecoveryBeforeReleasingTheLock(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.runtime
	ir.SetUnlocked()
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("simulated reload failure")
	})

	// reconcileLocked is the work reconcileReloadAndPromote runs under the
	// store mutation lock: the runtime must be in recovery when it returns,
	// before the lock around it is released.
	if _, err := server.adminServices().reconcileLocked(ir, true); err == nil {
		t.Fatal("the reconcile succeeded though its reload failed")
	}
	if !ir.IsRecovery() {
		t.Fatalf("state = %v when the locked work returned, want recovery", ir.GetState())
	}

	// Through the lock, the outcome is the same.
	ir.SetUnlocked()
	if _, err := server.adminServices().reconcileReloadAndPromote(ir, true); err == nil || !ir.IsRecovery() {
		t.Fatalf("reconcile: err = %v, state = %v; want a failure and recovery", err, ir.GetState())
	}
}

// The recovery-exit rescan after a restore or rollback leaves a lock that
// came in before it alone: a failure there keeps the signer locked rather
// than putting it back in recovery.
func TestARecoveryExitRescanKeepsALockThatCameFirst(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.runtime
	ir.SetRecovery()
	ir.Lock()
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v after Lock, want locked", ir.GetState())
	}
	if _, ok := server.adminServices().exitRecoveryIfReconciled(ir); ok {
		t.Fatal("the rescan lifted recovery on a locked signer")
	}
	if ir.GetState() != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v after the rescan, want the lock kept", ir.GetState())
	}
}

// A wrong passphrase is the only unlock failure coded invalid_passphrase. A
// store root the right passphrase cannot open is unlock_failed with its
// cause, and through the login it fails verification as something other than
// a wrong passphrase, so the login does not ask again.
func TestUnlockOfADamagedStoreRootIsNotAnInvalidPassphrase(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	svc := server.adminServices()
	ir.Lock()

	if success, _, errMsg, code := svc.UnlockIdentity([]byte("wrong passphrase")); success || code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("UnlockIdentity(wrong) = (%v, %q, %q), want invalid_passphrase", success, errMsg, code)
	}

	rootPath := filepath.Join(server.keyPaths.ProductDir(), storepaths.StoreRootName)
	if err := os.WriteFile(rootPath, []byte("not a store root"), 0o600); err != nil {
		t.Fatal(err)
	}
	success, _, errMsg, code := svc.UnlockIdentity(testPassphrase)
	if success || code != protocol.ErrCodeUnlockFailed || !strings.Contains(errMsg, "parse store root") {
		t.Fatalf("UnlockIdentity(damaged root) = (%v, %q, %q), want unlock_failed naming the cause", success, errMsg, code)
	}
	if ir.IsUnlocked() || ir.IsRecovery() {
		t.Fatalf("state = %v after a failed unlock, want locked", ir.GetState())
	}
	if err := svc.VerifyPassphrase(testPassphrase); err == nil || errors.Is(err, crypto.ErrInvalidPassphrase) {
		t.Fatalf("VerifyPassphrase(damaged root) = %v, want a store-root failure, not a wrong passphrase", err)
	}
}

// An unlock that lost a race to a lock or a store maintenance is expected and
// is not logged as an error; a store root that cannot be opened is, and a
// wrong passphrase is not logged at all.
func TestFailedUnlockLogsOnlyRealFailuresAsErrors(t *testing.T) {
	var logs *syncBuffer
	capture := func() {
		logs = &syncBuffer{}
		appLogger.SetOutput(logs)
	}
	t.Cleanup(func() { appLogger.SetOutput(os.Stderr) })

	capture()
	for _, msg := range []string{signerruntime.LockedDuringUnlockMessage, signerruntime.MaintenanceInProgressMessage} {
		if _, _, _, code := failedUnlock(msg); code != protocol.ErrCodeUnlockFailed {
			t.Fatalf("failedUnlock(%q) code = %q, want unlock_failed", msg, code)
		}
	}
	if got := logs.String(); strings.Contains(got, "[ERROR]") || !strings.Contains(got, "[INFO] unlock did not complete") {
		t.Fatalf("logs for lost unlock races = %q, want info lines only", got)
	}

	capture()
	if _, _, _, code := failedUnlock(productruntime.InvalidPassphraseMessage); code != protocol.ErrCodeInvalidPassphrase {
		t.Fatalf("failedUnlock(wrong passphrase) code = %q", code)
	}
	if got := logs.String(); got != "" {
		t.Fatalf("logs for a wrong passphrase = %q, want none", got)
	}

	capture()
	failedUnlock("store root could not be opened: parse store root: invalid character")
	if got := logs.String(); !strings.Contains(got, "[ERROR] unlock failed: store root could not be opened") {
		t.Fatalf("logs for a damaged store root = %q, want an error line with the cause", got)
	}
}

// An unlock in flight when a store change on another connection ends in
// doubt does not publish over the recovery that change entered. It publishes
// nothing and answers from the state the signer is then in: recovery_blocked
// while the recovery lasts, as an unlock that finds the store needing
// recovery does; a plain success once a reconcile on a third connection has
// lifted it; and a lost race once a lock has come in. The answer once said
// recovery_blocked whatever the state.
//
// The unlock's reload published a source token index before the fence; an
// unlock that publishes nothing leaves no tokens, as a failed unlock reload
// does, unless a reconcile has lifted the recovery and the signer is
// unlocked with them.
func TestAnUnlockThatMeetsARecoveryAnswersFromTheState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		after  func(*productruntime.Runtime)
		want   func(t *testing.T, success bool, keyCount int, errMsg, code string)
		state  signerruntime.SignerState
		tokens bool
	}{
		{
			name:  "still in recovery",
			after: func(*productruntime.Runtime) {},
			want: func(t *testing.T, success bool, keyCount int, errMsg, code string) {
				if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
					t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery_blocked", success, keyCount, errMsg, code)
				}
			},
			state: signerruntime.SignerStateRecovery,
		},
		{
			name:  "a reconcile lifted it",
			after: func(ir *productruntime.Runtime) { ir.PromoteRecoveryToUnlocked() },
			want: func(t *testing.T, success bool, keyCount int, errMsg, code string) {
				if !success || errMsg != "" || code != "" {
					t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want a plain success", success, keyCount, errMsg, code)
				}
			},
			state:  signerruntime.SignerStateUnlocked,
			tokens: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cleanup := setupTestSigner(t)
			defer cleanup()
			ir := server.productRuntime()
			ir.SetUnlocked()
			file, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "screening", []byte("tok-fenced"), time.Unix(1_785_200_000, 0))
			if err != nil {
				t.Fatal(err)
			}
			index := sourcetokens.NewIndex([]*sourcetokens.File{file})
			file.Zero()
			ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				if passphrase != nil {
					ir.SetRecovery() // the store change, while the unlock reloads
					tc.after(ir)
					ir.PublishSourceTokens(index)
				}
				return &signertemplates.ReloadReport{}, nil
			})

			success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
			tc.want(t, success, keyCount, errMsg, code)
			if got := ir.GetState(); got != tc.state {
				t.Fatalf("state = %v, want %v", got, tc.state)
			}
			got, known := ir.SourceTokenFor(sourcetokens.DefaultSelector, "screening")
			if known != tc.tokens || (tc.tokens && got != "tok-fenced") {
				t.Fatalf("SourceTokenFor() = %q, %v; want the index kept: %v", got, known, tc.tokens)
			}
			if kept, _ := index.TokenFor(sourcetokens.DefaultSelector, "screening"); !tc.tokens && strings.Trim(kept, "\x00") != "" {
				t.Fatalf("the fenced unlock's index still holds %q, want it zeroed", kept)
			}
		})
	}
}

// A fenced unlock that finds the signer locked, by a lock that came in after
// the fence, answers as an unlock that lost to a lock.
func TestAFencedUnlockAnswersALockThatCameAfter(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	ir.Lock()
	if success, _, errMsg, code := answerFencedUnlock(ir, signerruntime.RecoveryDuringUnlockMessage); success || errMsg != signerruntime.LockedDuringUnlockMessage || code != protocol.ErrCodeUnlockFailed {
		t.Fatalf("answerFencedUnlock(locked) = (%v, %q, %q), want the lost-race answer", success, errMsg, code)
	}
}
