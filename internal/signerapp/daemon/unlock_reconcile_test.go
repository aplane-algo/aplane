// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerruntime "github.com/aplane-algo/aplane/internal/signerapp/runtime"
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

// mintUnselectedGenerationForTest leaves a complete successor generation that
// the store root never selected, as a crash before the root rename does. The
// next reconcile quarantines it, and refuses to without a durable audit log.
func mintUnselectedGenerationForTest(t *testing.T, server *Signer) string {
	t.Helper()
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
	return successor
}

func TestReconcileGenerationQuarantineRequiresAndRecordsDurableAudit(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	successor := mintUnselectedGenerationForTest(t, server)

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

// gatedMutationLock is the store mutation lock as the product runtime takes
// it (SetReloadMutationLock), with hooks that run on the goroutine taking it:
// before[n] ahead of the nth acquisition through the runtime, after[n] once
// that acquisition is released. An unlock request takes it first to check
// whether the signer is already unlocked and, when it is not, to reconcile
// (AnswerIfUnlocked), and then, in TryUnlock, after it has read its session
// generations, to check again and load, releasing it before its fence. The hooks land another connection's
// transition in those gaps without a sleep. Other holders of the same mutex
// (withStoreMutation) take it directly and run no hook.
type gatedMutationLock struct {
	mu      *sync.Mutex
	taken   atomic.Int32
	holding int32 // the acquisition holding mu, read and written under it
	before  map[int32]func()
	after   map[int32]func()
}

func (g *gatedMutationLock) Lock() {
	n := g.taken.Add(1)
	if hook := g.before[n]; hook != nil {
		hook()
	}
	g.mu.Lock()
	g.holding = n
}

func (g *gatedMutationLock) Unlock() {
	n := g.holding
	g.mu.Unlock()
	if hook := g.after[n]; hook != nil {
		hook()
	}
}

// gateStoreMutation installs g over the signer's store mutation lock.
func gateStoreMutation(server *Signer, g *gatedMutationLock) {
	g.mu = &server.storeMutationLock
	server.productRuntime().SetReloadMutationLock(func() sync.Locker { return g })
}

// The acquisitions an unlock request of a signer not yet unlocked makes
// through the runtime: AnswerIfUnlocked's check and reconcile, then
// TryUnlock's check and load.
const (
	unlockAnswerCheck int32 = 1
	unlockLoadCheck   int32 = 2
)

// An unlock begun in recovery, when a store change on another connection
// ends in doubt after the unlock read its session generations, does not
// publish over the recovery that change entered again. It loads, since the
// signer is not unlocked, then publishes nothing and answers from the state
// the signer is then in: recovery_blocked while the recovery lasts, as an
// unlock that finds the store needing recovery does, and a plain success once
// a reconcile on a third connection has lifted it before the fence. The
// answer once said recovery_blocked whatever the state.
//
// The store change is a reconcile that fails, which enters recovery again
// under the store mutation lock: it lands between the unlock's generation
// read and its check. The lifting reconcile lands between the end of the
// unlock's load and its fence. Neither can land during the load, which holds
// the store mutation lock.
//
// The unlock's load published a source token index before the fence. The
// fence leaves it: recovery keeps the keyring that decrypts the token files.
// No lookup uses it until the signer is unlocked, and a lock zeroes it.
func TestAnUnlockThatMeetsARecoveryAnswersFromTheState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		lifted bool
		want   func(t *testing.T, success bool, keyCount int, errMsg, code string)
		state  signerruntime.SignerState
	}{
		{
			name: "still in recovery",
			want: func(t *testing.T, success bool, keyCount int, errMsg, code string) {
				if !success || keyCount != 0 || errMsg != "" || code != protocol.ResultCodeRecoveryBlocked {
					t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want recovery_blocked", success, keyCount, errMsg, code)
				}
			},
			state: signerruntime.SignerStateRecovery,
		},
		{
			name:   "a reconcile lifted it",
			lifted: true,
			want: func(t *testing.T, success bool, keyCount int, errMsg, code string) {
				if !success || errMsg != "" || code != "" {
					t.Fatalf("UnlockIdentity() = (%v, %d, %q, %q), want a plain success", success, keyCount, errMsg, code)
				}
			},
			state: signerruntime.SignerStateUnlocked,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, cleanup := setupTestSigner(t)
			defer cleanup()
			ir := server.productRuntime()
			ir.SetRecovery() // the unlock begins in recovery
			file, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "screening", []byte("tok-fenced"), time.Unix(1_785_200_000, 0))
			if err != nil {
				t.Fatal(err)
			}
			index := sourcetokens.NewIndex([]*sourcetokens.File{file})
			file.Zero()
			loads := 0
			failReconcile := false
			ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
				if passphrase != nil {
					loads++
					ir.PublishSourceTokens(index)
					return &signertemplates.ReloadReport{}, nil
				}
				if failReconcile {
					return nil, errors.New("simulated reconcile reload failure")
				}
				return &signertemplates.ReloadReport{}, nil
			})
			reconcile := func(fail bool) {
				failReconcile = fail
				_, err := server.adminServices().reconcileReloadAndPromote(ir, true)
				if (err != nil) != fail {
					t.Errorf("reconcile(fail %v) = %v", fail, err)
				}
			}
			gate := &gatedMutationLock{
				before: map[int32]func(){unlockLoadCheck: func() {
					reconcile(true) // the store change: recovery entered again
				}},
				after: map[int32]func(){unlockLoadCheck: func() {
					if tc.lifted {
						reconcile(false) // a third connection lifts it
					}
				}},
			}
			gateStoreMutation(server, gate)

			success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
			tc.want(t, success, keyCount, errMsg, code)
			if got := ir.GetState(); got != tc.state {
				t.Fatalf("state = %v, want %v", got, tc.state)
			}
			if loads != 1 {
				t.Fatalf("the unlock loaded %d time(s), want once: it found the signer in recovery", loads)
			}
			// The fence left the index the load published intact.
			if kept, _ := index.TokenFor(sourcetokens.DefaultSelector, "screening"); kept != "tok-fenced" {
				t.Fatalf("the index holds %q after the fenced unlock, want it kept", kept)
			}
			// Its token names are answered only while the signer is
			// unlocked: a policy check in recovery reads none from it.
			unlocked := tc.state == signerruntime.SignerStateUnlocked
			if _, known := ir.SourceTokenNamesFor(sourcetokens.DefaultSelector); known != unlocked {
				t.Fatalf("SourceTokenNamesFor() known = %v, want %v", known, unlocked)
			}
			// A lock ends it: the index the load published is zeroed.
			ir.Lock()
			if _, known := ir.SourceTokenFor(sourcetokens.DefaultSelector, "screening"); known {
				t.Fatal("a locked signer still serves a source token")
			}
			if kept, _ := index.TokenFor(sourcetokens.DefaultSelector, "screening"); strings.Trim(kept, "\x00") != "" {
				t.Fatalf("the index still holds %q after a lock, want it zeroed", kept)
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

// An unlock begun in recovery whose load fails without touching the keyring
// leaves recovery the keyring and the source token index it had: tokens go
// only with the keyring that decrypts them. The real load fails that way when
// the store root does not open at its start, after the passphrase check
// passed (a read failure); the reload here fails as that one does. A load
// with a passphrase no longer runs under a session in service: an unlock of
// an unlocked signer loads nothing. Under one, the index was once cleared on
// every failure, leaving the signer unlocked with no tokens.
func TestAFailedReloadThatKeepsTheKeyringKeepsTheSourceTokens(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	file, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "screening", []byte("tok-live"), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	index := sourcetokens.NewIndex([]*sourcetokens.File{file})
	file.Zero()
	ir.PublishSourceTokens(index)
	ir.SetRecovery()

	loads := 0
	ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			loads++
		}
		return nil, errors.New("failed to unlock the keystore: injected")
	})
	if success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase); success || !strings.Contains(errMsg, "injected") {
		t.Fatalf("UnlockIdentity() = (%v, %q), want the load's failure", success, errMsg)
	}
	if loads != 1 {
		t.Fatalf("the unlock loaded %d time(s), want once", loads)
	}
	if !ir.IsRecovery() {
		t.Fatalf("state = %v after a failed load in recovery, want recovery", ir.GetState())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("recovery's keyring is closed: %v", err)
	}
	if got, ok := ir.SourceTokenFor(sourcetokens.DefaultSelector, "screening"); !ok || got != "tok-live" {
		t.Fatalf("SourceTokenFor() = %q, %v after a failed load that kept the keyring; want the tokens kept", got, ok)
	}
}

// failLoadsAfterTheKeyringOpens makes the reloads that follow fail after a
// reload with a passphrase has opened its keyring: the networks the
// configuration names no longer pass the reload's policy verification, which
// an unlock request's reconcile does not run. It returns the undo.
func failLoadsAfterTheKeyringOpens(server *Signer) (undo func()) {
	server.config.GenesisHashNetworks = map[string]string{"not-a-genesis-hash": "lab"}
	return func() { server.config.GenesisHashNetworks = nil }
}

// An unlock begun in recovery whose load fails after it opened a keyring,
// here at its policy verification, leaves recovery a keyring, the generation
// binding and the source token index. The load replaced recovery's keyring
// with one it opened from the same store root, and once closed that one on
// every failure: the signer stayed in recovery with no keyring, and the
// reconcile, restore and rollback recovery needs failed until an unlock got
// past the cause. A load now closes the keyring only when it found none open.
func TestAFailedUnlockLoadInRecoveryLeavesRecoveryAKeyring(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	defer ir.StopKeyWatcher()
	file, err := sourcetokens.SetToken(nil, sourcetokens.DefaultSelector, "screening", []byte("tok-kept"), time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	ir.PublishSourceTokens(sourcetokens.NewIndex([]*sourcetokens.File{file}))
	file.Zero()
	ir.SetRecovery()
	before, err := ir.ActivePaths()
	if err != nil {
		t.Fatalf("recovery has no generation binding before the unlock: %v", err)
	}

	undo := failLoadsAfterTheKeyringOpens(server)
	success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	undo()
	if success || code != protocol.ErrCodeUnlockFailed || !strings.Contains(errMsg, "policy verification failed") {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want the load's policy verification failure", success, errMsg, code)
	}
	if !ir.IsRecovery() {
		t.Fatalf("state = %v after a failed load in recovery, want recovery", ir.GetState())
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("recovery's keyring is closed: %v", err)
	}
	if active, err := ir.ActivePaths(); err != nil || active.GenerationID() != before.GenerationID() {
		t.Fatalf("ActivePaths() = %v, %v; want the generation %s recovery was bound to", active.GenerationID(), err, before.GenerationID())
	}
	if got, ok := ir.SourceTokenFor(sourcetokens.DefaultSelector, "screening"); !ok || got != "tok-kept" {
		t.Fatalf("SourceTokenFor() = %q, %v; want the index kept with the keyring", got, ok)
	}

	// The reconcile recovery needs runs on that keyring and lifts it.
	if result := server.adminServices().backupServices().ReconcileStore(); !result.Success || !ir.IsUnlocked() {
		t.Fatalf("ReconcileStore() = %+v, state %v; want a success that lifts recovery", result, ir.GetState())
	}
}

// A first unlock of a locked signer whose load fails after it opened the
// keyring closes that keyring again: the signer stays locked, with no keyring
// and no generation binding, as before the attempt. Once the cause is gone
// the unlock succeeds. (An unlock of an unlocked signer loads nothing:
// TestASecondUnlockKeepsTheSessionInService.)
func TestAFailedFirstUnlockLoadClosesTheKeyringItOpened(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	defer ir.StopKeyWatcher()
	ir.Lock()

	undo := failLoadsAfterTheKeyringOpens(server)
	success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	undo()
	if success || code != protocol.ErrCodeUnlockFailed || !strings.Contains(errMsg, "policy verification failed") {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want the load's policy verification failure", success, errMsg, code)
	}
	if got := ir.GetState(); got != signerruntime.SignerStateLocked {
		t.Fatalf("state = %v after a failed first unlock, want locked", got)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("WithKeyring() = %v after a failed first unlock, want the keyring the load opened closed", err)
	}
	if _, err := ir.ActivePaths(); !errors.Is(err, keystore.ErrStoreLocked) {
		t.Fatalf("ActivePaths() error = %v after a failed first unlock, want no binding", err)
	}

	if success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase); !success || !ir.IsUnlocked() {
		t.Fatalf("UnlockIdentity() once the cause is gone = (%v, %q), state %v; want unlocked", success, errMsg, ir.GetState())
	}
}

// An unlock request on a signer that is already unlocked verifies the
// passphrase and answers, and reloads nothing: the session in service keeps
// the keyring, policy, keys and tokens it has. A reload there once replaced
// the keyring under the session, and one that failed afterwards closed it.
func TestAnUnlockOfAnUnlockedSignerReloadsNothing(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	if success, _, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase); !success {
		t.Fatalf("first UnlockIdentity() failed: %s", errMsg)
	}
	generation, unlocked := ir.UnlockedGeneration()
	if !unlocked {
		t.Fatal("the signer is not unlocked after its first unlock")
	}
	reloads := 0
	ir.SetReloadFunc(func([]byte, *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		reloads++
		return nil, errors.New("injected reload failure")
	})

	success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
	if !success || errMsg != "" || code != "" || keyCount != ir.KeyCount() {
		t.Fatalf("second UnlockIdentity() = (%v, %d, %q, %q), want a plain success with the session's key count", success, keyCount, errMsg, code)
	}
	if reloads != 0 {
		t.Fatalf("the second unlock ran %d reload(s), want none", reloads)
	}
	if !ir.IsUnlockedIn(generation) {
		t.Fatal("the second unlock ended the session in service")
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("the session's keyring is closed: %v", err)
	}

	// A wrong passphrase is refused, and leaves the session as it was.
	wrong := []byte("not-the-passphrase")
	if success, _, errMsg, _ := server.adminServices().UnlockIdentity(wrong); success || errMsg == "" {
		t.Fatalf("UnlockIdentity(wrong passphrase) on an unlocked signer = (%v, %q), want a refusal", success, errMsg)
	}
	if reloads != 0 || !ir.IsUnlockedIn(generation) {
		t.Fatalf("a refused unlock ran %d reload(s) or ended the session", reloads)
	}
	if err := ir.WithKeyring(func(*crypto.Keyring) error { return nil }); err != nil {
		t.Fatalf("a refused unlock closed the session's keyring: %v", err)
	}
}

// Two unlocks of a locked signer at once load once. The second begins after
// the first has loaded and before it publishes, finds the signer not yet
// unlocked at its first check, and waits for the first to publish (TryUnlock
// runs attempts one at a time); it then finds the signer unlocked at its
// second check and answers from the session.
func TestTwoUnlocksAtOnceReloadOnce(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	// The test signer starts unlocked; these unlocks begin from locked.
	ir.Lock()
	if ir.IsUnlocked() {
		t.Fatal("the signer is still unlocked after a lock")
	}
	var loads atomic.Int32
	ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			loads.Add(1)
		}
		return &signertemplates.ReloadReport{}, nil
	})
	type outcome struct {
		success  bool
		keyCount int
		errMsg   string
	}
	unlock := func(results chan<- outcome) {
		success, keyCount, errMsg, _ := server.adminServices().UnlockIdentity(testPassphrase)
		results <- outcome{success, keyCount, errMsg}
	}
	second := make(chan outcome, 1)
	secondChecked := make(chan bool, 1)
	secondSawUnlocked := true
	// The first unlock makes acquisitions 1 and 2. Once its load has
	// released the lock, and before its fence, the second begins, and its
	// first check is acquisition 3: no other holder takes the lock through
	// the runtime before the first unlock publishes and starts the watcher.
	gate := &gatedMutationLock{after: map[int32]func(){
		unlockLoadCheck: func() {
			go unlock(second)
			secondSawUnlocked = <-secondChecked
		},
		unlockLoadCheck + unlockAnswerCheck: func() {
			secondChecked <- ir.IsUnlocked()
		},
	}}
	gateStoreMutation(server, gate)

	first := make(chan outcome, 1)
	unlock(first)
	for name, results := range map[string]chan outcome{"first": first, "second": second} {
		if got := <-results; !got.success || got.errMsg != "" {
			t.Fatalf("the %s unlock = %+v, want a success", name, got)
		}
	}
	if secondSawUnlocked {
		t.Fatal("the second unlock began after the first had published; want it to begin before")
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("%d loads for two unlocks at once, want 1", got)
	}
	if !ir.IsUnlocked() {
		t.Fatal("the signer is not unlocked")
	}
}

// Two unlock requests on a locked signer: the second finds the signer not
// unlocked, the first publishes, and the second's reconcile fails. The second
// once entered recovery all the same (TryRecoveryUnlock), which ended the
// session the first had just published. It now checks again before it enters
// recovery, and answers from the session it finds, as a request that found
// the signer unlocked does.
//
// The second's reconcile fails because a generation the store root never
// selected appears after the first's reconcile, and there is no audit log to
// record its quarantine.
func TestAFailedReconcileLeavesASessionPublishedBesideIt(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	ir.Lock() // the test signer starts unlocked; these unlocks begin from locked
	auditLog := server.auditLog
	defer func() { server.auditLog = auditLog }()
	minted := false
	ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil && !minted {
			minted = true
			mintUnselectedGenerationForTest(t, server)
			server.auditLog = nil
		}
		return &signertemplates.ReloadReport{}, nil
	})
	type outcome struct {
		success      bool
		keyCount     int
		errMsg, code string
	}
	unlock := func(results chan<- outcome) {
		success, keyCount, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase)
		results <- outcome{success, keyCount, errMsg, code}
	}
	first, second := make(chan outcome, 1), make(chan outcome, 1)
	firstLoaded := make(chan struct{})
	var firstGot outcome
	var published uint64
	gate := &gatedMutationLock{after: map[int32]func(){
		// The first has reconciled and loaded, and not yet published.
		unlockLoadCheck: func() {
			go unlock(second)
			<-firstLoaded
		},
		// The second has found the signer not unlocked: the first publishes.
		unlockLoadCheck + unlockAnswerCheck: func() {
			close(firstLoaded)
			firstGot = <-first
			published, _ = ir.UnlockedGeneration()
		},
	}}
	gateStoreMutation(server, gate)

	unlock(first)
	secondGot := <-second
	if !firstGot.success || firstGot.errMsg != "" || firstGot.code != "" {
		t.Fatalf("the first unlock = %+v, want a plain success", firstGot)
	}
	if !secondGot.success || secondGot.errMsg != "" || secondGot.code != "" {
		t.Fatalf("the second unlock = %+v, want a plain success from the first's session", secondGot)
	}
	if !ir.IsUnlockedIn(published) {
		t.Fatalf("state = %v: the second unlock ended the session the first published", ir.GetState())
	}
}

// A reconcile that reaches the store mutation lock on a signer that is
// neither unlocked nor in recovery is refused there, before it reloads, and
// enters no recovery. The handler's state check runs before the request
// queues on the lock, and an unlock from locked whose load has ended and
// that has not yet published leaves the keyring open on a locked signer. A
// reconcile there once reloaded, and when the reload failed it called
// SetRecovery, which does nothing on a locked signer; the unlock then
// published unlocked over the failed reload.
func TestAReconcileOfALockedSignerIsRefusedUnderTheLock(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	ir.Lock()
	var reloads atomic.Int32 // without a passphrase: the reconcile's, and the watcher's after the publish
	ir.SetReloadFunc(func(passphrase []byte, _ *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		if passphrase != nil {
			return &signertemplates.ReloadReport{}, ir.KeyStore().Unlock(passphrase)
		}
		reloads.Add(1)
		return nil, errors.New("simulated reconcile reload failure")
	})
	var reconcileErr error
	var reconcileReloads int32
	gateStoreMutation(server, &gatedMutationLock{after: map[int32]func(){
		unlockLoadCheck: func() {
			_, reconcileErr = server.adminServices().reconcileReloadAndPromote(ir, true)
			reconcileReloads = reloads.Load()
		},
	}})

	if success, _, errMsg, code := server.adminServices().UnlockIdentity(testPassphrase); !success || errMsg != "" || code != "" {
		t.Fatalf("UnlockIdentity() = (%v, %q, %q), want a plain success", success, errMsg, code)
	}
	if !errors.Is(reconcileErr, keystore.ErrStoreLocked) {
		t.Fatalf("reconcile on the locked signer = %v, want a refusal as locked", reconcileErr)
	}
	if reconcileReloads != 0 {
		t.Fatalf("the refused reconcile reloaded %d time(s), want none", reconcileReloads)
	}
	if !ir.IsUnlocked() {
		t.Fatalf("state = %v, want the unlock published", ir.GetState())
	}
}

// A reconcile refused under the lock because the signer is locked answers
// as locked, not as recovery: nothing was reconciled and no recovery was
// entered, so a client must not show a recovery screen for it.
func TestAReconcileRefusedForALockedSignerAnswersLocked(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	ir.Lock()
	result := server.adminServices().backupServices().ReconcileStore()
	if result.Success || result.Code != protocol.ErrCodeSignerLocked || result.State != signerruntime.SignerStateLocked.String() {
		t.Fatalf("ReconcileStore() on a locked signer = %+v, want signer_locked and state locked", result)
	}
	if ir.IsRecovery() {
		t.Fatal("a refused reconcile entered recovery")
	}
}
