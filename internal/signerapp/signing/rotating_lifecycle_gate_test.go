// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// afterKeyLoad runs a hook once the sign path has copied the seed out of the
// store, the point from which nothing else revokes that copy. The hook arms
// on the chain read that comes just before the load.
type afterKeyLoad struct {
	base  *rotatingKeyStore
	armed bool
	hook  func()
}

func (s *afterKeyLoad) Get(ctx context.Context, account string) (*coresigning.KeyMaterial, error) {
	key, err := s.base.Get(ctx, account)
	if err == nil && s.armed {
		s.armed = false
		s.hook()
	}
	return key, err
}

type armingChain struct {
	base  *fakeRotatingChain
	store *afterKeyLoad
}

func (c *armingChain) ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error) {
	view, err := c.base.ReadAccount(ctx, genesisHash, account)
	c.store.armed = true
	return view, err
}

// signWithHook signs through a session whose seed load runs hook.
func signWithHook(t *testing.T, f *rotatingFixture, ctx context.Context, txns []string, hook func()) (*signerapi.RotatingSignResponse, *ServiceError) {
	t.Helper()
	store := &afterKeyLoad{base: f.store, hook: hook}
	session := keystore.NewKeySession(store)
	session.InitializeSession()
	t.Cleanup(session.Destroy)
	f.svc.Rotating.Chain = &armingChain{base: f.chain, store: store}
	return f.svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: f.account.String(), Transactions: txns}, session)
}

// A transition after the seed loads must stop the signature for every family,
// not only the one whose signing is slow.
func TestRotatingSignStopsAtALifecycleChange(t *testing.T) {
	for _, kind := range rotatingTestTypes {
		for _, mode := range []string{"locked", "cancelled", "lock generation"} {
			t.Run(kind.keyType+"/"+mode, func(t *testing.T) {
				f, audit := newSigningFixtureFor(t, kind)
				prep := mustPrepare(t, f, f.spend(1000, 1100))
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				ran := false
				resp, err := signWithHook(t, f, ctx, prep.Transactions, func() {
					ran = true
					switch mode {
					case "locked":
						f.svc.IsUnlocked = func() bool { return false }
					case "cancelled":
						cancel()
					case "lock generation":
						f.lockGen++
					}
				})
				if !ran {
					t.Fatal("the transition never ran")
				}
				if resp != nil || err == nil {
					t.Fatalf("released %d transactions after the transition", len(resp.Signed))
				}
				want := ErrorLocked
				if mode == "cancelled" {
					want = ErrorUnavailable
				}
				if err.Kind != want {
					t.Fatalf("error = %v, want kind %v", err, want)
				}
				if len(audit.releases) != 0 {
					t.Fatalf("a refused signature was audited as released: %+v", audit.releases)
				}
				if _, held := f.svc.Rotating.Releases.Get(f.account.String()); held {
					t.Fatal("a refused signature was remembered as released")
				}
			})
		}
	}
}

// The seed has to be gone before the audit write, and a lock arriving during
// that write still has to stop the signature. The release stays on record, which
// only makes its leaf look used.
func TestRotatingSignEndsItsKeyUseBeforeTheAuditWrite(t *testing.T) {
	f, audit := newSigningFixtureFor(t, wotscTestType)
	active := 0
	f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
		active++
		useCtx, cancel := context.WithCancel(ctx)
		return useCtx, func() {
			active--
			cancel()
		}
	}
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	active = 0
	audit.onRelease = func() {
		if active != 0 {
			t.Error("the audit write ran while the seed was held")
		}
		f.svc.IsUnlocked = func() bool { return false }
	}
	resp, err := f.sign(t, prep.Transactions)
	if resp != nil || err == nil || err.Kind != ErrorLocked {
		t.Fatalf("response %v, error %v, want a lock refusal", resp, err)
	}
	if rec, held := f.svc.Rotating.Releases.Get(f.account.String()); !held || len(rec.Leaves) != 1 {
		t.Fatalf("the leaf isn't on record as used: %+v", rec)
	}
}

// groupWithPick builds a second spend of the same stage whose TxID picks leaf.
func groupWithPick(t *testing.T, f *rotatingFixture, prep *signerapi.RotatingPrepareResponse, leaf uint32) []string {
	t.Helper()
	target, err := types.DecodeAddress(prep.RekeyTo)
	if err != nil {
		t.Fatal(err)
	}
	profile := f.svc.Planner.Snapshot().KeyMetadata[f.account.String()].LogicSigResources
	for n := range 20000 {
		txn := f.spend(1000, 1100)
		txn.RekeyTo = target
		txn.Note = fmt.Appendf(nil, "collision-%d", n)
		plan, planErr := f.svc.Planner.buildRotatingGroup(f.account.String(), txn, profile)
		if planErr != nil {
			t.Fatal(planErr)
		}
		txID := algocrypto.TransactionID(plan.AllTxns[0])
		if uint32(txID[0])%64 != leaf {
			continue
		}
		var group []string
		for _, built := range plan.AllTxns {
			group = append(group, txnutil.EncodeWithPrefixHex(built))
		}
		return group
	}
	t.Fatal("no transaction picks the leaf")
	return nil
}

// A worker that saw the lock can run its Reset after a later unlock and sign
// have already passed the restore check. Choosing from that emptied memory would
// sign two transactions on one leaf with 63 unused and report nothing.
func TestRotatingLeafChoiceRefusesADelayedReset(t *testing.T) {
	for _, kind := range []rotatingTestType{xmssTestType, wotscTestType} {
		t.Run(kind.keyType, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, kind)
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			mustSign(t, f, prep.Transactions)
			first, _ := f.svc.Rotating.Releases.Get(f.account.String())
			used := first.Leaves[0]
			second := groupWithPick(t, f, prep, used.Index)

			resp, err := signWithHook(t, f, context.Background(), second, f.svc.Rotating.Releases.Reset)
			if resp != nil || err == nil || err.Kind != ErrorUnavailable {
				t.Fatalf("response %v, error %v, want a refusal while the memory is held", resp, err)
			}
			if len(audit.releases) != 1 {
				t.Fatalf("%d releases audited, want the first only", len(audit.releases))
			}

			// Once the log is restored, the same transaction takes an unused leaf.
			if n, rebuildErr := f.svc.RebuildReleaseMemory(context.Background(), f.session, f.lockGen, []AuditedRelease{{
				Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
			}}, StageFillOptions{}); rebuildErr != nil || n != 1 {
				t.Fatalf("restore: rebuilt %d, err %v", n, rebuildErr)
			}
			f.svc.Rotating.Releases.RestoredAll()
			mustSign(t, f, second)
			rec, _ := f.svc.Rotating.Releases.Get(f.account.String())
			if rec.Reused || len(rec.Leaves) != 2 || rec.Leaves[0].Index == rec.Leaves[1].Index {
				t.Fatalf("second release after the restore: %+v", rec)
			}
		})
	}
}

// restoreInterruptedBy fails a restore's derivation the way a lock does, and
// runs stop as the lock lands. It returns the restore's result.
func restoreInterruptedBy(t *testing.T, f *rotatingFixture, first ReleaseRecord, ctx context.Context, stop func()) (int, error) {
	t.Helper()
	ran := false
	n, err := f.svc.RebuildReleaseMemory(ctx, f.session, f.lockGen, []AuditedRelease{{
		Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
	}}, StageFillOptions{KeyUse: func(parent context.Context) (context.Context, func()) {
		ran = true
		stop()
		cancelled, cancel := context.WithCancel(parent)
		cancel()
		return cancelled, func() {}
	}})
	if !ran {
		t.Fatal("the restore never reached the derivation")
	}
	return n, err
}

// A lock can cancel a restore's derivation and an unlock follow before the
// worker gets back. The account's history is still missing, so its wait has to
// stay closed. Both ways of seeing the lock are covered: the key-use context can
// be cancelled before the restore's own context is, leaving only the generation.
func TestInterruptedRestoreKeepsTheAccountHeld(t *testing.T) {
	for _, mode := range []string{"context cancelled", "generation only", "key use refused and nothing else moved"} {
		t.Run(mode, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, wotscTestType)
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			mustSign(t, f, prep.Transactions)
			first, _ := f.svc.Rotating.Releases.Get(f.account.String())
			second := groupWithPick(t, f, prep, first.Leaves[0].Index)

			f.svc.Rotating.Releases.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			n, err := restoreInterruptedBy(t, f, first, ctx, func() {
				// Recovery refuses the key use and moves nothing a restore can see.
				if mode == "key use refused and nothing else moved" {
					return
				}
				f.lockGen++
				if mode == "context cancelled" {
					cancel()
				}
			})
			if n != 0 || !errors.Is(err, ErrRestoreInterrupted) {
				t.Fatalf("restore: rebuilt %d, err %v", n, err)
			}
			if _, restored := f.svc.Rotating.Releases.ForLeafChoice(f.account.String()); restored {
				t.Fatal("an interrupted restore opened the account's wait")
			}
			short, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer stop()
			resp, signErr := f.svc.SignRotatingWithContext(short, signerapi.RotatingSignRequest{
				Account: f.account.String(), Transactions: second,
			}, f.session)
			if resp != nil || signErr == nil || signErr.Kind != ErrorUnavailable {
				t.Fatalf("response %v, error %v, want a refusal while held", resp, signErr)
			}
			if len(audit.releases) != 1 {
				t.Fatalf("%d releases audited, want the first only", len(audit.releases))
			}
		})
	}
}

// The restore's generation is read before its context and session exist. A lock
// landing after that, even before the restore starts, has to count as interrupting
// it: the signer's key use is already cancelled, and the restore's own context
// may not be yet.
func TestRestoreBoundToAnEarlierGenerationStaysHeld(t *testing.T) {
	f, _ := newSigningFixtureFor(t, wotscTestType)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	mustSign(t, f, prep.Transactions)
	first, _ := f.svc.Rotating.Releases.Get(f.account.String())
	f.svc.Rotating.Releases.Reset()

	generation := f.lockGen
	f.lockGen++ // The lock lands before RebuildReleaseMemory runs.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.svc.RebuildReleaseMemory(context.Background(), f.session, generation, []AuditedRelease{{
		Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
	}}, StageFillOptions{KeyUse: func(context.Context) (context.Context, func()) { return cancelled, func() {} }})
	if !errors.Is(err, ErrRestoreInterrupted) {
		t.Fatalf("error = %v, want an interrupted restore", err)
	}
	if _, restored := f.svc.Rotating.Releases.ForLeafChoice(f.account.String()); restored {
		t.Fatal("a restore from before the lock opened the account's wait")
	}
}

// failingKeyStore can't load a key, whatever the signer's state.
type failingKeyStore struct{}

func (failingKeyStore) Get(context.Context, string) (*coresigning.KeyMaterial, error) {
	return nil, errors.New("key file is damaged")
}

// restoreWithAFailedDerivation runs a restore whose derivation really fails: the
// key can't be loaded. A cancelled key use isn't a failure and can't stand in for
// one, because the signer refuses key use exactly when it is interrupted.
func restoreWithAFailedDerivation(t *testing.T, f *rotatingFixture) (int, error) {
	t.Helper()
	first, _ := f.svc.Rotating.Releases.Get(f.account.String())
	f.svc.Rotating.Releases.Reset()
	session := keystore.NewKeySession(failingKeyStore{})
	session.InitializeSession()
	t.Cleanup(session.Destroy)
	return f.svc.RebuildReleaseMemory(context.Background(), session, f.lockGen, []AuditedRelease{{
		Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
	}}, StageFillOptions{})
}

// A key that really can't be loaded isn't a cut, so nothing about the failure says
// a lock came first. Only the generation bound before the restore started does:
// read later, it would match, and the account would open in the next session.
func TestFailedRestoreFromAnEarlierSessionStaysHeld(t *testing.T) {
	f, _ := newSigningFixtureFor(t, wotscTestType)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	mustSign(t, f, prep.Transactions)
	first, _ := f.svc.Rotating.Releases.Get(f.account.String())
	f.svc.Rotating.Releases.Reset()
	generation := f.lockGen
	f.lockGen++
	session := keystore.NewKeySession(failingKeyStore{})
	session.InitializeSession()
	t.Cleanup(session.Destroy)
	_, err := f.svc.RebuildReleaseMemory(context.Background(), session, generation, []AuditedRelease{{
		Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
	}}, StageFillOptions{})
	if !errors.Is(err, ErrRestoreInterrupted) {
		t.Fatalf("error = %v, want an interrupted restore", err)
	}
	if _, restored := f.svc.Rotating.Releases.ForLeafChoice(f.account.String()); restored {
		t.Fatal("a failure from an earlier session opened the wait")
	}
}

// A failure that isn't an interruption is the stated loss case: state chooses the
// leaf, never whether to sign, so the account has to be let through.
func TestFailedRestoreStillOpensTheAccount(t *testing.T) {
	f, _ := newSigningFixtureFor(t, wotscTestType)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	mustSign(t, f, prep.Transactions)
	n, err := restoreWithAFailedDerivation(t, f)
	if n != 0 || err == nil || errors.Is(err, ErrRestoreInterrupted) {
		t.Fatalf("restore: rebuilt %d, err %v", n, err)
	}
	if _, restored := f.svc.Rotating.Releases.ForLeafChoice(f.account.String()); !restored {
		t.Fatal("a failed restore left the account held")
	}
}

// The same failure on a signer that can't sign proves nothing about the account,
// and the signer may come back with nothing changed.
func TestFailedRestoreOnASignerThatCantSignStaysHeld(t *testing.T) {
	f, _ := newSigningFixtureFor(t, wotscTestType)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	mustSign(t, f, prep.Transactions)
	f.svc.IsUnlocked = func() bool { return false }
	if _, err := restoreWithAFailedDerivation(t, f); !errors.Is(err, ErrRestoreInterrupted) {
		t.Fatalf("error = %v, want an interrupted restore", err)
	}
	if _, restored := f.svc.Rotating.Releases.ForLeafChoice(f.account.String()); restored {
		t.Fatal("a failure on a signer that can't sign opened the wait")
	}
}

// lockAfterSuccessAudit locks the signer during the last audit write of a sign.
type lockAfterSuccessAudit struct {
	*recordingReleaseAudit
	lock func()
}

func (a *lockAfterSuccessAudit) LogSignApproved(record SignedRecord) {
	a.recordingReleaseAudit.LogSignApproved(record)
	a.lock()
}

// Audit writes block, so a lock can land during the very last one. Nothing that
// blocks may come after the final check.
func TestRotatingSignStopsAtALockDuringTheLastAuditWrite(t *testing.T) {
	for _, kind := range rotatingTestTypes {
		t.Run(kind.keyType, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, kind)
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			locked := false
			f.svc.AuditLog = &lockAfterSuccessAudit{recordingReleaseAudit: audit, lock: func() {
				locked = true
				f.lockGen++
				f.svc.IsUnlocked = func() bool { return false }
			}}
			resp, err := f.sign(t, prep.Transactions)
			if !locked {
				t.Fatal("the sign never reached its last audit write")
			}
			if resp != nil || err == nil || err.Kind != ErrorLocked {
				t.Fatalf("response %v, error %v, want a lock refusal", resp, err)
			}
			// The log already says the transaction was signed; a SIGN_FAILED
			// for the same transaction says the signature never left.
			if len(audit.signed) != 1 || len(audit.failed) != 1 ||
				!strings.Contains(audit.failed[0], "signature withheld") || !strings.Contains(audit.failed[0], audit.signed[0].TxID) {
				t.Fatalf("signed %+v, failed %q; want the withheld signature recorded against its transaction", audit.signed, audit.failed)
			}
		})
	}
}

// countingChain counts chain reads.
type countingChain struct {
	base  *fakeRotatingChain
	reads atomic.Int32
}

func (c *countingChain) ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error) {
	c.reads.Add(1)
	return c.base.ReadAccount(ctx, genesisHash, account)
}

// hasWaiter reports whether a caller is parked in AwaitRestored: nothing else
// creates changed, and it stays set until the caller is woken.
func (m *ReleaseMemory) hasWaiter() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.changed != nil
}

// A spend that arrives during a restore waits for it, ahead of the account lock
// and the chain read, and then signs. The check at leaf choice would refuse it
// anyway, so a refusal says nothing about the wait. The test follows the sign to
// the wait itself rather than allowing it time to get there, so a sign that is
// merely slow can't pass for one that is waiting.
func TestRotatingSignWaitsForARestoreAndThenSigns(t *testing.T) {
	f, audit := newSigningFixtureFor(t, wotscTestType)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	chain := &countingChain{base: f.chain}
	f.svc.Rotating.Chain = chain
	f.svc.Rotating.Releases.Reset()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan *ServiceError, 1)
	go func() {
		_, err := f.svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{
			Account: f.account.String(), Transactions: prep.Transactions,
		}, f.session)
		done <- err
	}()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for !f.svc.Rotating.Releases.hasWaiter() {
		select {
		case err := <-done:
			t.Fatalf("the sign returned without waiting for the restore: %v", err)
		case <-ctx.Done():
			t.Fatal("the sign never reached the wait")
		case <-poll.C:
		}
	}
	if n := chain.reads.Load(); n != 0 {
		t.Fatalf("the sign read the chain %d times before the restore finished", n)
	}
	locked := make(chan func(), 1)
	go func() { locked <- f.svc.Rotating.Locks.Lock(f.account.String()) }()
	select {
	case unlock := <-locked:
		unlock()
	case <-ctx.Done():
		t.Fatal("the sign held the account lock while it waited for the restore")
	}
	f.svc.Rotating.Releases.RestoredAll()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sign after the restore: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("the sign never finished after the restore")
	}
	if chain.reads.Load() == 0 {
		t.Fatal("the sign finished without reading the chain")
	}
	if len(audit.releases) != 1 {
		t.Fatalf("%d releases audited, want 1", len(audit.releases))
	}
}

func TestForLeafChoice(t *testing.T) {
	m := &ReleaseMemory{}
	m.Record(ReleaseRecord{Account: "A", Stage: 1, TxID: "T"})
	if rec, restored := m.ForLeafChoice("A"); !restored || rec.TxID != "T" {
		t.Fatalf("a memory that was never reset: %+v, restored %v", rec, restored)
	}
	m.Reset()
	if _, restored := m.ForLeafChoice("A"); restored {
		t.Fatal("a held memory reported restored")
	}
	m.Restoring([]string{"A"})
	if _, restored := m.ForLeafChoice("A"); restored {
		t.Fatal("an account still restoring reported restored")
	}
	if _, restored := m.ForLeafChoice("B"); !restored {
		t.Fatal("an account with nothing to restore stayed held")
	}
	m.Restored("A")
	if _, restored := m.ForLeafChoice("A"); !restored {
		t.Fatal("a restored account stayed held")
	}
	var none *ReleaseMemory
	if _, restored := none.ForLeafChoice("A"); !restored {
		t.Fatal("no memory should hold nobody")
	}
}
