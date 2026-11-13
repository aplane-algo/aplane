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

// Every seed load in prepare and sign is a key use, and each one ends before the
// request moves on. The seed has to be gone before the audit write, and a lock
// arriving during that write still has to stop the signature. The release stays
// on record, which only makes its leaf look used.
func TestRotatingSignEndsItsKeyUseBeforeTheAuditWrite(t *testing.T) {
	f, audit := newSigningFixtureFor(t, wotscTestType)
	active, opened := 0, 0
	f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
		active++
		opened++
		useCtx, cancel := context.WithCancel(ctx)
		return useCtx, func() {
			active--
			cancel()
		}
	}
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	// Prepare on stage 0 loads the seed twice: for the account's identity and to
	// derive the target, stage 1.
	if opened != 2 || active != 0 || f.store.loads != 2 {
		t.Fatalf("prepare opened %d key uses for %d seed loads and left %d open; want 2 for 2, all ended", opened, f.store.loads, active)
	}
	opened, f.store.loads = 0, 0
	audit.onRelease = func() {
		if active != 0 {
			t.Error("the audit write ran while the seed was held")
		}
		// Sign loads the seed three times: for the account's identity, to derive
		// the target before approval, and to sign after it.
		if opened != 3 || f.store.loads != 3 {
			t.Errorf("sign opened %d key uses for %d seed loads; want 3 for 3", opened, f.store.loads)
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

// A key use the signer refuses because it is locking answers locked and loads
// nothing, wherever in prepare or sign it lands. The runtime refuses exactly
// when it no longer reads unlocked, so the double flips both together. A
// refusal during discovery has to end the search rather than retry it until the
// discovery timeout.
func TestRotatingRequestsAnswerLockedWhenAKeyUseIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		// refuse is the request's first key use the lock refuses.
		refuse          int
		sign            bool
		authorizerStage uint64
	}{
		{name: "prepare/account identity", refuse: 1},
		{name: "prepare/live stage", refuse: 2, authorizerStage: 1},
		{name: "prepare/target", refuse: 2},
		{name: "sign/account identity", refuse: 1, sign: true},
		{name: "sign/target", refuse: 2, sign: true},
		{name: "sign/signature", refuse: 3, sign: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, wotscTestType)
			var prep *signerapi.RotatingPrepareResponse
			if tc.sign {
				prep = mustPrepare(t, f, f.spend(1000, 1100))
			}
			if tc.authorizerStage != 0 {
				f.chain.authorizer = f.stageAddress(t, tc.authorizerStage)
			}
			uses := 0
			f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
				uses++
				if uses < tc.refuse {
					return ctx, func() {}
				}
				f.svc.IsUnlocked = func() bool { return false }
				refused, cancel := context.WithCancel(ctx)
				cancel()
				return refused, func() {}
			}
			// A spin would run to this bound and then report the stage unproven.
			f.svc.Rotating.DiscoveryTimeout = time.Minute
			before := f.store.loads
			var err *ServiceError
			if tc.sign {
				_, err = f.sign(t, prep.Transactions)
			} else {
				_, err = f.prepare(t, f.spend(1000, 1100))
			}
			if err == nil || err.Kind != ErrorLocked {
				t.Fatalf("error = %v, want the locked error", err)
			}
			if uses != tc.refuse {
				t.Fatalf("the request asked for %d key uses, want %d: it went on after the refusal or never reached it", uses, tc.refuse)
			}
			if loads := f.store.loads - before; loads != tc.refuse-1 {
				t.Fatalf("%d seed loads, want %d: a refused key use loaded the seed", loads, tc.refuse-1)
			}
			if len(audit.releases) != 0 {
				t.Fatalf("a refused request released a signature: %+v", audit.releases)
			}
		})
	}
}

// A bad account is refused as such while the signer is locking: it is checked
// against the key index before any key use, so it gets its 400, not the
// locked error, and asks for no key use.
func TestRotatingRequestsRefuseABadAccountBeforeAnyKeyUse(t *testing.T) {
	held := types.Address{7, 31: 7}.String()
	for _, sign := range []bool{false, true} {
		for _, tc := range []struct{ name, account string }{
			{name: "unknown address", account: types.Address{9, 31: 9}.String()},
			{name: "not a rotating account", account: held},
			{name: "malformed account", account: "NOT-AN-ADDRESS"},
		} {
			name := "prepare/" + tc.name
			if sign {
				name = "sign/" + tc.name
			}
			t.Run(name, func(t *testing.T) {
				f, _ := newSigningFixtureFor(t, wotscTestType)
				f.held = []string{held}
				var prep *signerapi.RotatingPrepareResponse
				if sign {
					prep = mustPrepare(t, f, f.spend(1000, 1100))
				}
				uses := 0
				f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
					uses++
					f.svc.IsUnlocked = func() bool { return false }
					refused, cancel := context.WithCancel(ctx)
					cancel()
					return refused, func() {}
				}
				var err *ServiceError
				if sign {
					_, err = f.svc.SignRotatingWithContext(context.Background(), signerapi.RotatingSignRequest{
						Account: tc.account, Transactions: prep.Transactions,
					}, f.session)
				} else {
					_, err = f.svc.PrepareRotatingWithContext(context.Background(), signerapi.RotatingPrepareRequest{
						Account: tc.account, TxnBytesHex: txnutil.EncodeWithPrefixHex(f.spend(1000, 1100)),
					}, f.session)
				}
				if err == nil || err.Kind != ErrorBadRequest {
					t.Fatalf("error = %v, want a bad request", err)
				}
				if uses != 0 {
					t.Fatalf("a bad request asked for %d key uses", uses)
				}
			})
		}
	}
}

// Deps without KeyUse load no seed anywhere: every load answers "not
// configured" instead, a helper reached directly doesn't panic, and the paths
// that load no seed (status, recovery cancel) keep working.
func TestRotatingWithoutKeyUseLoadsNoSeedAndKeepsItsStatus(t *testing.T) {
	f, _ := newSigningFixtureFor(t, wotscTestType)
	other := types.Address{4, 2, 31: 7}
	f.held = []string{other.String()}
	f.chain.authorizer = other
	report := f.fill(t, StageFillOptions{})
	f.svc.Rotating.KeyUse = nil
	before := f.store.loads

	if _, err := f.prepare(t, f.spend(1000, 1100)); err == nil || err.Kind != ErrorInternal || !strings.Contains(err.Message, "not configured") {
		t.Fatalf("prepare: %v, want not configured", err)
	}
	if _, err := f.svc.requestDeriver(f.account.String(), f.session)(context.Background(), 1, 2); !errors.Is(err, errKeyUseNotConfigured) {
		t.Fatalf("deriver: %v, want not configured", err)
	}
	if reports := f.svc.FillStageTables(context.Background(), f.session, StageFillOptions{}); len(reports) != 1 || reports[0].Err == nil {
		t.Fatalf("fill without KeyUse: %+v, want the account's error", reports)
	}
	if f.store.loads != before {
		t.Fatalf("%d seed loads without KeyUse", f.store.loads-before)
	}
	if _, notes := f.svc.RotatingStatus([]StageTableReport{report}); len(notes) != 1 {
		t.Fatalf("status without KeyUse: notes %v", notes)
	}
	if _, err := f.svc.RecoverRotatingWithContext(context.Background(), signerapi.RotatingRecoverRequest{
		Account: f.account.String(), Action: signerapi.RotatingRecoverActionCancel,
	}); err != nil {
		t.Fatalf("recovery cancel without KeyUse: %v", err)
	}
}

// loadHookStore runs onLoad, if set, each time the seed is loaded, after the
// copy exists.
type loadHookStore struct {
	base   *rotatingKeyStore
	loads  atomic.Int32
	onLoad func()
}

func (s *loadHookStore) Get(ctx context.Context, account string) (*coresigning.KeyMaterial, error) {
	key, err := s.base.Get(ctx, account)
	s.loads.Add(1)
	if s.onLoad != nil {
		s.onLoad()
	}
	return key, err
}

// A derivation reports a lock (errKeyUseRefused) exactly when the lock stopped
// its key use before a stage was derived: refused it, cancelled it, or had
// cleared the session. A caller that ended its own request gets an empty
// result and no lock, so it isn't answered "locked". The decision is taken
// where the key use was stopped, not read back from the request's context
// afterwards. The background deriver takes a lock as a quiet stop.
func TestStageDerivationReportsALockOnlyWhenTheKeyUseWasStopped(t *testing.T) {
	for _, tc := range []struct {
		name string
		// arrange sets up the key use and the load for one derivation under
		// parent, which cancel ends.
		arrange func(f *rotatingFixture, store *loadHookStore, session *keystore.KeySession, cancel context.CancelFunc)
		locked  bool
		kind    ErrorKind
		loads   int32
	}{
		{name: "key use refused", locked: true, kind: ErrorLocked, arrange: func(f *rotatingFixture, _ *loadHookStore, _ *keystore.KeySession, _ context.CancelFunc) {
			f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
				refused, stop := context.WithCancel(ctx)
				stop()
				return refused, func() {}
			}
		}},
		{name: "key use cancelled while the seed loads", locked: true, kind: ErrorLocked, loads: 1, arrange: func(f *rotatingFixture, store *loadHookStore, _ *keystore.KeySession, _ context.CancelFunc) {
			var stop context.CancelFunc
			f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
				var use context.Context
				use, stop = context.WithCancel(ctx)
				return use, func() {}
			}
			store.onLoad = func() { stop() }
		}},
		{name: "session already cleared", locked: true, kind: ErrorLocked, arrange: func(_ *rotatingFixture, _ *loadHookStore, session *keystore.KeySession, _ context.CancelFunc) {
			session.Destroy()
		}},
		{name: "key use refused, request then cancelled", locked: true, kind: ErrorLocked, arrange: func(f *rotatingFixture, _ *loadHookStore, _ *keystore.KeySession, cancel context.CancelFunc) {
			f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
				refused, stop := context.WithCancel(ctx)
				stop()
				return refused, cancel
			}
		}},
		{name: "request cancelled while the seed loads", kind: ErrorUnavailable, loads: 1, arrange: func(_ *rotatingFixture, store *loadHookStore, _ *keystore.KeySession, cancel context.CancelFunc) {
			store.onLoad = cancel
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, background := range []bool{false, true} {
				f := newRotatingFixture(t)
				store := &loadHookStore{base: f.store}
				session := keystore.NewKeySession(store)
				session.InitializeSession()
				t.Cleanup(session.Destroy)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				tc.arrange(f, store, session, cancel)
				account := f.account.String()
				if background {
					addrs, err := f.svc.backgroundDeriver(account, session, StageFillOptions{})(ctx, 1, 2)
					if len(addrs) != 0 || err != nil {
						t.Fatalf("background: %d addresses, err %v; want a quiet stop", len(addrs), err)
					}
					continue
				}
				var raw error
				derive := func(ctx context.Context, from, to uint64) ([]types.Address, error) {
					addrs, err := f.svc.requestDeriver(account, session)(ctx, from, to)
					raw = err
					return addrs, err
				}
				_, svcErr := derivedStageAddress(ctx, f.svc.Rotating, f.table(t), derive, 1)
				if got := errors.Is(raw, errKeyUseRefused); got != tc.locked {
					t.Fatalf("deriver error = %v; reports a lock: %v, want %v", raw, got, tc.locked)
				}
				if svcErr == nil || svcErr.Kind != tc.kind {
					t.Fatalf("request error = %v, want kind %v", svcErr, tc.kind)
				}
				if n := store.loads.Load(); n != tc.loads {
					t.Fatalf("%d seed loads, want %d", n, tc.loads)
				}
			}
		})
	}
}

// A lock during the stage table fill's identity read is where the pass stops,
// as it is one step later in the deriver: no account error, so the worker
// logs no warning. The lock refuses or cuts the read's key use, and it also
// cancels the pass's context, which may be seen first. The report once
// carried "signer is locked" or "context canceled", whichever came first.
func TestFillStopsQuietlyAtALockDuringTheIdentityRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		// passCancelled: the lock has cancelled the pass's context too.
		passCancelled bool
	}{
		{name: "key use refused"},
		{name: "key use refused and pass cancelled", passCancelled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := newSigningFixtureFor(t, wotscTestType)
			ctx, cancelPass := context.WithCancel(context.Background())
			defer cancelPass()
			uses := 0
			f.svc.Rotating.KeyUse = func(use context.Context) (context.Context, func()) {
				uses++
				f.svc.IsUnlocked = func() bool { return false }
				if tc.passCancelled {
					cancelPass()
				}
				refused, cancel := context.WithCancel(use)
				cancel()
				return refused, func() {}
			}
			before := f.store.loads
			reports := f.svc.FillStageTables(ctx, f.session, StageFillOptions{})
			if len(reports) != 1 || reports[0].Err != nil || reports[0].Observed || reports[0].Pending {
				t.Fatalf("reports = %+v, want one quiet stop with no error", reports)
			}
			if uses != 1 || f.store.loads != before {
				t.Fatalf("%d key uses and %d seed loads, want the identity read's one refused use and none", uses, f.store.loads-before)
			}
		})
	}
}

// The stateless-hash (SLH-DSA) sign reads the chain once more after signing,
// inside its key use. A lock that cuts that read short answers locked, as a key
// use the lock cuts does everywhere else; the request's own end answers
// unavailable. A lock there once answered unavailable("context canceled").
func TestSLHReleaseReadCutByALockAnswersLocked(t *testing.T) {
	for _, tc := range []struct {
		name string
		want ErrorKind
	}{
		{"lock", ErrorLocked},
		{"request cancelled", ErrorUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, slhTestType)
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			var cutKeyUse context.CancelFunc
			f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
				use, cancel := context.WithCancel(ctx)
				cutKeyUse = cancel
				return use, cancel
			}
			ctx, cancelRequest := context.WithCancel(context.Background())
			defer cancelRequest()
			reads := 0
			f.svc.Rotating.Chain = rotatingChainFunc(func(readCtx context.Context, genesis []byte, account types.Address) (chainread.AccountView, error) {
				reads++
				if reads < 2 {
					return f.chain.ReadAccount(readCtx, genesis, account)
				}
				// The release re-read, under the signing window's key use.
				switch tc.name {
				case "lock":
					f.svc.IsUnlocked = func() bool { return false }
					cutKeyUse()
				case "request cancelled":
					cancelRequest()
				}
				<-readCtx.Done()
				return chainread.AccountView{}, readCtx.Err()
			})
			resp, err := f.svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: f.account.String(), Transactions: prep.Transactions}, f.session)
			if reads != 2 {
				t.Fatalf("chain reads %d, want two", reads)
			}
			if resp != nil || err == nil || err.Kind != tc.want {
				t.Fatalf("response %v, error %v, want kind %v", resp, err, tc.want)
			}
			if len(audit.releases) != 0 {
				t.Fatal("a signature cut short was audited as released")
			}
		})
	}
}

type rotatingChainFunc func(ctx context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error)

func (f rotatingChainFunc) ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error) {
	return f(ctx, genesisHash, account)
}

// A request that joins another derivation of the same stages decides by its own
// key use when that derivation ends without a result: the other request was
// cancelled, or its key use was stopped. Either way the waiter derives under its
// own window instead of answering locked.
func TestJoinedDerivationRetriesUnderItsOwnKeyUse(t *testing.T) {
	for _, mode := range []string{"other request cancelled", "other key use cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newRotatingFixture(t)
			entered, park := make(chan struct{}), make(chan struct{})
			store := &loadHookStore{base: f.store}
			store.onLoad = func() {
				if store.loads.Load() == 1 {
					close(entered)
					<-park
				}
			}
			session := keystore.NewKeySession(store)
			session.InitializeSession()
			t.Cleanup(session.Destroy)
			var stopFirst context.CancelFunc
			var uses atomic.Int32
			f.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
				if uses.Add(1) == 1 {
					var use context.Context
					use, stopFirst = context.WithCancel(ctx)
					return use, func() {}
				}
				return ctx, func() {}
			}
			account := f.account.String()
			leaderCtx, cancelLeader := context.WithCancel(context.Background())
			defer cancelLeader()
			leaderDone := make(chan struct{})
			go func() {
				defer close(leaderDone)
				_, _ = f.svc.requestDeriver(account, session)(leaderCtx, 1, 2)
			}()
			<-entered

			waiting := make(chan struct{})
			type result struct {
				addr types.Address
				err  *ServiceError
			}
			got := make(chan result, 1)
			table := f.table(t)
			go func() {
				ctx := &waitObservedContext{Context: context.Background(), waiting: waiting}
				addr, err := derivedStageAddress(ctx, f.svc.Rotating, table, f.svc.requestDeriver(account, session), 1)
				got <- result{addr, err}
			}()
			<-waiting
			if mode == "other request cancelled" {
				cancelLeader()
			} else {
				stopFirst()
			}
			close(park)
			<-leaderDone
			r := <-got
			if r.err != nil || r.addr != f.stageAddress(t, 1) {
				t.Fatalf("waiter: %v, %v; want stage 1 under its own key use", r.addr, r.err)
			}
			if n := uses.Load(); n != 2 {
				t.Fatalf("%d key uses, want the other request's and the waiter's own", n)
			}
		})
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
			}}); rebuildErr != nil || n != 1 {
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
	keyUse := f.svc.Rotating.KeyUse
	f.svc.Rotating.KeyUse = func(parent context.Context) (context.Context, func()) {
		ran = true
		stop()
		cancelled, cancel := context.WithCancel(parent)
		cancel()
		return cancelled, func() {}
	}
	defer func() { f.svc.Rotating.KeyUse = keyUse }()
	n, err := f.svc.RebuildReleaseMemory(ctx, f.session, f.lockGen, []AuditedRelease{{
		Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
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
	f.svc.Rotating.KeyUse = func(context.Context) (context.Context, func()) { return cancelled, func() {} }
	_, err := f.svc.RebuildReleaseMemory(context.Background(), f.session, generation, []AuditedRelease{{
		Account: f.account.String(), Stage: first.Stage, TxID: first.TxID, LastValid: first.LastValid, Leaves: first.Leaves,
	}})
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
	}})
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
	}})
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
			// under the same txid and group_id says the signature never left.
			if len(audit.signed) != 1 || len(audit.withheld) != 1 {
				t.Fatalf("signed %+v, withheld %+v; want one of each", audit.signed, audit.withheld)
			}
			signed, withheld := audit.signed[0], audit.withheld[0]
			if withheld.record.TxID == "" || withheld.record.TxID != signed.TxID || withheld.record.GroupID != signed.GroupID ||
				withheld.record.AuthAddress != signed.AuthAddress || withheld.record.TxnSender != signed.TxnSender {
				t.Fatalf("withheld %+v, want the signed record's transaction %+v", withheld.record, signed)
			}
			if !strings.HasPrefix(withheld.reason, "signature withheld after it was recorded as signed: ") {
				t.Fatalf("withheld reason = %q", withheld.reason)
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
