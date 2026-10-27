// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/aplane-algo/aplane/internal/racetest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
	rotatingslhsignerreg "github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/signerreg"
	rotatingtriplesignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplewots/signerreg"
	rotatingxmsssignerreg "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/signerreg"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

var rotatingTestGenesis = func() []byte {
	b, _ := base64.StdEncoding.DecodeString("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=")
	return b
}()

// fakeRotatingChain answers account reads from memory. A zero authorizer
// means the account has no auth address set, which is stage 0.
type fakeRotatingChain struct {
	authorizer types.Address
	round      uint64
	err        error
	reads      int
}

func (f *fakeRotatingChain) ReadAccount(_ context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error) {
	f.reads++
	if f.err != nil {
		return chainread.AccountView{}, f.err
	}
	if !bytes.Equal(genesisHash, rotatingTestGenesis) {
		return chainread.AccountView{}, errors.New("wrong network")
	}
	authorizer := f.authorizer
	if authorizer.IsZero() {
		authorizer = account
	}
	return chainread.AccountView{Authorizer: authorizer, Round: f.round}, nil
}

// rotatingTestType selects which rotating key type a fixture exercises.
type rotatingTestType struct {
	keyType       string
	register      func()
	newKeyPayload func(*rotatinghybrid.Seed, [32]byte) (*keys.Payload, string, error)
	// dummies is the number of resource dummies one spend needs.
	dummies int
	// sharedSeed gives every fixture of the type the same seed, so a type
	// whose stages share trees that take seconds to build pays for one
	// tree per test binary through its process-wide cache. Fixtures never
	// share a store, so the shared address is harmless.
	sharedSeed bool
}

var (
	tripleTestType = rotatingTestType{
		keyType: rotatingkey.RotatingTripleWotsV1, register: rotatingtriplesignerreg.Register,
		newKeyPayload: rotatingtriplesignerreg.NewKeyPayload, dummies: 3,
	}
	// rotatingTestTypes is every rotating key type; the per-type tests loop
	// over it so a second type (the rotating-bounded contract) slots in.
	xmssTestType = rotatingTestType{
		keyType: rotatingkey.RotatingTripleXmssV1, register: rotatingxmsssignerreg.Register,
		newKeyPayload: rotatingxmsssignerreg.NewKeyPayload, dummies: 4, sharedSeed: true,
	}
	slhTestType = rotatingTestType{
		keyType: rotatingkey.RotatingTripleSlhdsaV1, register: rotatingslhsignerreg.Register,
		newKeyPayload: rotatingslhsignerreg.NewKeyPayload, dummies: map[int]int{22: 5, 63: 9}[rotatingkey.RotatingSlhdsaHeight],
	}
	rotatingTestTypes = []rotatingTestType{tripleTestType, xmssTestType, slhTestType}
)

type rotatingKeyStore struct {
	keyType string
	seed    []byte
	loads   int
}

func (s *rotatingKeyStore) Get(context.Context, string) (*coresigning.KeyMaterial, error) {
	s.loads++
	return &coresigning.KeyMaterial{
		Type:     s.keyType,
		Category: keys.CategoryRotatingLsig,
		Value: &coresigning.RotatingKeyMaterial{
			Seed:        bytes.Clone(s.seed),
			GenesisHash: bytes.Clone(rotatingTestGenesis),
		},
	}, nil
}

type rotatingFixture struct {
	kind rotatingTestType
	svc  *Service
	// held lists extra, non-rotating addresses the planner snapshot
	// reports as credentials this signer holds.
	held []string
	// lockGen is the lock generation the fixture reports; a test bumps it
	// to simulate a lock and unlock.
	lockGen uint64
	chain   *fakeRotatingChain
	store   *rotatingKeyStore
	present bool
	root    string
	tables  *stagetable.Store
	session *keystore.KeySession
	account types.Address
	secret  *coresigning.RotatingKeyMaterial
	ops     coresigning.RotatingStageOps
}

func newRotatingFixture(t *testing.T) *rotatingFixture {
	t.Helper()
	return newRotatingFixtureFor(t, tripleTestType)
}

func newRotatingFixtureFor(t testing.TB, kind rotatingTestType) *rotatingFixture {
	t.Helper()
	if kind.sharedSeed {
		racetest.SkipFullTree(t)
	}
	kind.register()
	// A fresh random seed per fixture: the tests compare the table against
	// derivations from the same seed, so no known vector is needed. A type
	// with shared trees uses one fixed seed instead (sharedSeed).
	var seed rotatinghybrid.Seed
	if kind.sharedSeed {
		for i := range seed {
			seed[i] = byte(0x5A ^ i)
		}
	} else if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seed.Zero)
	var gh [32]byte
	copy(gh[:], rotatingTestGenesis)
	payload, address, err := kind.newKeyPayload(&seed, gh)
	if err != nil {
		t.Fatal(err)
	}
	payload.ZeroSecrets()
	account, _ := types.DecodeAddress(address)

	rk, _ := rotatingkey.Lookup(kind.keyType)
	argumentBytes := uint64(rk.MaxArgumentBytes)
	profile, err := lsigresource.Materialize(uint64(rk.MaxProgramBytes), &argumentBytes, nil,
		lsigresource.DefaultOpcodeProfile(uint64(rk.MaxOpcodeCost)))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tables := stagetable.NewStore(storepaths.NewPaths(root))
	chain := &fakeRotatingChain{round: 1000}
	store := &rotatingKeyStore{keyType: kind.keyType, seed: bytes.Clone(seed[:])}
	t.Cleanup(func() { clear(store.seed) })
	session := keystore.NewKeySession(store)
	session.InitializeSession()
	ops, err := coresigning.GetRotatingStageOps(kind.keyType)
	if err != nil {
		t.Fatal(err)
	}

	f := &rotatingFixture{kind: kind, chain: chain, store: store, present: true, root: root, tables: tables, session: session, account: account, ops: ops}
	svc := &Service{
		Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
			if !f.present {
				return PlannerRuntimeSnapshot{}
			}
			snap := PlannerRuntimeSnapshot{
				KeyFiles: map[string]string{address: "keys/" + address + ".key"},
				KeyTypes: map[string]string{address: kind.keyType},
				KeyMetadata: map[string]PlannerKeyMetadata{address: {
					Category:          keys.CategoryRotatingLsig,
					LogicSigResources: &profile,
				}},
			}
			for _, h := range f.held {
				snap.KeyFiles[h] = "keys/" + h + ".key"
				snap.KeyTypes[h] = "ed25519"
				snap.KeyMetadata[h] = PlannerKeyMetadata{Category: keys.CategoryEd25519}
			}
			return snap
		}},
		IsUnlocked: func() bool { return true },
		// A generous automatic allowance: the fill tests exercise lookahead
		// and search mechanics; the recovery tests set their own bounds.
		Rotating: &RotatingDeps{Chain: chain, Tables: tables, Locks: &RotatingLocks{}, Recovery: &RotatingRecovery{MaxStages: 1 << 20, Timeout: time.Hour},
			LockGeneration: func() uint64 { return f.lockGen }},
	}
	f.svc = svc
	svc.Rotating.Recovery.SetGenerationSource(func() uint64 { return f.lockGen })
	f.secret = &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(seed[:]), GenesisHash: rotatingTestGenesis}
	t.Cleanup(f.secret.Zero)
	return f
}

func (f *rotatingFixture) stageAddress(t testing.TB, stage uint64) types.Address {
	t.Helper()
	a, err := f.ops.StageAddress(f.secret, stage)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *rotatingFixture) table(t testing.TB) *stagetable.Table {
	t.Helper()
	tb, err := f.tables.Table(f.account, rotatingTestGenesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func (f *rotatingFixture) fill(t testing.TB, opts StageFillOptions) StageTableReport {
	t.Helper()
	reports := f.svc.FillStageTables(context.Background(), f.session, opts)
	if len(reports) != 1 || reports[0].Account != f.account.String() {
		t.Fatalf("reports = %+v", reports)
	}
	return reports[0]
}

func TestFillStageTablesFreshAccountIsStageZeroAndLooksAhead(t *testing.T) {
	f := newRotatingFixture(t)
	r := f.fillUntilSettled(t, StageFillOptions{Horizon: 3, Batch: 2})
	if r.Err != nil || !r.Resolved || r.Stage != 0 || r.Pending {
		t.Fatalf("report = %+v", r)
	}
	// Covers stages 0 … 3: live stage plus the horizon.
	if r.Scanned != 4 || f.table(t).Len() != 4 {
		t.Fatalf("scanned = %d, table = %d, want 4", r.Scanned, f.table(t).Len())
	}
	for i := uint64(0); i < 4; i++ {
		if a, _ := f.table(t).Address(i); a != f.stageAddress(t, i) {
			t.Fatalf("table stage %d does not match derivation", i)
		}
	}
	if a, _ := f.table(t).Address(0); a != f.account {
		t.Fatal("stage 0 address is not the account")
	}
	// A second pass with nothing to do changes nothing and derives nothing.
	derivations := 0
	r = f.fill(t, StageFillOptions{Horizon: 3, Pace: func(time.Duration) { derivations++ }})
	if r.Scanned != 4 || r.Pending || derivations != 0 {
		t.Fatalf("idle pass scanned %d with %d derivations", r.Scanned, derivations)
	}
}

func TestFillStageTablesUnresolvedAccountKeepsScanningPastHorizon(t *testing.T) {
	f := newRotatingFixture(t)
	f.chain.authorizer = f.stageAddress(t, 5)
	opts := StageFillOptions{Horizon: 2, Batch: 2}

	// Passes 1 and 2 derive two stages each without finding the authorizer;
	// the horizon (2) does not stop them, because the search runs under an
	// automatic recovery grant whose allowance is what bounds it.
	for pass, wantScanned := range []uint64{2, 4} {
		r := f.fill(t, opts)
		if r.Err != nil || r.Resolved || !r.Pending || r.Scanned != wantScanned {
			t.Fatalf("pass %d report = %+v, want unresolved, pending, %d scanned", pass+1, r, wantScanned)
		}
	}
	// Pass 3 reaches stage 5 with its whole budget and resolves; the
	// lookahead to 5 + 2 is left pending for the next pass.
	r := f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 5 || !r.Pending || r.Scanned != 6 {
		t.Fatalf("pass 3 report = %+v", r)
	}
	r = f.fill(t, opts)
	if r.Err != nil || r.Pending || r.Scanned != 8 {
		t.Fatalf("pass 4 report = %+v, want 8 scanned (stages 0 … 7) and settled", r)
	}
	if stage, ok := f.table(t).Lookup(f.chain.authorizer); !ok || stage != 5 {
		t.Fatalf("lookup of the authorizer = %d, %v", stage, ok)
	}
}

func TestFillStageTablesNeverMatchingAuthorizerIsNeverForeign(t *testing.T) {
	f := newRotatingFixture(t)
	f.chain.authorizer = types.Address{0xde, 0xad, 0xbe, 0xef, 31: 1}
	opts := StageFillOptions{Horizon: 1, Batch: 3}
	var last StageTableReport
	for pass := 0; pass < 3; pass++ {
		last = f.fill(t, opts)
		if last.Err != nil || last.Resolved || !last.Pending || last.Class != ClassUnknown {
			t.Fatalf("pass %d: %+v", pass, last)
		}
		if last.Scanned != uint64(3*(pass+1)) {
			t.Fatalf("pass %d scanned %d", pass, last.Scanned)
		}
	}
	// Progress is in the table, so a fresh Service over the same directory
	// resumes rather than restarting.
	reopened := stagetable.NewStore(storepaths.NewPaths(f.root))
	tb, err := reopened.Table(f.account, rotatingTestGenesis, nil)
	if err != nil || tb.Len() != 9 {
		t.Fatalf("reopened table len %d, err %v", tb.Len(), err)
	}
}

func TestFillStageTablesChainErrorLeavesTableUntouched(t *testing.T) {
	f := newRotatingFixture(t)
	f.chain.err = errors.New("node down")
	r := f.fill(t, StageFillOptions{Horizon: 2})
	if r.Err == nil || r.Resolved || r.Scanned != 0 {
		t.Fatalf("report = %+v", r)
	}
	if f.table(t).Len() != 0 {
		t.Fatal("table grew despite the chain read failing")
	}
}

func TestFillStageTablesCancelledContextKeepsTablePrefixComplete(t *testing.T) {
	f := newRotatingFixture(t)
	f.chain.authorizer = f.stageAddress(t, 40)
	ctx, cancel := context.WithCancel(context.Background())
	derived := 0
	opts := StageFillOptions{Horizon: 1, Batch: 4, MaxDerivations: 40, Pace: func(time.Duration) {
		derived++
		if derived == 6 {
			cancel()
		}
	}}
	reports := f.svc.FillStageTables(ctx, f.session, opts)
	if len(reports) != 1 || reports[0].Err != nil || reports[0].Resolved {
		t.Fatalf("reports = %+v", reports)
	}
	// The first batch of 4 was written whole; the second was cut off after
	// two derivations and its contiguous prefix was kept, so no work is
	// lost and the table has no gap: stages 0 … 5.
	if got := f.table(t).Len(); got != 6 {
		t.Fatalf("table len = %d, want 6", got)
	}
	for i := uint64(0); i < 6; i++ {
		if a, _ := f.table(t).Address(i); a != f.stageAddress(t, i) {
			t.Fatalf("stage %d wrong after cancel", i)
		}
	}
}

func TestFillStageTablesReportsDiscardedTable(t *testing.T) {
	f := newRotatingFixture(t)
	tb := f.table(t)
	if err := tb.Append([]types.Address{f.account}); err != nil {
		t.Fatal(err)
	}
	// Corrupt the file and drop the store's cached copy so Open sees it.
	f.svc.Rotating.Tables = stagetable.NewStore(storepaths.NewPaths(f.root))
	if err := os.WriteFile(tb.Path(), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := f.fill(t, StageFillOptions{Horizon: 1})
	if r.Err != nil || !errors.Is(r.Discarded, stagetable.ErrDiscarded) || !r.Resolved || r.Scanned != 2 {
		t.Fatalf("report = %+v", r)
	}
}

func TestFillStageTablesWithoutDepsIsNoop(t *testing.T) {
	svc := &Service{}
	if reports := svc.FillStageTables(context.Background(), nil, StageFillOptions{}); reports != nil {
		t.Fatalf("reports = %+v", reports)
	}
}

// fillUntilSettled runs passes until none reports pending work.
func (f *rotatingFixture) fillUntilSettled(t *testing.T, opts StageFillOptions) StageTableReport {
	t.Helper()
	for i := 0; i < 64; i++ {
		r := f.fill(t, opts)
		if r.Err != nil || !r.Pending {
			return r
		}
	}
	t.Fatal("fill never settled")
	return StageTableReport{}
}

func TestFillStageTablesHoldsNoAccountLock(t *testing.T) {
	f := newRotatingFixture(t)
	acquired := 0
	opts := StageFillOptions{Horizon: 2, MaxDerivations: 3, Pace: func(time.Duration) {
		// Mid-derivation, a prepare or sign must be able to take the
		// account lock immediately.
		got := make(chan func(), 1)
		go func() { got <- f.svc.Rotating.Locks.Lock(f.account.String()) }()
		select {
		case unlock := <-got:
			unlock()
			acquired++
		case <-time.After(500 * time.Millisecond):
			t.Error("account lock held during table maintenance")
		}
	}}
	r := f.fill(t, opts)
	if r.Err != nil || acquired == 0 {
		t.Fatalf("report %+v, lock acquired %d times", r, acquired)
	}
}

func TestFillStageTablesBoundsLookaheadPerPass(t *testing.T) {
	f := newRotatingFixture(t)
	opts := StageFillOptions{Horizon: 100, MaxDerivations: 5}
	r := f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 0 || !r.Pending || r.Scanned != 5 {
		t.Fatalf("first pass = %+v, want resolved, pending, 5 scanned", r)
	}
	r = f.fill(t, opts)
	if r.Scanned != 10 || !r.Pending {
		t.Fatalf("second pass = %+v, want 10 scanned and pending", r)
	}
}

func TestFillStageTablesStopsWhenTableDeletedMidPass(t *testing.T) {
	f := newRotatingFixture(t)
	derived := 0
	opts := StageFillOptions{Horizon: 20, MaxDerivations: 20, Batch: 4, Pace: func(time.Duration) {
		derived++
		if derived == 2 {
			// As keyadmin.DeleteKey does: the key leaves the inventory first,
			// then its table is deleted.
			f.present = false
			if err := f.tables.Delete(f.account.String()); err != nil {
				t.Error(err)
			}
		}
	}}
	reports := f.svc.FillStageTables(context.Background(), f.session, opts)
	if len(reports) != 1 || reports[0].Err == nil {
		t.Fatalf("reports after delete = %+v, want an error", reports)
	}
	if _, statErr := os.Stat(f.tables.Path(f.account.String())); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("deleted table was recreated by the running fill")
	}
	fresh, err := f.tables.Table(f.account, rotatingTestGenesis, nil)
	if err != nil || fresh.Len() != 0 {
		t.Fatalf("table after delete: len %d, err %v", fresh.Len(), err)
	}
}

// TestFillStageTablesHoldsNoSeedDuringIO pins the lock-drain contract: every
// window in which the seed is loaded is bracketed by KeyUse, and no such
// window is open while the table is being written.
func TestFillStageTablesHoldsNoSeedDuringIO(t *testing.T) {
	f := newRotatingFixture(t)
	var mu sync.Mutex
	active, windows, writesSeen, violations := 0, 0, 0, 0
	opts := StageFillOptions{Horizon: 7, Batch: 2, MaxDerivations: 8, KeyUse: func(ctx context.Context) (context.Context, func()) {
		mu.Lock()
		active++
		windows++
		mu.Unlock()
		var once sync.Once
		return ctx, func() { once.Do(func() { mu.Lock(); active--; mu.Unlock() }) }
	}}
	fsutil.TestHook = func(op fsutil.HookOp, path string) error {
		if strings.HasSuffix(path, ".stages") || strings.Contains(path, ".stages.tmp-") {
			mu.Lock()
			writesSeen++
			if active != 0 {
				violations++
			}
			mu.Unlock()
		}
		return nil
	}
	defer func() { fsutil.TestHook = nil }()

	r := f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Scanned != 8 {
		t.Fatalf("report = %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if writesSeen == 0 {
		t.Fatal("hook saw no table writes")
	}
	if violations != 0 {
		t.Fatalf("seed held during %d of %d table write operations", violations, writesSeen)
	}
	if active != 0 {
		t.Fatalf("%d key-use windows left open", active)
	}
	// One identity window plus one per derivation chunk (Parallel 1): the
	// seed is reloaded per chunk and never kept across a write or sleep.
	if windows < 9 || f.store.loads != windows {
		t.Fatalf("windows = %d, key loads = %d", windows, f.store.loads)
	}
}

// blockingChain never answers until its context ends.
type blockingChain struct{ entered chan struct{} }

func (c *blockingChain) ReadAccount(ctx context.Context, _ []byte, _ types.Address) (chainread.AccountView, error) {
	close(c.entered)
	<-ctx.Done()
	return chainread.AccountView{}, ctx.Err()
}

func TestFillStageTablesBoundsEachChainRead(t *testing.T) {
	f := newRotatingFixture(t)
	chain := &blockingChain{entered: make(chan struct{})}
	f.svc.Rotating.Chain = chain
	started := time.Now()
	r := f.fill(t, StageFillOptions{Horizon: 1, ChainReadTimeout: 200 * time.Millisecond})
	if r.Err == nil || !errors.Is(r.Err, context.DeadlineExceeded) {
		t.Fatalf("report = %+v, want a deadline error", r)
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("chain read deadline not enforced: pass took %v", took)
	}
	if f.table(t).Len() != 0 {
		t.Fatal("table changed although the chain read failed")
	}
}
