// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/stagetable"
	"github.com/aplane-algo/aplane/internal/storepaths"
	rotatingsignerreg "github.com/aplane-algo/aplane/lsig/rotatinghybrid/signerreg"

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

type rotatingKeyStore struct{ seed []byte }

func (s *rotatingKeyStore) Get(context.Context, string) (*coresigning.KeyMaterial, error) {
	return &coresigning.KeyMaterial{
		Type:     rotatingkey.RotatingHybridV1,
		Category: keys.CategoryRotatingLsig,
		Value: &coresigning.RotatingKeyMaterial{
			Seed:        bytes.Clone(s.seed),
			GenesisHash: bytes.Clone(rotatingTestGenesis),
		},
	}, nil
}

type rotatingFixture struct {
	svc     *Service
	chain   *fakeRotatingChain
	root    string
	tables  *stagetable.Store
	session *keystore.KeySession
	account types.Address
	secret  *coresigning.RotatingKeyMaterial
	ops     coresigning.RotatingStageOps
}

func newRotatingFixture(t *testing.T) *rotatingFixture {
	t.Helper()
	rotatingsignerreg.Register()
	// A fresh random seed per fixture: the tests compare the table against
	// derivations from the same seed, so no known vector is needed.
	var seed rotatinghybrid.Seed
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seed.Zero)
	var gh [32]byte
	copy(gh[:], rotatingTestGenesis)
	payload, address, err := rotatingsignerreg.NewKeyPayload(&seed, gh)
	if err != nil {
		t.Fatal(err)
	}
	payload.ZeroSecrets()
	account, _ := types.DecodeAddress(address)

	argumentBytes := uint64(rotatingkey.RotatingMaxArgumentBytes)
	profile, err := lsigresource.Materialize(rotatingkey.RotatingMaxProgramBytes, &argumentBytes, nil,
		lsigresource.DefaultOpcodeProfile(rotatingkey.RotatingMaxOpcodeCost))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	tables := stagetable.NewStore(storepaths.NewPaths(root))
	chain := &fakeRotatingChain{round: 1000}
	session := keystore.NewKeySession(&rotatingKeyStore{seed: bytes.Clone(seed[:])})
	session.InitializeSession()
	ops, err := coresigning.GetRotatingStageOps(rotatingkey.RotatingHybridV1)
	if err != nil {
		t.Fatal(err)
	}

	svc := &Service{
		Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
			return PlannerRuntimeSnapshot{
				KeyFiles: map[string]string{address: "keys/" + address + ".key"},
				KeyTypes: map[string]string{address: rotatingkey.RotatingHybridV1},
				KeyMetadata: map[string]PlannerKeyMetadata{address: {
					Category:          keys.CategoryRotatingLsig,
					LogicSigResources: &profile,
				}},
			}
		}},
		IsUnlocked: func() bool { return true },
		Rotating:   &RotatingDeps{Chain: chain, Tables: tables, Locks: &RotatingLocks{}},
	}
	f := &rotatingFixture{
		svc: svc, chain: chain, root: root, tables: tables, session: session, account: account, ops: ops,
		secret: &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(seed[:]), GenesisHash: rotatingTestGenesis},
	}
	t.Cleanup(f.secret.Zero)
	return f
}

func (f *rotatingFixture) stageAddress(t *testing.T, stage uint64) types.Address {
	t.Helper()
	a, err := f.ops.StageAddress(f.secret, stage)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (f *rotatingFixture) table(t *testing.T) *stagetable.Table {
	t.Helper()
	tb, err := f.tables.Table(f.account, rotatingTestGenesis)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func (f *rotatingFixture) fill(t *testing.T, opts StageFillOptions) StageTableReport {
	t.Helper()
	reports := f.svc.FillStageTables(context.Background(), f.session, opts)
	if len(reports) != 1 || reports[0].Account != f.account.String() {
		t.Fatalf("reports = %+v", reports)
	}
	return reports[0]
}

func TestFillStageTablesFreshAccountIsStageZeroAndLooksAhead(t *testing.T) {
	f := newRotatingFixture(t)
	r := f.fill(t, StageFillOptions{Horizon: 3, Batch: 2})
	if r.Err != nil || !r.Resolved || r.Stage != 0 {
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
	if r.Scanned != 4 || derivations != 0 {
		t.Fatalf("idle pass scanned %d with %d derivations", r.Scanned, derivations)
	}
}

func TestFillStageTablesUnresolvedAccountKeepsScanningPastHorizon(t *testing.T) {
	f := newRotatingFixture(t)
	f.chain.authorizer = f.stageAddress(t, 5)
	opts := StageFillOptions{Horizon: 2, Batch: 2}

	// Passes 1 and 2 derive two stages each without finding the authorizer;
	// the horizon (2) does not stop them.
	for pass, wantScanned := range []uint64{2, 4} {
		r := f.fill(t, opts)
		if r.Err != nil || r.Resolved || r.Scanned != wantScanned {
			t.Fatalf("pass %d report = %+v, want unresolved with %d scanned", pass+1, r, wantScanned)
		}
	}
	// Pass 3 reaches stage 5, resolves, and looks ahead to 5 + 2.
	r := f.fill(t, opts)
	if r.Err != nil || !r.Resolved || r.Stage != 5 {
		t.Fatalf("pass 3 report = %+v", r)
	}
	if r.Scanned != 8 {
		t.Fatalf("scanned = %d, want 8 (stages 0 … 7)", r.Scanned)
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
		if last.Err != nil || last.Resolved {
			t.Fatalf("pass %d: %+v", pass, last)
		}
		if last.Scanned != uint64(3*(pass+1)) {
			t.Fatalf("pass %d scanned %d", pass, last.Scanned)
		}
	}
	// Progress is in the table, so a fresh Service over the same directory
	// resumes rather than restarting.
	reopened := stagetable.NewStore(storepaths.NewPaths(f.root))
	tb, err := reopened.Table(f.account, rotatingTestGenesis)
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
