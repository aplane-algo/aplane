// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
	coresigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/signerops"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// heldSeed is a seed load parked mid-request: the context it was loaded under.
type heldSeed struct {
	ctx context.Context
}

// holdingSeedStore hands out a rotating seed and parks one load, chosen by its
// position in the request, until the test lets it go. The decrypted copy exists
// by then, so the request is holding a seed.
type holdingSeedStore struct {
	secret *coresigning.RotatingKeyMaterial
	holdAt int32
	loads  atomic.Int32
	held   chan heldSeed
	resume chan struct{}
	// parked is the seed the parked load handed out, once it has.
	parked atomic.Pointer[[]byte]
}

func (s *holdingSeedStore) Get(ctx context.Context, _ string) (*coresigning.KeyMaterial, error) {
	copied := &coresigning.RotatingKeyMaterial{Seed: bytes.Clone(s.secret.Seed), GenesisHash: bytes.Clone(s.secret.GenesisHash)}
	if s.loads.Add(1) == s.holdAt {
		seed := copied.Seed
		s.parked.Store(&seed)
		s.held <- heldSeed{ctx: ctx}
		<-s.resume
	}
	return &coresigning.KeyMaterial{Type: rotatingkey.RotatingTripleWotscV1, Category: keys.CategoryRotatingLsig, Value: copied}, nil
}

// windowEnd is what the parked load's key use saw as it ended: whether the
// seed was zero by then and whether the lock had already finished.
type windowEnd struct {
	ended, zeroed, lockDone atomic.Bool
}

// observeWindowEnd wraps the service's key use so that the first window to end
// after the parked load records a windowEnd before it releases. That runs on
// the request's own goroutine, after the request zeroed the seed if it did, so
// reading the seed there can't race with the zeroing.
func observeWindowEnd(fx *rotatingLockFixture, store *holdingSeedStore, locked <-chan struct{}) *windowEnd {
	end := &windowEnd{}
	inner := fx.svc.Rotating.KeyUse
	fx.svc.Rotating.KeyUse = func(ctx context.Context) (context.Context, func()) {
		useCtx, release := inner(ctx)
		return useCtx, func() {
			if seed := store.parked.Load(); seed != nil && !end.ended.Swap(true) {
				end.zeroed.Store(allZero(*seed))
				select {
				case <-locked:
					end.lockDone.Store(true)
				default:
				}
			}
			release()
		}
	}
	return end
}

// rotatingLockFixture is an unlocked signer holding one rotating account, with
// its real runtime, signing service and a mock node.
type rotatingLockFixture struct {
	ir      *productruntime.Runtime
	svc     *signersigning.Service
	node    *mockAccountNode
	account types.Address
	secret  *coresigning.RotatingKeyMaterial
	genesis [32]byte
}

func newRotatingLockFixture(t *testing.T) *rotatingLockFixture {
	t.Helper()
	server, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	ir := server.productRuntime()
	node := &mockAccountNode{}
	server.config.Algod = config.AlgodConfig{"testnet": &config.AlgodNetworkConfig{Server: "http://mock-algod"}}
	server.makeAlgod = func(serverURL, token string) (*algod.Client, error) {
		return algod.MakeClientWithTransport(serverURL, token, nil, node.transport())
	}
	account, secret := installRotatingKey(t, server)
	node.set("", 100)
	ir.Config().SetUserAutoApprove(true)
	fx := &rotatingLockFixture{
		ir:      ir,
		svc:     server.newSigningServiceWithAudit(ir, &signingAuditLogger{log: server.auditLog}),
		node:    node,
		account: account,
		secret:  secret,
	}
	gh, _ := base64.StdEncoding.DecodeString(testnetGenesisB64)
	copy(fx.genesis[:], gh)
	return fx
}

func (fx *rotatingLockFixture) stageAddress(t *testing.T, stage uint64) types.Address {
	t.Helper()
	a, err := signerops.StageOps{}.StageAddress(fx.secret, stage)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (fx *rotatingLockFixture) prepare(session *keystore.KeySession) (*signerapi.RotatingPrepareResponse, *signersigning.ServiceError) {
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: fx.account, Fee: 1000, FirstValid: 100, LastValid: 200, GenesisHash: fx.genesis},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: fx.account},
	}
	return fx.svc.PrepareRotatingWithContext(context.Background(), signerapi.RotatingPrepareRequest{
		Account: fx.account.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(txn),
	}, session)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

// Every rotating seed load in prepare and sign is a key use the real lock
// waits for. Each case parks one load while the request holds the decrypted
// seed and starts a lock: the lock has to cancel that load's context and must
// not finish while the load stays parked, given time to, and the seed has to
// be zeroed before that load's key use ends, while the lock is still waiting.
// The request then answers locked.
func TestLockWaitsForEveryRotatingSeedLoad(t *testing.T) {
	prepareRequest := func(t *testing.T, fx *rotatingLockFixture) func(*keystore.KeySession) *signersigning.ServiceError {
		return func(session *keystore.KeySession) *signersigning.ServiceError {
			_, err := fx.prepare(session)
			return err
		}
	}
	signRequest := func(t *testing.T, fx *rotatingLockFixture) func(*keystore.KeySession) *signersigning.ServiceError {
		prep, err := fx.prepare(fx.ir.SnapshotKeySession())
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		return func(session *keystore.KeySession) *signersigning.ServiceError {
			_, err := fx.svc.SignRotatingWithContext(context.Background(), signerapi.RotatingSignRequest{
				Account: fx.account.String(), Transactions: prep.Transactions,
			}, session)
			return err
		}
	}
	// The account has rotated to stage 1, which the table doesn't know yet:
	// prepare has to find it by searching.
	rotatedUnknown := func(t *testing.T, fx *rotatingLockFixture) {
		fx.node.set(fx.stageAddress(t, 1).String(), 100)
	}
	// The account has rotated to stage 1, which the table lists but no
	// derivation since the last reload has proven: prepare derives it again.
	rotatedUnverified := func(t *testing.T, fx *rotatingLockFixture) {
		stage1 := fx.stageAddress(t, 1)
		table, err := fx.ir.StageTables().Table(fx.account, fx.genesis[:], nil, rotatingkey.RotatingTripleWotscV1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := table.RecordDerived(0, []types.Address{fx.account, stage1}); err != nil {
			t.Fatal(err)
		}
		fx.ir.StageTables().Invalidate()
		if table.Verified(1, stage1) {
			t.Fatal("the table still trusts stage 1")
		}
		fx.node.set(stage1.String(), 100)
	}

	for _, tc := range []struct {
		name string
		// hold is the request's seed load to park: prepare loads for the
		// account's identity and then derives; sign loads for the identity,
		// derives the target before approval and signs after it.
		hold    int32
		arrange func(*testing.T, *rotatingLockFixture)
		request func(*testing.T, *rotatingLockFixture) func(*keystore.KeySession) *signersigning.ServiceError
	}{
		{name: "prepare/account identity", hold: 1, request: prepareRequest},
		{name: "prepare/live stage found by search", hold: 2, arrange: rotatedUnknown, request: prepareRequest},
		{name: "prepare/live stage from an unproven table entry", hold: 2, arrange: rotatedUnverified, request: prepareRequest},
		{name: "prepare/target", hold: 2, request: prepareRequest},
		{name: "sign/account identity", hold: 1, request: signRequest},
		{name: "sign/target", hold: 2, request: signRequest},
		{name: "sign/signature", hold: 3, request: signRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newRotatingLockFixture(t)
			if tc.arrange != nil {
				tc.arrange(t, fx)
			}
			run := tc.request(t, fx)
			store := &holdingSeedStore{secret: fx.secret, holdAt: tc.hold, held: make(chan heldSeed, 1), resume: make(chan struct{})}
			locked := make(chan struct{})
			end := observeWindowEnd(fx, store, locked)
			session := keystore.NewKeySession(store)
			session.InitializeSession()
			t.Cleanup(session.Destroy)
			resumed := false
			resume := func() {
				if !resumed {
					resumed = true
					close(store.resume)
				}
			}
			defer resume()

			done := make(chan *signersigning.ServiceError, 1)
			go func() { done <- run(session) }()
			var held heldSeed
			select {
			case held = <-store.held:
			case err := <-done:
				t.Fatalf("the request ended before seed load %d: %v", tc.hold, err)
			case <-time.After(30 * time.Second):
				t.Fatalf("the request never reached seed load %d", tc.hold)
			}

			go func() {
				fx.ir.Lock()
				close(locked)
			}()
			select {
			case <-held.ctx.Done():
				// The lock is draining and this load is a key use it cancelled.
			case <-locked:
				t.Fatal("the lock finished while the request held the seed")
			case <-time.After(30 * time.Second):
				t.Fatal("the lock never cancelled the load: it isn't a key use")
			}
			// The load is still parked. A lock that cancels without waiting
			// finishes well within this.
			select {
			case <-locked:
				t.Fatal("the lock finished while the request held the seed")
			case <-time.After(100 * time.Millisecond):
			}
			resume()
			select {
			case <-locked:
			case <-time.After(30 * time.Second):
				t.Fatal("the lock never finished after the request let go of the seed")
			}
			switch {
			case !end.ended.Load():
				t.Fatal("the parked load's key use never ended")
			case end.lockDone.Load():
				t.Fatal("the lock finished before the parked load's key use ended")
			case !end.zeroed.Load():
				t.Fatal("the parked load's key use ended before the request zeroed the seed")
			}
			select {
			case err := <-done:
				if err == nil || err.Kind != signersigning.ErrorLocked {
					t.Fatalf("error = %v, want the locked error", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the request never finished after the lock")
			}
			if n := store.loads.Load(); n != tc.hold {
				t.Fatalf("%d seed loads, want %d: the request loaded the seed again after the lock", n, tc.hold)
			}
		})
	}
}
