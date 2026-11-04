// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"testing"

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
			if n, rebuildErr := f.svc.RebuildReleaseMemory(context.Background(), f.session, []AuditedRelease{{
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
