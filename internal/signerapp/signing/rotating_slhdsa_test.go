// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type releaseCheckChain struct {
	base      *fakeRotatingChain
	calls     int
	atRelease func()
}

func (c *releaseCheckChain) ReadAccount(ctx context.Context, genesis []byte, account types.Address) (chainread.AccountView, error) {
	c.calls++
	if c.calls == 2 {
		c.atRelease()
	}
	return c.base.ReadAccount(ctx, genesis, account)
}

func TestSLHReleaseRechecksAfterSigning(t *testing.T) {
	for _, mode := range []string{"authorizer", "expiry", "network error", "cancel", "lock generation", "locked", "removed"} {
		t.Run(mode, func(t *testing.T) {
			f, audit := newSigningFixtureFor(t, slhTestType)
			prep := mustPrepare(t, f, f.spend(1000, 1100))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			chain := &releaseCheckChain{base: f.chain, atRelease: func() {
				switch mode {
				case "authorizer":
					f.chain.authorizer = types.Address{9}
				case "expiry":
					f.chain.round = 1095
				case "network error":
					f.chain.err = errors.New("unreachable")
				case "cancel":
					cancel()
				case "lock generation":
					f.lockGen++
				case "locked":
					f.svc.IsUnlocked = func() bool { return false }
				case "removed":
					f.present = false
				}
			}}
			f.svc.Rotating.Chain = chain
			resp, err := f.svc.SignRotatingWithContext(ctx, signerapi.RotatingSignRequest{Account: f.account.String(), Transactions: prep.Transactions}, f.session)
			if chain.calls != 2 {
				t.Fatalf("chain reads %d, want two", chain.calls)
			}
			if resp != nil || err == nil {
				t.Fatalf("released after %s: response %v, error %v", mode, resp, err)
			}
			if len(audit.releases) != 0 {
				t.Fatal("aborted signature audited as released")
			}
			if _, ok := f.svc.Rotating.Releases.Get(f.account.String()); ok {
				t.Fatal("aborted signature remembered as released")
			}
		})
	}
}

func TestSLHRestoredReleaseHasNoLeafHistory(t *testing.T) {
	f, _ := newSigningFixtureFor(t, slhTestType)
	entries := []AuditedRelease{{Account: f.account.String(), Stage: 0, TxID: "B", LastValid: 1100, Reused: true,
		Leaves: []LeafRelease{{TxID: "A"}, {TxID: "B"}}}}
	n, err := f.svc.RebuildReleaseMemory(context.Background(), f.session, entries, StageFillOptions{})
	if err != nil || n != 1 {
		t.Fatalf("restore %d: %v", n, err)
	}
	rec, ok := f.svc.Rotating.Releases.Get(f.account.String())
	if !ok || !rec.StatelessHash || rec.Reused || len(rec.Leaves) != 0 || rec.TxID != "B" {
		t.Fatalf("restored record %+v", rec)
	}
	f.svc.Rotating.Releases.Record(ReleaseRecord{Account: f.account.String(), Stage: 0, TxID: "C", LastValid: 1110, StatelessHash: true})
	_, err = f.svc.RebuildReleaseMemory(context.Background(), f.session, entries, StageFillOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ = f.svc.Rotating.Releases.Get(f.account.String())
	if rec.TxID != "C" || rec.LastValid != 1110 {
		t.Fatal("audit restore overwrote newer release")
	}
}
