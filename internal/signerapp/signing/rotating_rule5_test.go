// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strconv"
	"sync"
	"testing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapp/chainread"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

// regrouped is a prepared group changed and given the group ID of what it
// became, so it decodes as a consistent group and only the comparison with
// the group the signer would build can refuse it.
func regrouped(t *testing.T, prepared []string, change func([]types.Transaction) []types.Transaction) []string {
	t.Helper()
	group := make([]types.Transaction, len(prepared))
	for i, h := range prepared {
		txn, err := txnutil.DecodePrefixedHex(h)
		if err != nil {
			t.Fatal(err)
		}
		txn.Group = types.Digest{}
		group[i] = txn
	}
	group = change(group)
	gid, err := algocrypto.ComputeGroupID(group)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(group))
	for i := range group {
		group[i].Group = gid
		out[i] = txnutil.EncodeWithPrefixHex(group[i])
	}
	return out
}

// Rule 5: the presented group must be, byte for byte, the group the signer
// builds from the spend. A group that is consistent in itself but has a
// changed dummy, one dummy fewer or one more is refused, and the refusal
// says how it differs.
func TestRotatingSignRefusesAGroupItWouldNotBuild(t *testing.T) {
	f, audit := newSigningFixture(t)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	n := len(prep.Transactions)
	if n < 3 {
		t.Fatalf("the prepared group has %d transactions; this test needs two dummies", n)
	}
	tests := []struct {
		name   string
		change func([]types.Transaction) []types.Transaction
		want   string
	}{
		// A changed dummy changes the group ID, which every transaction
		// carries, so the first to differ is always the spend.
		{"a dummy's note changed", func(g []types.Transaction) []types.Transaction {
			g[1].Note = []byte("x")
			return g
		}, "transaction 1 differs from the group the signer would build (dummies, fees and group ID must be exactly the prepared ones)"},
		{"the last dummy's note changed", func(g []types.Transaction) []types.Transaction {
			g[len(g)-1].Note = []byte("x")
			return g
		}, "transaction 1 differs from the group the signer would build (dummies, fees and group ID must be exactly the prepared ones)"},
		{"a dummy dropped", func(g []types.Transaction) []types.Transaction {
			return g[:len(g)-1]
		}, "group has " + strconv.Itoa(n-1) + " transactions; the spend needs " + strconv.Itoa(n)},
		{"a dummy added", func(g []types.Transaction) []types.Transaction {
			extra := g[len(g)-1]
			extra.Note = []byte("one more")
			return append(g, extra)
		}, "group has " + strconv.Itoa(n+1) + " transactions; the spend needs " + strconv.Itoa(n)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.sign(t, regrouped(t, prep.Transactions, tt.change))
			if err == nil || err.Kind != ErrorBadRequest || err.Message != tt.want {
				t.Fatalf("error = %v, want bad request %q", err, tt.want)
			}
		})
	}
	if len(audit.releases) != 0 {
		t.Fatalf("a refused group was released %d times", len(audit.releases))
	}
	// The group as prepared, regrouped to itself, still signs.
	if _, err := f.sign(t, regrouped(t, prep.Transactions, func(g []types.Transaction) []types.Transaction { return g })); err != nil {
		t.Fatalf("the prepared group was refused: %v", err)
	}
}

// readsRecordingChain records the account of every chain read.
type readsRecordingChain struct {
	noStageLookup
	base *fakeRotatingChain
	mu   sync.Mutex
	read []types.Address
}

func (c *readsRecordingChain) ReadAccount(ctx context.Context, genesisHash []byte, account types.Address) (chainread.AccountView, error) {
	c.mu.Lock()
	c.read = append(c.read, account)
	c.mu.Unlock()
	return c.base.ReadAccount(ctx, genesisHash, account)
}

// A stateless signature reads the chain twice, before signing and after, and
// both reads are of the account: never of the stage address that signs for
// it.
func TestSLHReleaseReadsTheAccountBothTimes(t *testing.T) {
	f, _ := newSigningFixtureFor(t, slhTestType)
	// Past stage 0 the stage that signs has its own address; at stage 0 it
	// is the account's, and the two could not be told apart.
	f.chain.authorizer = f.stageAddress(t, 1)
	prep := mustPrepare(t, f, f.spend(1000, 1100))
	if prep.Stage != 1 {
		t.Fatalf("prepared at stage %d, want 1", prep.Stage)
	}
	chain := &readsRecordingChain{base: f.chain}
	f.svc.Rotating.Chain = chain
	mustSign(t, f, prep.Transactions)
	if len(chain.read) != 2 {
		t.Fatalf("the sign read the chain %d times, want 2", len(chain.read))
	}
	for i, account := range chain.read {
		if account != f.account {
			t.Fatalf("read %d was of %s, want the account %s", i+1, account, f.account)
		}
	}
}
