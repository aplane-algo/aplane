// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
)

func testPreparedTxn(t *testing.T, from, to types.Address, note string, lsigArgs map[string][]byte) *TransactionPrepResult {
	t.Helper()

	sp := types.SuggestedParams{
		Fee:             1000,
		FlatFee:         true,
		FirstRoundValid: 1,
		LastRoundValid:  100,
		GenesisID:       "testnet-v1.0",
		GenesisHash:     []byte("12345678901234567890123456789012"),
	}

	txn, err := transaction.MakePaymentTxn(from.String(), to.String(), 1234, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	return &TransactionPrepResult{
		Transaction: txn,
		SigningContext: &SigningContext{
			Address:     from.String(),
			SigningAddr: from.String(),
			KeyType:     "ed25519",
		},
		LsigArgs: lsigArgs,
	}
}

func TestPrepareGroupRejectsEmpty(t *testing.T) {
	if _, err := PrepareGroup(); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error")
	}
}

func TestPrepareGroupRejectsSingle(t *testing.T) {
	prep := testPreparedTxn(t, testAddress(1), testAddress(2), "one", nil)
	if _, err := PrepareGroup(prep); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error for single transaction")
	}
}

func TestPrepareGroupRejectsNilEntry(t *testing.T) {
	prep := testPreparedTxn(t, testAddress(1), testAddress(2), "one", nil)
	if _, err := PrepareGroup(prep, nil); err == nil {
		t.Fatal("PrepareGroup() error = nil, want error for nil entry")
	}
}

func TestPrepareGroupLeavesUngroupedAndPreservesMetadata(t *testing.T) {
	prep1 := testPreparedTxn(t, testAddress(1), testAddress(2), "first", map[string][]byte{"foo": []byte("bar")})
	prep2 := testPreparedTxn(t, testAddress(3), testAddress(4), "second", nil)

	group, err := PrepareGroup(prep1, prep2)
	if err != nil {
		t.Fatalf("PrepareGroup() error = %v", err)
	}

	if len(group.Entries) != 2 {
		t.Fatalf("len(group.Entries) = %d, want 2", len(group.Entries))
	}

	// Group ID must NOT be assigned — the signer assigns it after adding
	// any required dummy transactions (e.g. for Falcon LogicSig budget).
	for i, entry := range group.Entries {
		if entry.Transaction.Group != (types.Digest{}) {
			t.Fatalf("entry %d has non-zero group ID %x, want ungrouped", i, entry.Transaction.Group)
		}
	}

	if string(group.Entries[0].Transaction.Note) != "first" || string(group.Entries[1].Transaction.Note) != "second" {
		t.Fatalf("transaction ordering was not preserved")
	}
	if group.Entries[0].SigningContext.Address != prep1.SigningContext.Address {
		t.Fatalf("signing context not preserved: got %s want %s", group.Entries[0].SigningContext.Address, prep1.SigningContext.Address)
	}
	if string(group.LsigArgsMap()[0]["foo"]) != "bar" {
		t.Fatalf("lsig args not preserved: %+v", group.LsigArgsMap())
	}
	if group.LsigArgsMap()[1] != nil {
		t.Fatalf("unexpected lsig args for second entry: %+v", group.LsigArgsMap()[1])
	}
}

func TestPreparePaymentAndMethodCall_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")

	_, err := PreparePaymentMethodGroupWithContext(context.Background(), eng,
		SendPaymentParams{
			From:   testAddress(1).String(),
			To:     testAddress(2).String(),
			Amount: 1000,
		},
		MethodAppCallParams{
			ABIPath: testFixturePath(t, "testapp", "aplane_test.json"),
			Method:  "deposit",
			RawAppCallParams: RawAppCallParams{
				AppID: 123,
				From:  testAddress(1).String(),
			},
		},
	)
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

// The arguments are checked against the signing keys once the signing state
// is refreshed, and before anything is sent to the signer.
func TestExecutePreparedGroupValidatesLsigArgsBeforeSubmit(t *testing.T) {
	lsigAddr := testAddress(1).String()
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(lsigAddr, "aplane.htlc.v1")
	signerCache.SetGenericLsig(lsigAddr, true)
	signerCache.SetSigningArgs(lsigAddr, []cache.SigningArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
	})
	signerCache.AddAddress(testAddress(3).String(), "ed25519")
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected signer request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})
	algodClient, server := consensusTestAlgod(t, string(protocol.ConsensusV43), nil)
	defer server.Close()
	eng.AlgodClient = algodClient
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[lsigAddr] = ""
	eng.AuthCache.AuthAddresses[testAddress(3).String()] = ""

	prep1 := testPreparedTxn(t, testAddress(1), testAddress(2), "first", nil)
	prep2 := testPreparedTxn(t, testAddress(3), testAddress(4), "second", nil)

	group, err := PrepareGroup(prep1, prep2)
	if err != nil {
		t.Fatalf("PrepareGroup() error = %v", err)
	}

	_, err = eng.ExecutePreparedGroup(context.Background(), group, false)
	if err == nil {
		t.Fatal("ExecutePreparedGroup() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "transaction 1: invalid LogicSig arguments: missing required argument: preimage") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// A composed LogicSig's required signing argument is checked on the client
// too, not only a generic one's: left out, it is refused before the signer is
// asked for anything, so nothing is planned or put to approval.
func TestSignAndSubmitRefusesAComposedKeysMissingArgumentBeforeTheSigner(t *testing.T) {
	composed := testAddress(1).String()
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(composed, "example.composed-hashlock.v1")
	signerCache.SetSigningArgs(composed, []cache.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true}})
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected signer request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})
	algodClient, server := consensusTestAlgod(t, string(protocol.ConsensusV43), nil)
	defer server.Close()
	eng.AlgodClient = algodClient
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[composed] = ""

	_, err := eng.SignAndSubmit(context.Background(), testPreparedTxn(t, testAddress(1), testAddress(2), "spend", nil), false)
	if err == nil || !strings.Contains(err.Error(), "transaction 1: invalid LogicSig arguments: missing required argument: secret") {
		t.Fatalf("SignAndSubmit() error = %v, want the missing argument refused", err)
	}
}

func TestValidateSubmitLsigArgsAcceptsValidArgs(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	lsigAddr := testAddress(1).String()
	eng.SignerCache.SetGenericLsig(lsigAddr, true)
	eng.SignerCache.SetSigningArgs(lsigAddr, []cache.SigningArgInfo{
		{Name: "preimage", Type: "bytes", Required: true},
	})

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "first", map[string][]byte{"preimage": []byte("ok")}).Transaction
	if err := eng.validateSubmitLsigArgs([]types.Transaction{txn}, []map[string][]byte{{"preimage": []byte("ok")}}); err != nil {
		t.Fatalf("validateSubmitLsigArgs() error = %v", err)
	}
}
