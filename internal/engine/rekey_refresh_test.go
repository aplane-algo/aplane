// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestRefreshRekeyedSendersUpdatesStaleAuthEntry is the regression test for the
// auth-cache staleness that broke JS/MCP rekeys: the pre-submit hook caches a
// sender's pre-rekey authorizer (here, "not rekeyed" -> ""), and being
// fill-on-miss it never corrects that entry. After a confirmed rekey the engine
// must overwrite it with the new on-chain authorizer so the signer authorizes
// subsequent transactions through the rekeyed-to LogicSig.
func TestRefreshRekeyedSendersUpdatesStaleAuthEntry(t *testing.T) {
	node := testAddress(40)
	allowlist := testAddress(41)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:                     node.String(),
		AuthAddr:                    allowlist.String(), // on-chain: rekeyed to the allowlist lsig
		Amount:                      1_000_000,
		AmountWithoutPendingRewards: 1_000_000,
		MinBalance:                  100_000,
		Status:                      "Offline",
	})
	eng := setupEngineWithMockAlgod(t, transport)

	// Reproduce the poisoned cache: the pre-submit hook recorded the sender as
	// "not rekeyed" while the rekey was still in flight.
	eng.AuthCache.AuthAddresses[node.String()] = ""

	var rekeyTxn types.Transaction
	rekeyTxn.Sender = node
	rekeyTxn.RekeyTo = allowlist

	if err := eng.refreshRekeyedSenders(context.Background(), []types.Transaction{rekeyTxn}); err != nil {
		t.Fatalf("refreshRekeyedSenders() error = %v, want nil", err)
	}

	got, ok := eng.AuthCache.GetAuthAddress(node.String())
	if !ok || got != allowlist.String() {
		t.Fatalf("auth cache after rekey = %q (cached=%v); want %q", got, ok, allowlist.String())
	}
}

// TestRefreshRekeyedSendersIgnoresNonRekeyTxns verifies the hook is gated on the
// RekeyTo field: an ordinary payment must not trigger an auth re-query, so a
// stale entry for that sender is left untouched.
func TestRefreshRekeyedSendersIgnoresNonRekeyTxns(t *testing.T) {
	sender := testAddress(42)
	onChainAuth := testAddress(43)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:                     sender.String(),
		AuthAddr:                    onChainAuth.String(),
		Amount:                      1_000_000,
		AmountWithoutPendingRewards: 1_000_000,
		MinBalance:                  100_000,
		Status:                      "Offline",
	})
	eng := setupEngineWithMockAlgod(t, transport)
	eng.AuthCache.AuthAddresses[sender.String()] = "" // deliberately stale

	var payment types.Transaction
	payment.Sender = sender // no RekeyTo set

	if err := eng.refreshRekeyedSenders(context.Background(), []types.Transaction{payment}); err != nil {
		t.Fatalf("refreshRekeyedSenders() error = %v, want nil", err)
	}
	if got, _ := eng.AuthCache.GetAuthAddress(sender.String()); got != "" {
		t.Fatalf("non-rekey txn refreshed auth cache to %q; want it left unchanged (\"\")", got)
	}
}

// TestRefreshRekeyedSendersReportsRefreshFailure verifies that when the
// post-confirmation auth-address query fails, the error is returned (so callers
// can surface a warning) rather than silently swallowed.
func TestRefreshRekeyedSendersReportsRefreshFailure(t *testing.T) {
	known := testAddress(44)
	unknown := testAddress(45) // intentionally absent from the mock -> algod 404
	allowlist := testAddress(46)

	transport := newAccountMockTransport(t)
	transport.addAccount(known.String(), 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	var rekeyTxn types.Transaction
	rekeyTxn.Sender = unknown
	rekeyTxn.RekeyTo = allowlist

	if err := eng.refreshRekeyedSenders(context.Background(), []types.Transaction{rekeyTxn}); err == nil {
		t.Fatal("refreshRekeyedSenders() error = nil; want a non-nil refresh failure")
	}
}
