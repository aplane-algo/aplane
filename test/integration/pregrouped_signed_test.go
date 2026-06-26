// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestPregroupedSignedVerbatimSubmit is the increment-1 validation: a fully
// plugin-signed, already-grouped group is decoded, validated, and submitted
// verbatim through the engine's pregrouped-signed path — no /plan, no regroup,
// no apsigner, no signer connection — and the confirmed on-chain transaction
// carries the exact group ID the group was built with (proof APlane did not
// mutate the group).
func TestPregroupedSignedVerbatimSubmit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg, err := harness.NewTestnetConfig()
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	funder, err := harness.NewFundTestAccount(cfg.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	ctx := context.Background()
	sp, err := cfg.Client.SuggestedParams().Do(ctx)
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}

	sender := funder.GetAddress()
	sk := funder.GetPrivateKey()

	// Build a 2-txn self-payment group (distinct notes => distinct TxIDs).
	txn0, err := transaction.MakePaymentTxn(sender, sender, 0, []byte("pregrouped-signed-0"), "", sp)
	if err != nil {
		t.Fatalf("make txn0: %v", err)
	}
	txn1, err := transaction.MakePaymentTxn(sender, sender, 0, []byte("pregrouped-signed-1"), "", sp)
	if err != nil {
		t.Fatalf("make txn1: %v", err)
	}

	gid, err := crypto.ComputeGroupID([]types.Transaction{txn0, txn1})
	if err != nil {
		t.Fatalf("compute group id: %v", err)
	}
	txn0.Group = gid
	txn1.Group = gid

	// Sign both (as a plugin's owned signer would) and base64 the signed blobs to
	// mimic plugin "signed" intents.
	_, raw0, err := crypto.SignTransaction(sk, txn0)
	if err != nil {
		t.Fatalf("sign txn0: %v", err)
	}
	_, raw1, err := crypto.SignTransaction(sk, txn1)
	if err != nil {
		t.Fatalf("sign txn1: %v", err)
	}
	encoded := []string{
		base64.StdEncoding.EncodeToString(raw0),
		base64.StdEncoding.EncodeToString(raw1),
	}

	// Decode + validate through the engine's pregrouped-signed entry point.
	group, err := engine.DecodePregroupedSigned(encoded)
	if err != nil {
		t.Fatalf("DecodePregroupedSigned: %v", err)
	}

	// Submit verbatim — engine has an algod client but NO signer connection.
	eng, err := engine.NewEngine(cfg.Network, engine.WithAlgodClient(cfg.Client))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	res, err := eng.SubmitPregroupedSigned(ctx, group)
	if err != nil {
		t.Fatalf("SubmitPregroupedSigned: %v\n%s", err, res.Output)
	}
	if len(res.TxIDs) != 2 {
		t.Fatalf("expected 2 txIDs, got %d", len(res.TxIDs))
	}

	// The confirmed on-chain transaction must carry the exact group ID we built.
	info, onchain, err := cfg.Client.PendingTransactionInformation(res.TxIDs[0]).Do(ctx)
	if err != nil {
		t.Fatalf("pending txn info: %v", err)
	}
	if info.ConfirmedRound == 0 {
		t.Fatalf("txn %s not confirmed", res.TxIDs[0])
	}
	if onchain.Txn.Group != gid {
		t.Fatalf("on-chain group id %x != built group id %x (APlane mutated the group)", onchain.Txn.Group, gid)
	}
}
