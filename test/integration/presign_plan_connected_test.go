// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestPresignPlanConnectedEngineSubmit exercises the WHOLE pre-sign planning loop
// end to end against a real apsigner and a real network — the path a Falcon-funded
// Mithras deposit will take, with a generic stub plugin (no Mithras dependency):
//
//	engine.SignAndSubmitWithPluginSigners
//	  -> /plan          (real apsigner: canonicalize and budget v42 resources)
//	  -> signSlots      (the "plugin" signs its owned slot over the canonical bytes)
//	  -> /sign          (real apsigner Falcon-signs the managed funder slot)
//	  -> submit         (real localnet algod)
//
// The plugin callback here is in-process: the manager's signTransactions JSON-RPC
// hop is covered separately by manager_presign_test.go, so the closure faithfully
// stands in for it. The engine treats a plugin-signed slot opaquely (it checks only
// that the signed txn matches the canonical bytes), so an ed25519-signed slot
// exercises the same engine path a Mithras verifier LogicSig slot would.
func TestPresignPlanConnectedEngineSubmit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	cfg, err := harness.NewTestnetConfig()
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	// --- apsigner with a managed Falcon funder key ---
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	falconAddr, err := apadmin.GenerateKey("presign connected harness funder")
	if err != nil {
		t.Fatalf("generate falcon key: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("start unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	tokenBytes, err := os.ReadFile(signerd.GetTokenPath())
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	token := string(bytes.TrimSpace(tokenBytes))

	if !waitForKey(t, signerd.GetURL(), token, falconAddr, 15*time.Second) {
		t.Fatalf("falcon key %s not loaded", falconAddr)
	}

	// --- fund the managed Falcon slot and a plugin-owned slot ---
	funder, err := harness.NewFundTestAccount(cfg.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	plugin := crypto.GenerateAccount() // the "plugin"-owned signer
	if err := funder.FundMicroAlgosAndWait(falconAddr, 1_000_000); err != nil {
		t.Fatalf("fund falcon funder: %v", err)
	}
	if err := funder.FundMicroAlgosAndWait(plugin.Address.String(), 1_000_000); err != nil {
		t.Fatalf("fund plugin account: %v", err)
	}

	// --- engine connected to the real apsigner + algod ---
	eng, err := engine.NewEngine(cfg.Network, engine.WithAlgodClient(cfg.Client))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	if !eng.IsConnected() {
		t.Fatal("engine not connected to signer after wiring SignerClient")
	}

	ctx := context.Background()
	sp, err := cfg.Client.SuggestedParams().Do(ctx)
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}

	// Ungrouped draft: a managed Falcon slot + a plugin-owned slot. /plan computes
	// the group ID. Under v42 the plugin slot supplies the second group member
	// required by Falcon's argument pool, so no dummy is needed.
	managedTxn, err := transaction.MakePaymentTxn(falconAddr, falconAddr, 0, []byte("presign-connected-managed"), "", sp)
	if err != nil {
		t.Fatalf("make managed txn: %v", err)
	}
	pluginTxn, err := transaction.MakePaymentTxn(plugin.Address.String(), plugin.Address.String(), 0, []byte("presign-connected-plugin"), "", sp)
	if err != nil {
		t.Fatalf("make plugin txn: %v", err)
	}

	refs := map[string]string{plugin.Address.String(): "plugin-ref-1"}

	// The plugin signs only the slots it owns, over the exact canonical bytes /plan
	// produced. A wrong-key or substituted txn would be rejected by the engine's
	// anti-substitution guard.
	signSlots := func(reqs []engine.PluginSlotSignRequest) ([]engine.PluginSlotSigned, error) {
		out := make([]engine.PluginSlotSigned, len(reqs))
		for i, r := range reqs {
			raw, derr := base64.StdEncoding.DecodeString(r.Encoded)
			if derr != nil {
				return nil, derr
			}
			var txn types.Transaction
			if derr := msgpack.Decode(raw, &txn); derr != nil {
				return nil, derr
			}
			_, stx, serr := crypto.SignTransaction(plugin.PrivateKey, txn)
			if serr != nil {
				return nil, serr
			}
			out[i] = engine.PluginSlotSigned{Index: r.Index, Encoded: base64.StdEncoding.EncodeToString(stx)}
		}
		return out, nil
	}

	res, err := eng.SignAndSubmitWithPluginSigners(ctx, []types.Transaction{managedTxn, pluginTxn}, refs, nil, signSlots, nil)
	if err != nil {
		out := ""
		if res != nil {
			out = res.Output
		}
		t.Fatalf("SignAndSubmitWithPluginSigners: %v\n%s", err, out)
	}

	if len(res.TxIDs) != 2 {
		t.Fatalf("expected the two real v42 group members with no dummy, got %d txids", len(res.TxIDs))
	}

	// The group confirms atomically; verify the managed Falcon slot landed on-chain.
	info, _, err := cfg.Client.PendingTransactionInformation(res.TxIDs[0]).Do(ctx)
	if err != nil {
		t.Fatalf("pending txn info: %v", err)
	}
	if info.ConfirmedRound == 0 {
		t.Fatalf("managed Falcon txn %s not confirmed", res.TxIDs[0])
	}
}
