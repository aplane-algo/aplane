// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestPresignPlanPreservesPluginSlotFields validates the load-bearing premise of
// the pre-sign planning flow against a real apsigner: when /plan canonicalizes a
// mixed group (a Falcon-managed slot + a foreign/plugin slot), it (a) adds budget
// dummies for the Falcon key and (b) preserves the plugin slot's artifact-bound
// fields (sender, validity window, lease, amount, genesis) — changing only group id
// and fee. A violation would silently break a plugin's HPKE envelope / proof.
func TestPresignPlanPreservesPluginSlotFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	falconAddr, err := apadmin.GenerateKey("presign field-preservation test")
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

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("suggested params: %v", err)
	}
	const burnAddr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	// Managed Falcon slot (unsigned, sign-mode). A distinctive lease lets us detect
	// any /plan mutation of the managed slot — a Falcon-funded Mithras deposit's
	// funder slots carry HPKE-bound fields (sender/validity/lease), so the planner
	// must change only fee and group id here too.
	managedTxn, err := transaction.MakePaymentTxn(falconAddr, burnAddr, 0, []byte("managed"), "", sp)
	if err != nil {
		t.Fatalf("make managed txn: %v", err)
	}
	managedTxn.Lease = [32]byte{0x11, 0x22, 0x33, 0x44, 0x55}

	// Foreign/plugin slot (unsigned) with a distinctive lease to detect mutation.
	plugin := crypto.GenerateAccount()
	pluginTxn, err := transaction.MakePaymentTxn(plugin.Address.String(), burnAddr, 0, []byte("plugin"), "", sp)
	if err != nil {
		t.Fatalf("make plugin txn: %v", err)
	}
	pluginTxn.Lease = [32]byte{0xAB, 1, 2, 3, 0xCD}

	groupReq := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: falconAddr, TxnBytesHex: txnutil.EncodeWithPrefixHex(managedTxn)}, // managed sign-mode
		{TxnBytesHex: txnutil.EncodeWithPrefixHex(pluginTxn)},                           // foreign/plugin
	}}

	reqBody, _ := json.Marshal(groupReq)
	req, err := http.NewRequest("POST", signerd.GetURL()+"/plan", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+token)

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatalf("post /plan: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var planResp signerapi.GroupPlanResponse
	if err := json.NewDecoder(resp.Body).Decode(&planResp); err != nil {
		t.Fatalf("decode plan response: %v", err)
	}
	if planResp.Error != "" {
		t.Fatalf("plan error: %s", planResp.Error)
	}

	canonical := make([]types.Transaction, len(planResp.Transactions))
	for i, h := range planResp.Transactions {
		txn, err := txnutil.DecodePrefixedHex(h)
		if err != nil {
			t.Fatalf("decode canonical txn %d: %v", i, err)
		}
		canonical[i] = txn
	}

	// (a) Budget dummies were added for the Falcon key.
	if len(canonical) <= 2 {
		t.Fatalf("expected budget dummies for the Falcon key; got %d canonical txns", len(canonical))
	}

	// (b) The plugin slot's artifact-bound fields are preserved.
	var found *types.Transaction
	for i := range canonical {
		if canonical[i].Sender == plugin.Address {
			found = &canonical[i]
			break
		}
	}
	if found == nil {
		t.Fatal("plugin slot not present in the canonical group")
	}

	// Only group id and fee may change; compare everything else byte-for-byte.
	d, c := pluginTxn, *found
	d.Group, c.Group = types.Digest{}, types.Digest{}
	d.Fee, c.Fee = 0, 0
	if !bytes.Equal(msgpack.Encode(d), msgpack.Encode(c)) {
		t.Fatalf("/plan changed an artifact-bound field of the plugin slot\n draft=%+v\n canon=%+v", d, c)
	}

	// (c) The MANAGED Falcon slot's artifact-bound fields are preserved too. The
	// original slots keep their indices [0, originalCount); dummies are appended, so
	// the managed slot is canonical[0]. (Searching by sender would also match the
	// Falcon budget dummies, which share the funder's address.) Its fee changes from
	// budget pooling, so allow only fee + group to differ.
	if canonical[0].Sender.String() != falconAddr {
		t.Fatalf("expected the managed Falcon slot at canonical index 0, got sender %s", canonical[0].Sender)
	}
	md, mc := managedTxn, canonical[0]
	md.Group, mc.Group = types.Digest{}, types.Digest{}
	md.Fee, mc.Fee = 0, 0
	if !bytes.Equal(msgpack.Encode(md), msgpack.Encode(mc)) {
		t.Fatalf("/plan changed an artifact-bound field of the managed slot\n draft=%+v\n canon=%+v", md, mc)
	}
}
