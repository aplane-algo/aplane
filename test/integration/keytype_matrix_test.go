// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const matrixAccountFunding = 500_000

func TestIncludedKeyTypesSignInBatchedGroups(t *testing.T) {
	lockOnDisconnect := false
	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{LockOnDisconnect: &lockOnDisconnect})
	installAllBundledTemplates(t, env.SignerDataDir)

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}
	token := readSignerToken(t, signerd)
	signerClient := signerclient.NewSignerClientWithToken(signerd.GetURL(), token)
	fundingAddress, err := apadmin.ImportFundingKey(os.Getenv("TEST_FUNDING_MNEMONIC"))
	if err != nil {
		t.Fatalf("failed to import native Falcon funding key for matrix fee sponsorship: %v", err)
	}
	if fundingAddress != funder.GetAddress() {
		t.Fatalf("imported funding address %s does not match derived address %s", fundingAddress, funder.GetAddress())
	}
	if !waitForKey(t, signerd.GetURL(), token, fundingAddress, 10*time.Second) {
		t.Fatalf("signer did not reload imported funding key %s", fundingAddress)
	}

	status, err := testnet.Client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get algod status: %v", err)
	}
	baseRound := uint64(status.LastRound)
	if baseRound < 10 {
		baseRound = 10
	}
	preimage := bytes.Repeat([]byte("k"), 32)
	preimageHash := sha256.Sum256(preimage)
	timelockRound := baseRound

	cases := []includedKeyTypeCase{
		{
			keyType: "ed25519",
		},
		{
			keyType: "aplane.falcon1024.v1",
		},
		{
			keyType: "aplane.htlc.v1",
			params: map[string]string{
				"hash":           hex.EncodeToString(preimageHash[:]),
				"recipient":      funder.GetAddress(),
				"refund_address": funder.GetAddress(),
				"timeout_round":  fmt.Sprintf("%d", baseRound+1_000),
			},
			positiveArgs: map[string]string{"preimage": hex.EncodeToString(preimage)},
			negative: includedKeyTypeNegative{
				name: "wrong preimage",
				args: map[string]string{"preimage": hex.EncodeToString(bytes.Repeat([]byte("x"), 32))},
			},
		},
		{
			keyType: "aplane.falcon1024-allowlist.v1",
			params:  map[string]string{"recipients": funder.GetAddress()},
			negative: includedKeyTypeNegative{
				name:     "non-allowlisted receiver",
				receiver: integrationBurnAddress,
			},
		},
		{
			keyType:            "aplane.falcon1024-timelock.v1",
			params:             map[string]string{"unlock_round": fmt.Sprintf("%d", timelockRound)},
			positiveFirstValid: timelockRound,
			negative: includedKeyTypeNegative{
				name:       "before unlock round",
				firstValid: timelockRound - 1,
			},
		},
	}

	generated := make([]includedKeyTypeAccount, 0, len(cases))
	for _, tc := range cases {
		address := mustAdminGenerateKey(t, signerClient, signerd, tc.keyType, tc.params)
		if err := funder.FundMicroAlgosAndWait(address, matrixAccountFunding); err != nil {
			t.Fatalf("failed to fund %s account %s: %v", tc.keyType, address, err)
		}
		generated = append(generated, includedKeyTypeAccount{
			includedKeyTypeCase: tc,
			address:             address,
		})
	}

	for _, account := range generated {
		if account.negative.name == "" {
			continue
		}
		t.Run(account.keyType+"/negative/"+account.negative.name, func(t *testing.T) {
			sp, err := testnet.GetSuggestedParams()
			if err != nil {
				t.Fatalf("failed to get suggested params: %v", err)
			}
			req := matrixSignRequest(t, sp, fundingAddress, []matrixSignTxn{
				account.negativeSignTxn(t, sp, funder.GetAddress()),
			})
			status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
			if status != http.StatusOK {
				t.Fatalf("expected signer to produce LogicSig for negative case, got %d: %s", status, string(body))
			}
			var signResp signerapi.GroupSignResponse
			if err := json.Unmarshal(body, &signResp); err != nil {
				t.Fatalf("failed to parse sign response: %v", err)
			}
			if signResp.Error != "" {
				t.Fatalf("unexpected sign error: %s", signResp.Error)
			}
			assertMatrixPlannerDidNotPad(t, signResp, len(req.Requests))
			submitSignedTxnGroupExpectFailure(t, testnet, signResp.Signed)
		})
	}

	for i := 0; i < len(generated); i += 3 {
		end := i + 3
		if end > len(generated) {
			end = len(generated)
		}
		batch := generated[i:end]
		t.Run(fmt.Sprintf("positive/batch-%d", i/3+1), func(t *testing.T) {
			sp, err := testnet.GetSuggestedParams()
			if err != nil {
				t.Fatalf("failed to get suggested params: %v", err)
			}
			signTxns := make([]matrixSignTxn, 0, len(batch))
			for _, account := range batch {
				signTxns = append(signTxns, account.positiveSignTxn(t, sp, funder.GetAddress()))
			}
			req := plannedMatrixSignRequest(t, signerClient, sp, fundingAddress, signTxns)
			status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, req)
			if status != http.StatusOK {
				t.Fatalf("expected positive batch sign to succeed, got %d: %s", status, string(body))
			}
			var signResp signerapi.GroupSignResponse
			if err := json.Unmarshal(body, &signResp); err != nil {
				t.Fatalf("failed to parse positive batch sign response: %v", err)
			}
			if signResp.Error != "" {
				t.Fatalf("unexpected positive batch sign error: %s", signResp.Error)
			}
			assertMatrixPlannerDidNotPad(t, signResp, len(req.Requests))
			assertMatrixAccountsDrainExactly(t, signResp.Signed, len(signTxns))
			txids := submitSignedTxnGroup(t, testnet, signResp.Signed)
			if len(txids) == 0 {
				t.Fatal("positive batch produced no transaction IDs")
			}
			if _, err := testnet.WaitForConfirmation(txids[0], 10); err != nil {
				t.Fatalf("positive batch failed to confirm: %v", err)
			}
		})
	}
}

type includedKeyTypeCase struct {
	keyType            string
	params             map[string]string
	positiveArgs       map[string]string
	positiveFirstValid uint64
	negative           includedKeyTypeNegative
}

type includedKeyTypeNegative struct {
	name       string
	receiver   string
	args       map[string]string
	firstValid uint64
}

type includedKeyTypeAccount struct {
	includedKeyTypeCase
	address string
}

type matrixSignTxn struct {
	authAddress string
	txn         types.Transaction
	lsigArgs    map[string]string
}

func (a includedKeyTypeAccount) positiveSignTxn(t *testing.T, sp types.SuggestedParams, destination string) matrixSignTxn {
	t.Helper()
	txn := mustPaymentTxnForMatrix(t, sp, a.address, destination, "keytype-matrix-positive", "", a.positiveFirstValid)
	if uint64(txn.Fee) >= matrixAccountFunding {
		t.Fatalf("matrix transaction fee %d exhausts account funding %d", txn.Fee, matrixAccountFunding)
	}
	txn.Amount = types.MicroAlgos(matrixAccountFunding - uint64(txn.Fee))
	return matrixSignTxn{
		authAddress: a.address,
		txn:         txn,
		lsigArgs:    a.positiveArgs,
	}
}

func (a includedKeyTypeAccount) negativeSignTxn(t *testing.T, sp types.SuggestedParams, fallbackDestination string) matrixSignTxn {
	t.Helper()
	destination := fallbackDestination
	if a.negative.receiver != "" {
		destination = a.negative.receiver
	}
	return matrixSignTxn{
		authAddress: a.address,
		txn:         mustPaymentTxnForMatrix(t, sp, a.address, destination, "keytype-matrix-negative", "", a.negative.firstValid),
		lsigArgs:    a.negative.args,
	}
}

func matrixSignRequest(t *testing.T, sp types.SuggestedParams, fundingAddress string, signTxns []matrixSignTxn) signerapi.GroupSignRequest {
	t.Helper()
	if len(signTxns) == 0 {
		t.Fatal("matrix sign request requires at least one transaction to sign")
	}

	req := signerapi.GroupSignRequest{Requests: make([]signerapi.SignRequest, 0, len(signTxns)+1)}
	for _, signTxn := range signTxns {
		req.Requests = append(req.Requests, signerapi.SignRequest{
			AuthAddress: signTxn.authAddress,
			TxnBytesHex: txnHexForMatrix(signTxn.txn),
			LsigArgs:    signTxn.lsigArgs,
		})
	}
	sponsorTxn := mustPaymentTxnForMatrix(t, sp, fundingAddress, fundingAddress, "keytype-matrix-sponsor", "", uint64(signTxns[0].txn.FirstValid))
	req.Requests = append(req.Requests, signerapi.SignRequest{
		AuthAddress: fundingAddress,
		TxnBytesHex: txnHexForMatrix(sponsorTxn),
	})
	return req
}

func plannedMatrixSignRequest(
	t *testing.T,
	client *signerclient.Client,
	sp types.SuggestedParams,
	fundingAddress string,
	signTxns []matrixSignTxn,
) signerapi.GroupSignRequest {
	t.Helper()
	// Ask the same production planner used by /sign for the exact per-slot
	// fees before setting drain amounts. The final request remains ungrouped so
	// /sign must independently reproduce the minimal v42 group and fee plan.
	draft := matrixSignRequest(t, sp, fundingAddress, signTxns)
	plan, err := client.RequestGroupPlan(draft.Requests)
	if err != nil {
		t.Fatalf("failed to plan v42 matrix group: %v", err)
	}
	if plan.Mutations == nil {
		t.Fatal("v42 matrix plan omitted mutation details")
	}
	if plan.Mutations.DummiesAdded != 0 {
		t.Fatalf("v42 matrix plan added %d unexpected dummy transaction(s)", plan.Mutations.DummiesAdded)
	}
	if got := len(plan.Transactions); got != len(draft.Requests) {
		t.Fatalf("v42 matrix plan returned %d transactions for %d requested", got, len(draft.Requests))
	}

	for i := range signTxns {
		plannedTxn, err := txnutil.DecodePrefixedHex(plan.Transactions[i])
		if err != nil {
			t.Fatalf("failed to decode planned matrix transaction %d: %v", i+1, err)
		}
		plannedFee := uint64(plannedTxn.Fee)
		if plannedFee >= matrixAccountFunding {
			t.Fatalf("planned matrix fee %d exhausts account funding %d", plannedFee, matrixAccountFunding)
		}
		signTxns[i].txn.Amount = types.MicroAlgos(matrixAccountFunding - plannedFee)
	}
	return matrixSignRequest(t, sp, fundingAddress, signTxns)
}

func assertMatrixPlannerDidNotPad(t *testing.T, response signerapi.GroupSignResponse, requested int) {
	t.Helper()
	if response.Mutations == nil {
		t.Fatal("matrix sign response omitted planner mutation details")
	}
	if response.Mutations.DummiesAdded != 0 {
		t.Fatalf("v42 matrix planner added %d unexpected dummy transaction(s)", response.Mutations.DummiesAdded)
	}
	if got := len(response.Signed); got != requested {
		t.Fatalf("v42 matrix planner returned %d transactions for %d requested", got, requested)
	}
	if response.Mutations.FinalCount != requested {
		t.Fatalf("v42 matrix mutation report final_count=%d, want %d", response.Mutations.FinalCount, requested)
	}
}

func assertMatrixAccountsDrainExactly(t *testing.T, signed []string, accountCount int) {
	t.Helper()
	for i := 0; i < accountCount; i++ {
		stxn := decodeSignedTxnHex(t, signed[i])
		spent := uint64(stxn.Txn.Amount) + uint64(stxn.Txn.Fee)
		if spent != matrixAccountFunding {
			t.Fatalf("matrix transaction %d spends %d microAlgos, want funded balance %d", i+1, spent, matrixAccountFunding)
		}
	}
}

func mustPaymentTxnForMatrix(
	t *testing.T,
	sp types.SuggestedParams,
	from, to, note, closeTo string,
	firstValid uint64,
) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(from, to, 0, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("failed to build payment txn: %v", err)
	}
	if closeTo != "" {
		closeAddr, err := types.DecodeAddress(closeTo)
		if err != nil {
			t.Fatalf("failed to decode close address %s: %v", closeTo, err)
		}
		txn.CloseRemainderTo = closeAddr
	}
	if firstValid != 0 {
		window := uint64(txn.LastValid - txn.FirstValid)
		if window == 0 {
			window = 1_000
		}
		txn.FirstValid = types.Round(firstValid)
		txn.LastValid = types.Round(firstValid + window)
	}
	if txn.Fee == 0 {
		txn.Fee = types.MicroAlgos(sp.MinFee)
	}
	if txn.Fee == 0 {
		txn.Fee = 1_000
	}
	return txn
}

func txnHexForMatrix(txn types.Transaction) string {
	return hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn)...))
}

func submitSignedTxnGroupExpectFailure(t *testing.T, testnet *harness.TestnetConfig, signedHexes []string) {
	t.Helper()
	if len(signedHexes) == 0 {
		t.Fatal("negative sign response produced no signed transactions")
	}
	rawGroup := make([]byte, 0)
	for _, signedHex := range signedHexes {
		signedBytes, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatalf("failed to decode signed negative txn: %v", err)
		}
		rawGroup = append(rawGroup, signedBytes...)
	}
	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err == nil {
		t.Fatal("negative LogicSig case unexpectedly submitted successfully")
	}
}

func installAllBundledTemplates(t *testing.T, signerDataDir string) {
	t.Helper()
	t.Setenv("APSIGNER_PASSPHRASE", mustReadPassphrase(t, signerDataDir))
	apstore := harness.NewApStoreHarness(t, signerDataDir)
	templateFiles := []string{
		"aplane.htlc.v1.yaml",
		"aplane.falcon1024-allowlist.v1.yaml",
		"aplane.falcon1024-allowlist.v2.yaml",
		"aplane.falcon1024-timelock.v1.yaml",
	}
	templatePaths := make([]string, 0, len(templateFiles))
	for _, file := range templateFiles {
		templatePaths = append(templatePaths, syncTemplateLibraryFile(t, signerDataDir, file))
	}
	runWithTempSigner(t, func() {
		for _, templatePath := range templatePaths {
			if output, err := apstore.Run("template", "import", templatePath); err != nil {
				t.Fatalf("failed to add bundled template %s: %v\noutput:\n%s", templatePath, err, output)
			}
		}
	})
	_ = os.Unsetenv("APSIGNER_PASSPHRASE")
}
