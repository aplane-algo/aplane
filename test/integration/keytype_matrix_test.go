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
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	txsigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/transport"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/library/templates"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	edlsigv1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	falconlsigv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	"github.com/aplane-algo/aplane/test/integration/harness"

	sdkalgod "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const matrixAccountFunding = 500_000

func TestIncludedKeyTypesSignInBatchedGroups(t *testing.T) {
	assertBundledOpcodeValidationInventory(t)
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
	compileAlgod := matrixCompileAlgod(t, testnet)

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
	if err := apadmin.ActivateKeyType(ed25519lsig.KeyTypeV1); err != nil {
		t.Fatalf("failed to activate %s for key-type matrix: %v", ed25519lsig.KeyTypeV1, err)
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
	htlcAssetID := createCorridorTestAsset(t, testnet, funder)

	cases := []includedKeyTypeCase{
		{
			keyType: "ed25519",
		},
		{
			keyType: "aplane.ed25519.v1",
		},
		{
			keyType: "aplane.falcon1024.v1",
		},
		{
			keyType:            "aplane.htlc.v1",
			opcodeVectorName:   "maximum-claim",
			opcodeAssetOptInID: htlcAssetID,
			params: map[string]string{
				"hash":                 hex.EncodeToString(preimageHash[:]),
				"recipient":            funder.GetAddress(),
				"refund_address":       funder.GetAddress(),
				"timeout_round":        fmt.Sprintf("%d", baseRound+1_000),
				"allowed_optin_assets": matrixAssetIDsEndingWith(htlcAssetID, 16),
			},
			positiveArgs: map[string]string{"preimage": hex.EncodeToString(preimage)},
			negative: includedKeyTypeNegative{
				name: "wrong preimage",
				args: map[string]string{"preimage": hex.EncodeToString(bytes.Repeat([]byte("x"), 32))},
			},
		},
		{
			keyType:            "aplane.htlc.v1",
			opcodeVectorName:   "refund-after-timeout",
			positiveFirstValid: baseRound,
			params: map[string]string{
				"hash":           hex.EncodeToString(preimageHash[:]),
				"recipient":      funder.GetAddress(),
				"refund_address": funder.GetAddress(),
				"timeout_round":  fmt.Sprintf("%d", baseRound),
			},
		},
		{
			keyType: "aplane.falcon1024-allowlist.v1",
			params:  map[string]string{"recipients": matrixMaximumRecipients(funder.GetAddress())},
			negative: includedKeyTypeNegative{
				name:     "non-allowlisted receiver",
				receiver: integrationBurnAddress,
			},
		},
		{
			keyType: "aplane.falcon1024-allowlist.v2",
			params:  map[string]string{"recipients": matrixMaximumRecipients(funder.GetAddress())},
		},
		{
			keyType: "aplane.falcon1024-allowlist-alock.v1",
			params: map[string]string{
				"recipients":         matrixMaximumRecipients(funder.GetAddress()),
				"asset_ids":          matrixMaximumAssetIDs(),
				"max_payment_amount": "18446744073709551615",
				"max_asset_amount":   "18446744073709551615",
				composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)),
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
	resourceProfiles := matrixLogicSigResourceProfiles(t, signerClient)
	approvalClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	t.Cleanup(approvalClient.Close)

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
			assertMatrixPlannerDummies(t, signResp, len(req.Requests), 0)
			submitSignedTxnGroupExpectFailure(t, testnet, signResp.Signed)
		})
	}

	validateMatrixHTLCAssetOptInOpcodeCeilings(
		t, compileAlgod, signerd.GetURL(), token, fundingAddress, generated, mustSuggestedParams(t, testnet),
	)
	validateMatrixSpendingRekeyOpcodeCeilings(
		t, compileAlgod, signerd.GetURL(), token, fundingAddress, generated, mustSuggestedParams(t, testnet), approvalClient,
	)

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
			expectedDummies := matrixExpectedResourceDummies(t, sp.ConsensusVersion, batch, resourceProfiles)
			req := plannedMatrixSignRequest(t, signerClient, sp, fundingAddress, signTxns, expectedDummies)
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
			assertMatrixPlannerDummies(t, signResp, len(req.Requests), expectedDummies)
			assertMatrixAccountsDrainExactly(t, signResp.Signed, len(signTxns))
			validateMatrixOpcodeCeilings(t, compileAlgod, batch, signResp.Signed)
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

func assertBundledOpcodeValidationInventory(t *testing.T) {
	t.Helper()
	validated := map[string]struct{}{
		"aplane.corridor.v1.yaml":                   {},
		"aplane.falcon1024-allowlist-alock.v1.yaml": {},
		"aplane.falcon1024-allowlist.v1.yaml":       {},
		"aplane.falcon1024-allowlist.v2.yaml":       {},
		"aplane.falcon1024-timelock.v1.yaml":        {},
		"aplane.htlc.v1.yaml":                       {},
	}
	entries, err := templates.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("list bundled LogicSig templates: %v", err)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		seen[entry.Name()] = struct{}{}
		if _, ok := validated[entry.Name()]; !ok {
			t.Errorf("bundled template %s has no opcode-ceiling integration vector", entry.Name())
		}
	}
	for name := range validated {
		if _, ok := seen[name]; !ok {
			t.Errorf("opcode-ceiling inventory names missing bundled template %s", name)
		}
	}
}

func validateMatrixSpendingRekeyOpcodeCeilings(
	t *testing.T,
	client *sdkalgod.Client,
	signerURL string,
	token string,
	fundingAddress string,
	accounts []includedKeyTypeAccount,
	sp types.SuggestedParams,
	approvalClient *transport.IPCClient,
) {
	t.Helper()
	for _, account := range accounts {
		if !matrixSupportsSpendingRekey(account.keyType) {
			continue
		}
		t.Run(account.keyType+"/opcode/spending-rekey", func(t *testing.T) {
			txn := mustPaymentTxnForMatrix(
				t, sp, account.address, account.address, "keytype-matrix-spending-rekey", "", account.positiveFirstValid,
			)
			txn.RekeyTo = algocrypto.GenerateAccount().Address
			req := matrixSignRequest(t, sp, fundingAddress, []matrixSignTxn{{
				authAddress: account.address,
				txn:         txn,
			}})
			var status int
			var body []byte
			done := make(chan struct{})
			go func() {
				defer close(done)
				status, body = postSignRequest(t, signerURL, "aplane "+token, req)
			}()
			approval := mustReadIPCSignRequest(t, approvalClient, 10*time.Second)
			// matrixSignRequest includes the LogicSig transaction and a native-Falcon
			// fee sponsor, so the approval correctly represents two authorizers.
			const wantApprovalAddress = "2 auth addresses (see details)"
			gotApprovalAddress := approval.Address
			mustApproveIPCSignRequest(t, approvalClient, approval.ID)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("timed out waiting for approved spending-rekey signing")
			}
			if gotApprovalAddress != wantApprovalAddress {
				t.Fatalf("spending-rekey approval address = %s, want %s", gotApprovalAddress, wantApprovalAddress)
			}
			if status != http.StatusOK {
				t.Fatalf("expected spending-key rekey signing to succeed, got %d: %s", status, string(body))
			}
			var signResp signerapi.GroupSignResponse
			if err := json.Unmarshal(body, &signResp); err != nil {
				t.Fatalf("parse spending-key rekey sign response: %v", err)
			}
			if signResp.Error != "" {
				t.Fatalf("unexpected spending-key rekey sign error: %s", signResp.Error)
			}
			assertMatrixPlannerDummies(t, signResp, len(req.Requests), 0)
			signed := make([]types.SignedTxn, len(signResp.Signed))
			for i, encoded := range signResp.Signed {
				signed[i] = decodeSignedTxnHex(t, encoded)
			}
			profile := matrixDeclaredOpcodeProfile(t, account.keyType)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), client, harness.OpcodeCeilingValidation{
				Name:          account.keyType,
				FinalProgram:  signed[0].Lsig.Logic,
				Profile:       profile,
				Bounded:       true,
				RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathSpendingRekey},
				Vectors: []harness.OpcodeCeilingVector{{
					Name: "maximum-spending-key-rekey", Path: lsigresource.PathSpendingRekey, SignedTxns: signed, LSigIndex: 0,
				}},
			})
			if err != nil {
				t.Fatalf("validate spending-key rekey opcode ceiling: %v", err)
			}
			observed := report.Paths[lsigresource.PathSpendingRekey]
			t.Logf("spending-rekey opcode cost: %d observed / %d declared", observed.MaximumObserved, observed.DeclaredCeiling)
		})
	}
}

func matrixSupportsSpendingRekey(keyType string) bool {
	switch keyType {
	case "aplane.falcon1024-allowlist.v1",
		"aplane.falcon1024-allowlist.v2",
		"aplane.falcon1024-timelock.v1":
		return true
	default:
		return false
	}
}

type includedKeyTypeCase struct {
	keyType            string
	opcodeVectorName   string
	opcodeAssetOptInID uint64
	params             map[string]string
	positiveArgs       map[string]string
	positiveFirstValid uint64
	negative           includedKeyTypeNegative
}

func validateMatrixHTLCAssetOptInOpcodeCeilings(
	t *testing.T,
	client *sdkalgod.Client,
	signerURL string,
	token string,
	fundingAddress string,
	accounts []includedKeyTypeAccount,
	sp types.SuggestedParams,
) {
	t.Helper()
	for _, account := range accounts {
		if account.opcodeAssetOptInID == 0 {
			continue
		}
		t.Run(account.keyType+"/opcode/maximum-asset-optin", func(t *testing.T) {
			txn := corridorAssetTransferTxn(
				t, sp, account.address, account.address, 0, account.opcodeAssetOptInID, "keytype-matrix-asset-optin",
			)
			req := matrixSignRequest(t, sp, fundingAddress, []matrixSignTxn{{authAddress: account.address, txn: txn}})
			status, body := postSignRequest(t, signerURL, "aplane "+token, req)
			if status != http.StatusOK {
				t.Fatalf("expected HTLC asset opt-in signing to succeed, got %d: %s", status, string(body))
			}
			var signResp signerapi.GroupSignResponse
			if err := json.Unmarshal(body, &signResp); err != nil {
				t.Fatalf("parse HTLC asset opt-in sign response: %v", err)
			}
			if signResp.Error != "" {
				t.Fatalf("unexpected HTLC asset opt-in sign error: %s", signResp.Error)
			}
			assertMatrixPlannerDummies(t, signResp, len(req.Requests), 0)
			signed := make([]types.SignedTxn, len(signResp.Signed))
			for i, encoded := range signResp.Signed {
				signed[i] = decodeSignedTxnHex(t, encoded)
			}
			profile := matrixDeclaredOpcodeProfile(t, account.keyType)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), client, harness.OpcodeCeilingValidation{
				Name:          account.keyType,
				FinalProgram:  signed[0].Lsig.Logic,
				Profile:       profile,
				RequiredPaths: []lsigresource.AuthorizationPath{lsigresource.PathDefault},
				Vectors: []harness.OpcodeCeilingVector{{
					Name: "maximum-asset-optin", Path: lsigresource.PathDefault, SignedTxns: signed, LSigIndex: 0,
				}},
			})
			if err != nil {
				t.Fatalf("validate HTLC asset opt-in opcode ceiling: %v", err)
			}
			observed := report.Paths[lsigresource.PathDefault]
			t.Logf("asset-optin opcode cost: %d observed / %d declared", observed.MaximumObserved, observed.DeclaredCeiling)
		})
	}
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
	expectedDummies int,
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
	if plan.Mutations.DummiesAdded != expectedDummies {
		t.Fatalf("v42 matrix plan added %d dummy transaction(s), want minimal resource count %d", plan.Mutations.DummiesAdded, expectedDummies)
	}
	wantTransactions := len(draft.Requests) + expectedDummies
	if got := len(plan.Transactions); got != wantTransactions {
		t.Fatalf("v42 matrix plan returned %d transactions, want %d", got, wantTransactions)
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

func assertMatrixPlannerDummies(t *testing.T, response signerapi.GroupSignResponse, requested, expectedDummies int) {
	t.Helper()
	if response.Mutations == nil {
		t.Fatal("matrix sign response omitted planner mutation details")
	}
	if response.Mutations.DummiesAdded != expectedDummies {
		t.Fatalf("v42 matrix planner added %d dummy transaction(s), want %d", response.Mutations.DummiesAdded, expectedDummies)
	}
	wantFinal := requested + expectedDummies
	if got := len(response.Signed); got != wantFinal {
		t.Fatalf("v42 matrix planner returned %d transactions, want %d", got, wantFinal)
	}
	if response.Mutations.FinalCount != wantFinal {
		t.Fatalf("v42 matrix mutation report final_count=%d, want %d", response.Mutations.FinalCount, wantFinal)
	}
}

func matrixLogicSigResourceProfiles(t *testing.T, client *signerclient.Client) map[string]*signerapi.LogicSigResourceProfile {
	t.Helper()
	keys, err := client.GetKeys()
	if err != nil {
		t.Fatalf("read generated key resource profiles: %v", err)
	}
	profiles := make(map[string]*signerapi.LogicSigResourceProfile, len(keys.Keys))
	for _, key := range keys.Keys {
		profiles[key.Address] = key.LogicSigResources
	}
	return profiles
}

func matrixExpectedResourceDummies(
	t *testing.T,
	consensusVersion string,
	batch []includedKeyTypeAccount,
	profiles map[string]*signerapi.LogicSigResourceProfile,
) int {
	t.Helper()
	consensus, err := lsigresource.ResolveConsensus(consensusVersion)
	if err != nil {
		t.Fatalf("resolve matrix consensus %q: %v", consensusVersion, err)
	}
	usages := make([]lsigresource.Usage, 0, len(batch))
	for _, account := range batch {
		profile := profiles[account.address]
		if profile == nil {
			continue
		}
		selected := profile.Default
		if profile.Spend != nil {
			selected = profile.Spend
		}
		if selected == nil {
			t.Fatalf("generated LogicSig key %s (%s) has no positive-path resource usage", account.address, account.keyType)
		}
		usages = append(usages, lsigresource.Usage{
			ProgramBytes:  selected.ProgramBytes,
			ArgumentBytes: selected.ArgumentBytes,
			MaxOpcodeCost: selected.MaxOpcodeCost,
		})
	}
	plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
		TransactionCount: uint64(len(batch) + 1), // one native-Falcon fee sponsor
		LogicSigs:        usages,
		Dummy: lsigresource.Usage{
			ProgramBytes:  uint64(len(txsigning.EmbeddedDummyTealTok)),
			MaxOpcodeCost: 1,
		},
	})
	if err != nil {
		t.Fatalf("solve expected matrix LogicSig resources: %v", err)
	}
	return int(plan.DummyCount)
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

func matrixCompileAlgod(t *testing.T, network *harness.TestnetConfig) *sdkalgod.Client {
	t.Helper()
	client := network.Client
	if client == nil {
		t.Fatal("compile/simulation algod client is not configured")
	}
	sp, err := client.SuggestedParams().Do(context.Background())
	if err != nil {
		t.Fatalf("read compile/simulation algod suggested params: %v", err)
	}
	status, err := client.Status().Do(context.Background())
	if err != nil {
		t.Fatalf("read compile/simulation algod status: %v", err)
	}
	for label, version := range map[string]string{"suggested": sp.ConsensusVersion, "status": status.LastVersion} {
		profile, err := lsigresource.ResolveConsensus(version)
		if err != nil {
			t.Fatalf("compile/simulation algod %s consensus %q is unsupported: %v", label, version, err)
		}
		if profile.MaximumLogicSigVersion < 13 {
			t.Fatalf(
				"compile/simulation algod %s consensus %q is not v42-compatible (LogicSigVersion=%d)",
				label, version, profile.MaximumLogicSigVersion,
			)
		}
	}
	return client
}

func validateMatrixOpcodeCeilings(
	t *testing.T,
	client *sdkalgod.Client,
	accounts []includedKeyTypeAccount,
	signedHexes []string,
) {
	t.Helper()
	signed := make([]types.SignedTxn, len(signedHexes))
	for i, encoded := range signedHexes {
		signed[i] = decodeSignedTxnHex(t, encoded)
	}
	for i, account := range accounts {
		if len(signed[i].Lsig.Logic) == 0 {
			continue
		}
		profile := matrixDeclaredOpcodeProfile(t, account.keyType)
		bounded := profile.Default == 0
		path := lsigresource.PathDefault
		if bounded {
			path = lsigresource.PathSpend
		}
		vectorName := account.opcodeVectorName
		if vectorName == "" {
			vectorName = "maximum-positive-matrix"
		}
		report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), client, harness.OpcodeCeilingValidation{
			Name:          account.keyType,
			FinalProgram:  signed[i].Lsig.Logic,
			Profile:       profile,
			Bounded:       bounded,
			RequiredPaths: []lsigresource.AuthorizationPath{path},
			Vectors: []harness.OpcodeCeilingVector{{
				Name: vectorName, Path: path, SignedTxns: signed, LSigIndex: i,
			}},
		})
		if err != nil {
			t.Fatalf("validate %s opcode ceiling: %v", account.keyType, err)
		}
		observed := report.Paths[path]
		t.Logf(
			"%s LogicSig opcode cost: %d observed / %d declared",
			account.keyType, observed.MaximumObserved, observed.DeclaredCeiling,
		)
	}
}

func matrixDeclaredOpcodeProfile(t *testing.T, keyType string) lsigresource.OpcodeProfile {
	t.Helper()
	switch keyType {
	case "aplane.ed25519.v1":
		return edlsigv1.NewProvider().LogicSigOpcodeProfile()
	case "aplane.falcon1024.v1":
		return (&falconlsigv1.Falcon1024V1{}).LogicSigOpcodeProfile()
	case "aplane.htlc.v1":
		data, err := templates.ReadFile(keyType + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		spec, err := generictemplate.ParseTemplateSpec(data)
		if err != nil {
			t.Fatal(err)
		}
		return generictemplate.NewYAMLTemplate(spec).LogicSigOpcodeProfile()
	default:
		data, err := templates.ReadFile(keyType + ".yaml")
		if err != nil {
			t.Fatal(err)
		}
		spec, err := composeddsa.ParseTemplateSpec(data)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		return provider.LogicSigOpcodeProfile()
	}
}

func matrixMaximumRecipients(destination string) string {
	recipients := []string{destination}
	for i := byte(1); len(recipients) < 30; i++ {
		var address types.Address
		address[0] = i
		encoded := address.String()
		if encoded != destination {
			recipients = append(recipients, encoded)
		}
	}
	return strings.Join(recipients, ",")
}

func matrixMaximumAssetIDs() string {
	ids := make([]string, 30)
	for i := range ids {
		ids[i] = fmt.Sprintf("%d", i+1)
	}
	return strings.Join(ids, ",")
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
		"aplane.falcon1024-allowlist-alock.v1.yaml",
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
