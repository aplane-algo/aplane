// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	stded25519 "crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	boundedauthorization "github.com/aplane-algo/aplane/internal/boundedadmin/authorization"
	boundedprotocol "github.com/aplane-algo/aplane/internal/boundedadmin/protocol"
	securecrypto "github.com/aplane-algo/aplane/internal/crypto"
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
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	falconlsigv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	"github.com/aplane-algo/aplane/test/integration/harness"

	sdkalgod "github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

const (
	matrixAccountFunding     = 250_000
	matrixBaseMinimumBalance = 100_000
)

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
	htlcAssetID := corridorTestAssetID(t, testnet, funder)
	cleanupAuthority := algocrypto.GenerateAccount()
	alockAdminPublicKey, alockAdminPrivateKey, err := signerops.New(nil).GenerateKeypair(randomFalconSeed(t))
	if err != nil {
		t.Fatalf("generate matrix ALock cleanup admin key: %v", err)
	}
	t.Cleanup(func() { securecrypto.ZeroBytes(alockAdminPrivateKey) })

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
			keyType:         "aplane.falcon1024-allowlist-alock.v1",
			adminPrivateKey: alockAdminPrivateKey,
			params: map[string]string{
				"recipients":         matrixMaximumRecipients(funder.GetAddress()),
				"asset_ids":          matrixMaximumAssetIDs(),
				"max_payment_amount": "18446744073709551615",
				"max_asset_amount":   "18446744073709551615",
				composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(alockAdminPublicKey),
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
		generated = append(generated, includedKeyTypeAccount{
			includedKeyTypeCase: tc,
			address:             address,
		})
	}
	resourceProfiles := matrixLogicSigResourceProfiles(t, signerClient)
	approvalClient := mustConnectIPCClient(t, signerd.GetWorkDir())
	t.Cleanup(approvalClient.Close)

	for i := 0; i < len(generated); i += 3 {
		end := i + 3
		if end > len(generated) {
			end = len(generated)
		}
		batch := generated[i:end]
		t.Run(fmt.Sprintf("batch-%d", i/3+1), func(t *testing.T) {
			sp, err := testnet.GetSuggestedParams()
			if err != nil {
				t.Fatalf("failed to get suggested params: %v", err)
			}

			// Prepare every recovery authority before putting funds at risk. Bounded
			// accounts reject CloseRemainderTo by contract, so they first rekey to
			// this test-owned Ed25519 authority and are then closed normally.
			cleanupPlans := prepareMatrixRekeyCleanups(
				t, testnet, signerClient, signerd.GetURL(), token, fundingAddress,
				batch, sp, approvalClient, cleanupAuthority,
			)
			cleanupReserves := matrixCleanupReserves(cleanupPlans)

			// Prepare and sign the exact settlement group before putting funds at
			// risk. Close-capable accounts close directly; bounded accounts retain
			// only the minimum balance plus their already-finalized rekey fee.
			signTxns := make([]matrixSignTxn, 0, len(batch))
			for _, account := range batch {
				signTxns = append(signTxns, account.positiveSignTxn(
					t, sp, funder.GetAddress(), cleanupReserves[account.address],
				))
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
			assertMatrixAccountsSettleExactly(t, signResp.Signed, signTxns)

			cleanupState := newMatrixBatchCleanupState(signResp.Signed, cleanupPlans)
			t.Cleanup(func() {
				if cleanupState.funded && !cleanupState.complete() {
					if err := cleanupState.run(testnet, funder.GetAddress()); err != nil {
						t.Logf("WARNING: matrix cleanup could not recover batch funding: %v", err)
					}
				}
			})

			cleanupState.funded = true
			fundingRound := fundMatrixBatch(t, testnet, funder, sp, batch)
			waitForMatrixFundingVisibility(t, testnet, batch)

			for _, account := range batch {
				if account.negative.name == "" {
					continue
				}
				t.Run(account.keyType+"/negative/"+account.negative.name, func(t *testing.T) {
					negativeReq := matrixSignRequest(t, sp, fundingAddress, []matrixSignTxn{
						account.negativeSignTxn(t, sp, funder.GetAddress()),
					})
					negativeStatus, negativeBody := postSignRequest(t, signerd.GetURL(), "aplane "+token, negativeReq)
					if negativeStatus != http.StatusOK {
						t.Fatalf("expected signer to produce LogicSig for negative case, got %d: %s", negativeStatus, string(negativeBody))
					}
					var negativeResp signerapi.GroupSignResponse
					if err := json.Unmarshal(negativeBody, &negativeResp); err != nil {
						t.Fatalf("failed to parse sign response: %v", err)
					}
					if negativeResp.Error != "" {
						t.Fatalf("unexpected sign error: %s", negativeResp.Error)
					}
					assertMatrixPlannerDummies(t, negativeResp, len(negativeReq.Requests), 0)
					submitSignedTxnGroupExpectFailure(t, testnet, negativeResp.Signed)
				})
			}

			validateMatrixHTLCAssetOptInOpcodeCeilings(
				t, compileAlgod, signerd.GetURL(), token, fundingAddress, batch, mustSuggestedParams(t, testnet), fundingRound,
			)
			validateMatrixRekeyOpcodeCeilings(t, compileAlgod, cleanupPlans, fundingRound)

			validateMatrixOpcodeCeilings(t, compileAlgod, batch, signResp.Signed, fundingRound)
			if err := cleanupState.run(testnet, funder.GetAddress()); err != nil {
				t.Fatalf("recover matrix batch funding: %v", err)
			}
			if !cleanupState.complete() {
				t.Fatal("matrix batch cleanup returned without completing")
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

type matrixRekeyCleanupPlan struct {
	account           includedKeyTypeAccount
	signedHexes       []string
	targetFee         uint64
	path              lsigresource.AuthorizationPath
	cleanupPrivateKey stded25519.PrivateKey
}

func prepareMatrixRekeyCleanups(
	t *testing.T,
	testnet *harness.TestnetConfig,
	signerClient *signerclient.Client,
	signerURL string,
	token string,
	fundingAddress string,
	accounts []includedKeyTypeAccount,
	sp types.SuggestedParams,
	approvalClient *transport.IPCClient,
	cleanupAuthority algocrypto.Account,
) []matrixRekeyCleanupPlan {
	t.Helper()
	plans := make([]matrixRekeyCleanupPlan, 0)
	for _, account := range accounts {
		switch {
		case matrixSupportsSpendingRekey(account.keyType):
			plans = append(plans, prepareMatrixSpendingRekeyCleanup(
				t, signerURL, token, fundingAddress, account, sp, approvalClient, cleanupAuthority,
			))
		case account.keyType == "aplane.falcon1024-allowlist-alock.v1":
			plans = append(plans, prepareMatrixAdminRekeyCleanup(
				t, testnet, signerClient, account, sp, approvalClient, cleanupAuthority,
			))
		}
	}
	return plans
}

func prepareMatrixSpendingRekeyCleanup(
	t *testing.T,
	signerURL string,
	token string,
	fundingAddress string,
	account includedKeyTypeAccount,
	sp types.SuggestedParams,
	approvalClient *transport.IPCClient,
	cleanupAuthority algocrypto.Account,
) matrixRekeyCleanupPlan {
	t.Helper()
	txn := mustPaymentTxnForMatrix(
		t, sp, account.address, account.address, "keytype-matrix-spending-rekey", "", account.positiveFirstValid,
	)
	txn.RekeyTo = cleanupAuthority.Address
	req := matrixSignRequest(t, sp, fundingAddress, []matrixSignTxn{{authAddress: account.address, txn: txn}})

	var status int
	var body []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		status, body = postSignRequest(t, signerURL, "aplane "+token, req)
	}()
	approval := mustReadIPCSignRequest(t, approvalClient, 10*time.Second)
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
	target := decodeSignedTxnHex(t, signResp.Signed[0])
	return matrixRekeyCleanupPlan{
		account: account, signedHexes: signResp.Signed, targetFee: uint64(target.Txn.Fee),
		path: lsigresource.PathSpendingRekey, cleanupPrivateKey: cleanupAuthority.PrivateKey,
	}
}

func prepareMatrixAdminRekeyCleanup(
	t *testing.T,
	testnet *harness.TestnetConfig,
	signerClient *signerclient.Client,
	account includedKeyTypeAccount,
	sp types.SuggestedParams,
	approvalClient *transport.IPCClient,
	cleanupAuthority algocrypto.Account,
) matrixRekeyCleanupPlan {
	t.Helper()
	if len(account.adminPrivateKey) == 0 {
		t.Fatalf("%s cleanup admin private key is missing", account.keyType)
	}
	txn := mustPaymentTxnForMatrix(
		t, sp, account.address, account.address, "keytype-matrix-admin-rekey", "", account.positiveFirstValid,
	)
	txn.RekeyTo = cleanupAuthority.Address

	var partial *signerapi.BoundedAdminPartialResponse
	var requestErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		partial, requestErr = signerClient.RequestBoundedAdmin(
			signerapi.BoundedAdminOperationRekey,
			[]signerapi.SignRequest{{
				AuthAddress: account.address,
				TxnSender:   account.address,
				TxnBytesHex: txnHexForMatrix(txn),
			}},
		)
	}()
	approval := mustReadIPCSignRequest(t, approvalClient, 10*time.Second)
	mustApproveIPCSignRequest(t, approvalClient, approval.ID)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for approved contract-admin rekey signing")
	}
	if requestErr != nil {
		t.Fatalf("prepare contract-admin rekey cleanup: %v", requestErr)
	}

	request, err := boundedprotocol.NewRequest(boundedprotocol.RequestPayload{
		Partial:            *partial,
		Network:            testnet.Network,
		GenesisHashHex:     hex.EncodeToString(sp.GenesisHash),
		CurrentAuthAddress: account.address,
	})
	if err != nil {
		t.Fatalf("build contract-admin cleanup request: %v", err)
	}
	validated, err := boundedauthorization.ValidateRequest(request)
	if err != nil {
		t.Fatalf("validate contract-admin cleanup request: %v", err)
	}
	adminSignature, err := signerops.New(nil).Sign(account.adminPrivateKey, validated.Message[:])
	if err != nil {
		t.Fatalf("sign contract-admin cleanup request: %v", err)
	}
	response := boundedprotocol.Response{
		Schema:             boundedprotocol.ResponseSchemaV1,
		RequestHashHex:     request.RequestHashHex,
		ContractAdminKeyID: partial.Authorization.ContractAdminKeyID,
		SignatureHex:       hex.EncodeToString(adminSignature),
	}
	signed, txns, err := boundedauthorization.Complete(request, response)
	if err != nil {
		t.Fatalf("complete contract-admin cleanup request: %v", err)
	}
	signedHexes := make([]string, len(signed))
	for i := range signed {
		signedHexes[i] = hex.EncodeToString(signed[i])
	}
	return matrixRekeyCleanupPlan{
		account: account, signedHexes: signedHexes, targetFee: uint64(txns[partial.TargetIndex].Fee),
		path: lsigresource.PathAdminRekey, cleanupPrivateKey: cleanupAuthority.PrivateKey,
	}
}

func validateMatrixRekeyOpcodeCeilings(
	t *testing.T,
	client *sdkalgod.Client,
	plans []matrixRekeyCleanupPlan,
	simulationRound uint64,
) {
	t.Helper()
	for _, plan := range plans {
		plan := plan
		pathName := "spending-rekey"
		vectorName := "maximum-spending-key-rekey"
		if plan.path == lsigresource.PathAdminRekey {
			pathName = "admin-rekey"
			vectorName = "maximum-admin-key-rekey"
		}
		t.Run(plan.account.keyType+"/opcode/"+pathName, func(t *testing.T) {
			signed := make([]types.SignedTxn, len(plan.signedHexes))
			for i, encoded := range plan.signedHexes {
				signed[i] = decodeSignedTxnHex(t, encoded)
			}
			profile := matrixDeclaredOpcodeProfile(t, plan.account.keyType)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), client, harness.OpcodeCeilingValidation{
				Name: plan.account.keyType, FinalProgram: signed[0].Lsig.Logic, Profile: profile,
				Bounded: true, Round: simulationRound, RequiredPaths: []lsigresource.AuthorizationPath{plan.path},
				Vectors: []harness.OpcodeCeilingVector{{
					Name: vectorName, Path: plan.path, SignedTxns: signed, LSigIndex: 0,
				}},
			})
			if err != nil {
				t.Fatalf("validate %s opcode ceiling: %v", pathName, err)
			}
			observed := report.Paths[plan.path]
			t.Logf("%s opcode cost: %d observed / %d declared", pathName, observed.MaximumObserved, observed.DeclaredCeiling)
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
	adminPrivateKey    []byte
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
	simulationRound uint64,
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
			// The vector is built after the funding-visibility wait. A public
			// TestNet node may therefore give it a FirstValid later than the
			// funding round whose state the simulation must include.
			opcodeSimulationRound := matrixOpcodeSimulationRound(t, simulationRound, signed)
			profile := matrixDeclaredOpcodeProfile(t, account.keyType)
			report, err := harness.ValidateDeclaredOpcodeCeiling(context.Background(), client, harness.OpcodeCeilingValidation{
				Name:          account.keyType,
				FinalProgram:  signed[0].Lsig.Logic,
				Profile:       profile,
				Round:         opcodeSimulationRound,
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

func matrixOpcodeSimulationRound(t *testing.T, stateRound uint64, signed []types.SignedTxn) uint64 {
	t.Helper()
	round := stateRound
	for _, stxn := range signed {
		if firstValid := uint64(stxn.Txn.FirstValid); round < firstValid {
			round = firstValid
		}
	}
	for i, stxn := range signed {
		if lastValid := uint64(stxn.Txn.LastValid); round > lastValid {
			t.Fatalf(
				"opcode simulation round %d is outside transaction %d validity window %d--%d",
				round, i, stxn.Txn.FirstValid, stxn.Txn.LastValid,
			)
		}
	}
	return round
}

func TestMatrixOpcodeSimulationRoundUsesValidGroupRound(t *testing.T) {
	signed := []types.SignedTxn{
		{Txn: types.Transaction{Header: types.Header{FirstValid: 101, LastValid: 1_101}}},
		{Txn: types.Transaction{Header: types.Header{FirstValid: 103, LastValid: 1_103}}},
	}
	for _, tc := range []struct {
		name       string
		stateRound uint64
		want       uint64
	}{
		{name: "advance stale state round", stateRound: 100, want: 103},
		{name: "preserve newer state round", stateRound: 105, want: 105},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matrixOpcodeSimulationRound(t, tc.stateRound, signed); got != tc.want {
				t.Fatalf("matrixOpcodeSimulationRound() = %d, want %d", got, tc.want)
			}
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
	authAddress     string
	txn             types.Transaction
	lsigArgs        map[string]string
	retainedBalance uint64
}

func (a includedKeyTypeAccount) positiveSignTxn(
	t *testing.T,
	sp types.SuggestedParams,
	destination string,
	retainedBalance uint64,
) matrixSignTxn {
	t.Helper()
	closeTo := ""
	if retainedBalance == 0 {
		closeTo = destination
	}
	txn := mustPaymentTxnForMatrix(t, sp, a.address, destination, "keytype-matrix-positive", closeTo, a.positiveFirstValid)
	if uint64(txn.Fee)+retainedBalance >= matrixAccountFunding {
		t.Fatalf(
			"matrix transaction fee %d plus retained balance %d exhaust account funding %d",
			txn.Fee, retainedBalance, matrixAccountFunding,
		)
	}
	txn.Amount = types.MicroAlgos(matrixAccountFunding - uint64(txn.Fee) - retainedBalance)
	return matrixSignTxn{
		authAddress:     a.address,
		txn:             txn,
		lsigArgs:        a.positiveArgs,
		retainedBalance: retainedBalance,
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
		if plannedFee+signTxns[i].retainedBalance >= matrixAccountFunding {
			t.Fatalf(
				"planned matrix fee %d plus retained balance %d exhaust account funding %d",
				plannedFee, signTxns[i].retainedBalance, matrixAccountFunding,
			)
		}
		signTxns[i].txn.Amount = types.MicroAlgos(
			matrixAccountFunding - plannedFee - signTxns[i].retainedBalance,
		)
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

func assertMatrixAccountsSettleExactly(t *testing.T, signed []string, signTxns []matrixSignTxn) {
	t.Helper()
	for i, signTxn := range signTxns {
		stxn := decodeSignedTxnHex(t, signed[i])
		spent := uint64(stxn.Txn.Amount) + uint64(stxn.Txn.Fee)
		wantSpent := matrixAccountFunding - signTxn.retainedBalance
		if spent != wantSpent {
			t.Fatalf("matrix transaction %d spends %d microAlgos, want %d", i+1, spent, wantSpent)
		}
		if signTxn.retainedBalance == 0 && stxn.Txn.CloseRemainderTo.IsZero() {
			t.Fatalf("matrix transaction %d must close its account", i+1)
		}
		if signTxn.retainedBalance != 0 && !stxn.Txn.CloseRemainderTo.IsZero() {
			t.Fatalf("bounded matrix transaction %d unexpectedly closes its account", i+1)
		}
	}
}

func fundMatrixBatch(
	t *testing.T,
	testnet *harness.TestnetConfig,
	funder *harness.FundTestAccount,
	sp types.SuggestedParams,
	accounts []includedKeyTypeAccount,
) uint64 {
	t.Helper()
	txns := make([]types.Transaction, len(accounts))
	for i, account := range accounts {
		txn, err := transaction.MakePaymentTxn(
			funder.GetAddress(), account.address, matrixAccountFunding,
			[]byte("keytype-matrix-fund"), "", sp,
		)
		if err != nil {
			t.Fatalf("build %s funding transaction: %v", account.keyType, err)
		}
		prepared, err := funder.PrepareTransaction(txn, sp.MinFee)
		if err != nil {
			t.Fatalf("prepare %s funding transaction: %v", account.keyType, err)
		}
		txns[i] = prepared
	}
	groupID, err := algocrypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("compute matrix funding group ID: %v", err)
	}
	rawGroup := make([]byte, 0)
	firstTxID := ""
	for i := range txns {
		txns[i].Group = groupID
		txid, signed, err := funder.SignTransaction(txns[i])
		if err != nil {
			t.Fatalf("sign %s funding transaction: %v", accounts[i].keyType, err)
		}
		if firstTxID == "" {
			firstTxID = txid
		}
		rawGroup = append(rawGroup, signed...)
	}
	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		t.Fatalf("submit atomic matrix funding group: %v", err)
	}
	confirmedRound, err := testnet.WaitForConfirmation(firstTxID, 10)
	if err != nil {
		t.Fatalf("matrix funding group %s failed to confirm: %v", firstTxID, err)
	}
	return confirmedRound
}

func waitForMatrixFundingVisibility(
	t *testing.T,
	testnet *harness.TestnetConfig,
	accounts []includedKeyTypeAccount,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	observedOnce := false
	lastIssue := "funded accounts were not visible"
	for ctx.Err() == nil {
		allVisible := true
		for _, account := range accounts {
			info, err := testnet.Client.AccountInformation(account.address).Do(ctx)
			if err != nil {
				allVisible = false
				lastIssue = fmt.Sprintf("read %s account %s: %v", account.keyType, account.address, err)
				break
			}
			if info.Amount < matrixAccountFunding {
				allVisible = false
				lastIssue = fmt.Sprintf(
					"%s account %s balance is %d, want at least %d",
					account.keyType, account.address, info.Amount, matrixAccountFunding,
				)
				break
			}
		}
		if !allVisible {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if testnet.Network == harness.IntegrationNetworkLocalnet || observedOnce {
			return
		}

		// Public algod endpoints may load-balance account reads and simulation
		// across nodes. Require the funded state to remain visible across one
		// additional round before asking a potentially different node to
		// simulate the group. LocalNet may not produce empty rounds, so the
		// confirmed balance reads above are sufficient for that profile.
		status, err := testnet.Client.Status().Do(ctx)
		if err != nil {
			lastIssue = fmt.Sprintf("read algod status after funding: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if _, err := testnet.Client.StatusAfterBlock(status.LastRound).Do(ctx); err != nil {
			lastIssue = fmt.Sprintf("wait for post-funding round: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		observedOnce = true
	}
	t.Fatalf("matrix funding did not become consistently visible within 30s: %s", lastIssue)
}

func matrixCleanupReserves(plans []matrixRekeyCleanupPlan) map[string]uint64 {
	reserves := make(map[string]uint64, len(plans))
	for _, plan := range plans {
		reserves[plan.account.address] = matrixBaseMinimumBalance + plan.targetFee
	}
	return reserves
}

type matrixBatchCleanupState struct {
	funded     bool
	settlement []string
	settled    bool
	plans      []matrixRekeyCleanupPlan
	rekeyed    []bool
	closed     []bool
}

func newMatrixBatchCleanupState(
	settlement []string,
	plans []matrixRekeyCleanupPlan,
) *matrixBatchCleanupState {
	return &matrixBatchCleanupState{
		settlement: append([]string(nil), settlement...),
		plans:      append([]matrixRekeyCleanupPlan(nil), plans...),
		rekeyed:    make([]bool, len(plans)),
		closed:     make([]bool, len(plans)),
	}
}

func (s *matrixBatchCleanupState) complete() bool {
	if s == nil || !s.settled {
		return false
	}
	for i := range s.plans {
		if !s.rekeyed[i] || !s.closed[i] {
			return false
		}
	}
	return true
}

func (s *matrixBatchCleanupState) run(testnet *harness.TestnetConfig, destination string) error {
	if s == nil {
		return fmt.Errorf("matrix cleanup state is nil")
	}
	if !s.settled {
		txids, err := sendMatrixSignedGroup(testnet, s.settlement)
		if err != nil {
			return fmt.Errorf("submit matrix settlement group: %w", err)
		}
		if len(txids) == 0 {
			return fmt.Errorf("matrix settlement group produced no transaction IDs")
		}
		s.settled = true
	}
	for i, plan := range s.plans {
		if !s.rekeyed[i] {
			if _, err := sendMatrixSignedGroup(testnet, plan.signedHexes); err != nil {
				return fmt.Errorf("rekey %s cleanup authority: %w", plan.account.keyType, err)
			}
			s.rekeyed[i] = true
		}
		if !s.closed[i] {
			if err := closeMatrixRekeyedAccount(
				testnet, plan.account.address, destination, plan.cleanupPrivateKey,
			); err != nil {
				return fmt.Errorf("close rekeyed %s account: %w", plan.account.keyType, err)
			}
			s.closed[i] = true
		}
	}
	return nil
}

func sendMatrixSignedGroup(testnet *harness.TestnetConfig, signedHexes []string) ([]string, error) {
	rawGroup := make([]byte, 0)
	txids := make([]string, 0, len(signedHexes))
	for _, signedHex := range signedHexes {
		signedBytes, err := hex.DecodeString(signedHex)
		if err != nil {
			return nil, fmt.Errorf("decode signed matrix transaction: %w", err)
		}
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedBytes, &stxn); err != nil {
			return nil, fmt.Errorf("decode signed matrix transaction: %w", err)
		}
		rawGroup = append(rawGroup, signedBytes...)
		txids = append(txids, algocrypto.GetTxID(stxn.Txn))
	}
	if len(rawGroup) == 0 {
		return nil, fmt.Errorf("signed matrix group is empty")
	}
	if _, err := testnet.Client.SendRawTransaction(rawGroup).Do(context.Background()); err != nil {
		return nil, err
	}
	if _, err := testnet.WaitForConfirmation(txids[0], 10); err != nil {
		return nil, fmt.Errorf("wait for matrix group %s: %w", txids[0], err)
	}
	return txids, nil
}

func closeMatrixRekeyedAccount(
	testnet *harness.TestnetConfig,
	account string,
	destination string,
	authPrivateKey stded25519.PrivateKey,
) error {
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		return fmt.Errorf("read suggested params: %w", err)
	}
	txn, err := transaction.MakePaymentTxn(
		account, destination, 0, []byte("keytype-matrix-cleanup-close"), destination, sp,
	)
	if err != nil {
		return fmt.Errorf("build close transaction: %w", err)
	}
	txid, signedBytes, err := algocrypto.SignTransaction(authPrivateKey, txn)
	if err != nil {
		return fmt.Errorf("sign close transaction: %w", err)
	}
	if _, err := testnet.Client.SendRawTransaction(signedBytes).Do(context.Background()); err != nil {
		return fmt.Errorf("submit close transaction: %w", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		return fmt.Errorf("wait for close transaction %s: %w", txid, err)
	}
	return nil
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
	simulationRound uint64,
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
			Round:         simulationRound,
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
	falcon.RegisterClient()

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
	apadmin := harness.NewApAdminHarness(t, signerDataDir)
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
			if output, err := apadmin.Run("template", "import", templatePath); err != nil {
				t.Fatalf("failed to add bundled template %s: %v\noutput:\n%s", templatePath, err, output)
			}
		}
	})
	_ = os.Unsetenv("APSIGNER_PASSPHRASE")
}
