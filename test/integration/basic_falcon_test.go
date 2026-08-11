// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	if os.Getenv("INTEGRATION") != "1" {
		os.Exit(0)
	}

	if harness.IntegrationNetwork() == harness.IntegrationNetworkFNet {
		if _, err := harness.NewTestnetConfig(); err != nil {
			panic("failed to validate FNet integration profile: " + err.Error())
		}
		if os.Getenv("APLANE_FNET_FULL_SUITE") == "1" {
			fundingAccount, err := harness.NewFundingAccount()
			if err != nil {
				panic("failed to load FNet native Falcon funding account: " + err.Error())
			}
			network, err := harness.NewTestnetConfig()
			if err != nil {
				panic("failed to reconnect to FNet: " + err.Error())
			}
			if err := fundingAccount.EnsureFunded(network.Client); err != nil {
				panic("FNet native Falcon funding account check failed: " + err.Error())
			}
		}
		os.Exit(m.Run())
	}

	// Check for funding account
	fundingAccount, err := harness.NewFundingAccount()
	if err != nil {
		// Skip integration tests if no funding account is configured
		os.Exit(0)
	}

	// Connect to testnet
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		panic("Failed to connect to testnet: " + err.Error())
	}

	// Verify funding account has sufficient balance
	if err := fundingAccount.EnsureFunded(testnet.Client); err != nil {
		panic("Funding account check failed: " + err.Error())
	}

	// Run tests
	os.Exit(m.Run())
}

// TestBasicFalconTransaction tests a simple Falcon-signed payment
func TestBasicFalconTransaction(t *testing.T) {
	// Skip if no funding account
	if os.Getenv("TEST_FUNDING_ACCOUNT") == "" && os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_ACCOUNT or TEST_FUNDING_MNEMONIC not set, skipping integration test")
	}

	// Connect to testnet
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("Failed to connect to testnet: %v", err)
	}

	// Start Signer
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	// Create apadmin harness for key management
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup() // Clean up keys created during test

	// Import the funded native Falcon account into Signer
	fundingMnemonic := os.Getenv("TEST_FUNDING_MNEMONIC")
	if fundingMnemonic == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}

	t.Log("Importing funded account into Signer...")
	fundingAddr, err := apadmin.ImportFundingKey(fundingMnemonic)
	if err != nil {
		t.Fatalf("Failed to import funding account: %v", err)
	}
	t.Logf("Imported funding account: %s", fundingAddr)

	// Generate a Falcon key
	t.Log("Generating Falcon key...")
	falconAddr, err := apadmin.GenerateKey("test falcon key for integration testing")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	t.Logf("Generated Falcon address: %s", falconAddr)

	// Create apshell harness for sending transactions
	apshell := harness.NewApshellHarness(t, signerd.GetURL())

	// Copy the API token from signer to apshell work directory
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("Failed to copy API token: %v", err)
	}

	// Start background unlock to keep signer unlocked during apshell operations
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("Failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	// Fund the Falcon account using apshell (native Falcon → LogicSig Falcon)
	t.Logf("Funding Falcon account %s with 0.25 ALGO from %s...", falconAddr, fundingAddr)
	fundTxid, err := apshell.SendTransaction(fundingAddr, falconAddr, 0.25)
	if err != nil {
		t.Fatalf("Failed to fund Falcon account: %v", err)
	}
	t.Logf("Funding transaction submitted: %s", fundTxid)

	// Wait for funding transaction to confirm
	t.Log("Waiting for funding transaction to confirm...")
	if _, err := testnet.WaitForConfirmation(fundTxid, 10); err != nil {
		t.Fatalf("Funding transaction failed to confirm: %v", err)
	}
	t.Log("Falcon account funded successfully")

	// Send a Falcon-signed transaction
	t.Log("Sending Falcon-signed transaction...")
	recipient := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" // burn address
	txid, err := apshell.SendTransaction(falconAddr, recipient, 0.01)
	if err != nil {
		t.Fatalf("Failed to send Falcon transaction: %v", err)
	}
	t.Logf("Falcon transaction submitted: %s", txid)

	// Wait for confirmation
	t.Log("Waiting for Falcon transaction confirmation...")
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("Falcon transaction failed to confirm: %v", err)
	}
	t.Log("✓ Falcon transaction confirmed on testnet!")

	// Close Falcon account back to funding account (returns all remaining ALGO)
	t.Logf("Closing Falcon account %s to funding account %s...", falconAddr, fundingAddr)
	closeTxid, err := apshell.CloseAccount(falconAddr, fundingAddr)
	if err != nil {
		t.Fatalf("Failed to close Falcon account: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(closeTxid, 10); err != nil {
		t.Fatalf("Close transaction failed to confirm: %v", err)
	}
	t.Logf("✓ Falcon account closed, funds returned (txid %s)", closeTxid)

	// Verify in logs that Falcon signing was used
	logs, err := signerd.GetLogs()
	if err != nil {
		t.Logf("Warning: Could not retrieve logs: %v", err)
	} else {
		if strings.Contains(logs, "Falcon") || strings.Contains(logs, "falcon") {
			t.Log("Confirmed: Falcon signing was used (found in logs)")
		}
	}
}

// TestFalconGroupTransaction tests Falcon signing in an atomic group
func TestFalconGroupTransaction(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping Falcon group integration test")
	}

	harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("Failed to connect to testnet: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("Failed to load funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("Failed to copy API token: %v", err)
	}

	t.Log("Generating Falcon keys...")
	addr1, err := apadmin.GenerateKey("test falcon key 1")
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}
	addr2, err := apadmin.GenerateKey("test falcon key 2")
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}
	t.Logf("Generated addresses: %s, %s", addr1, addr2)

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("Failed to start background unlock: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	t.Cleanup(func() {
		closeAccountToFunding(t, apshell, testnet, addr1, funder.GetAddress())
		closeAccountToFunding(t, apshell, testnet, addr2, funder.GetAddress())
	})

	if err := funder.FundMicroAlgosAndWait(addr1, 300_000); err != nil {
		t.Fatalf("Failed to fund Falcon account %s: %v", addr1, err)
	}
	if err := funder.FundMicroAlgosAndWait(addr2, 300_000); err != nil {
		t.Fatalf("Failed to fund Falcon account %s: %v", addr2, err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("Failed to get suggested params: %v", err)
	}

	token := readSignerToken(t, signerd)
	if !waitForKey(t, signerd.GetURL(), token, addr1, 10*time.Second) {
		t.Fatalf("Signer did not reload Falcon key %s", addr1)
	}
	if !waitForKey(t, signerd.GetURL(), token, addr2, 10*time.Second) {
		t.Fatalf("Signer did not reload Falcon key %s", addr2)
	}

	txn1, err := transaction.MakePaymentTxn(addr1, integrationBurnAddress, 0, []byte("falcon-group-1"), "", sp)
	if err != nil {
		t.Fatalf("Failed to build txn 1: %v", err)
	}
	txn2, err := transaction.MakePaymentTxn(addr2, integrationBurnAddress, 0, []byte("falcon-group-2"), "", sp)
	if err != nil {
		t.Fatalf("Failed to build txn 2: %v", err)
	}

	signReq := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{
				AuthAddress: addr1,
				TxnBytesHex: hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn1)...)),
			},
			{
				AuthAddress: addr2,
				TxnBytesHex: hex.EncodeToString(append([]byte("TX"), msgpack.Encode(txn2)...)),
			},
		},
	}

	status, body := postSignRequest(t, signerd.GetURL(), "aplane "+token, signReq)
	if status != 200 {
		t.Fatalf("Expected 200 from /sign, got %d: %s", status, string(body))
	}

	var signResp signerapi.GroupSignResponse
	if err := json.Unmarshal(body, &signResp); err != nil {
		t.Fatalf("Failed to parse group sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("Signer returned error: %s", signResp.Error)
	}
	if len(signResp.Signed) < 2 {
		t.Fatalf("Expected at least 2 signed transactions, got %d", len(signResp.Signed))
	}
	if signResp.Mutations == nil || signResp.Mutations.DummiesAdded == 0 {
		t.Fatalf("Expected Falcon group signing to add dummy transactions for LSig budget, got %#v", signResp.Mutations)
	}

	stxn1 := decodeSignedTxnHex(t, signResp.Signed[0])
	stxn2 := decodeSignedTxnHex(t, signResp.Signed[1])
	if len(stxn1.Lsig.Logic) == 0 || len(stxn2.Lsig.Logic) == 0 {
		t.Fatalf("Expected Falcon LogicSig transactions, got lsig sizes %d and %d", len(stxn1.Lsig.Logic), len(stxn2.Lsig.Logic))
	}
	if stxn1.Sig != (types.Signature{}) || stxn2.Sig != (types.Signature{}) {
		t.Fatalf("Expected Falcon transactions to be LogicSig-signed, got direct signatures")
	}
	if stxn1.Txn.Group == (types.Digest{}) || stxn2.Txn.Group == (types.Digest{}) || stxn1.Txn.Group != stxn2.Txn.Group {
		t.Fatalf("Expected signer to group Falcon transactions, got %x and %x", stxn1.Txn.Group[:8], stxn2.Txn.Group[:8])
	}

	txids := submitSignedTxnGroup(t, testnet, signResp.Signed)
	if len(txids) != len(signResp.Signed) {
		t.Fatalf("Expected txids for all signed transactions, got %d for %d signed txns", len(txids), len(signResp.Signed))
	}
	if _, err := testnet.WaitForConfirmation(txids[0], 10); err != nil {
		t.Fatalf("Falcon group transaction failed to confirm: %v", err)
	}
}
