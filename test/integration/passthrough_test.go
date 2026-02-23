// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package integration_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/util"
	"github.com/aplane-algo/aplane/test/integration/harness"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/mnemonic"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestPassthroughMixedGroup tests submitting a group with both sign and passthrough transactions.
// This simulates multi-party signing where Party B has already signed their transaction.
func TestPassthroughMixedGroup(t *testing.T) {
	// Skip if no funding mnemonic (we need the private key to sign externally)
	fundingMnemonic := os.Getenv("TEST_FUNDING_MNEMONIC")
	if fundingMnemonic == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping passthrough integration test")
	}

	// Connect to testnet
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("Failed to connect to testnet: %v", err)
	}

	// Get funding account private key (for external signing - simulates Party B)
	fundingPrivKey, err := mnemonic.ToPrivateKey(fundingMnemonic)
	if err != nil {
		t.Fatalf("Failed to convert mnemonic to private key: %v", err)
	}
	fundingAddr, err := crypto.GenerateAddressFromSK(fundingPrivKey)
	if err != nil {
		t.Fatalf("Failed to generate address from SK: %v", err)
	}
	t.Logf("Funding account (Party B - external signer): %s", fundingAddr.String())

	// Start Signer
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	// Create apadmin harness for key management
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	// Import the funding account into Signer as well (for signing txn A)
	// This represents Party A who uses apsignerd
	t.Log("Importing funding account into Signer (Party A)...")
	importedAddr, err := apadmin.ImportKey(fundingMnemonic)
	if err != nil {
		t.Fatalf("Failed to import funding account: %v", err)
	}
	t.Logf("Imported as Party A's key: %s", importedAddr)

	// Start background unlock
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("Failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	// Get suggested params
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("Failed to get suggested params: %v", err)
	}

	// Create two transactions:
	// - Txn A: Will be signed by apsignerd (sign mode)
	// - Txn B: Will be signed externally and passed through (passthrough mode)
	burnAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	// Transaction A: funding -> burn (to be signed by server)
	txnA, err := transaction.MakePaymentTxn(
		fundingAddr.String(),
		burnAddr,
		0, // 0 ALGO (validation-style)
		[]byte("txn-A-server-signs"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("Failed to create txn A: %v", err)
	}

	// Transaction B: funding -> burn (to be signed externally, passthrough)
	txnB, err := transaction.MakePaymentTxn(
		fundingAddr.String(),
		burnAddr,
		0, // 0 ALGO
		[]byte("txn-B-passthrough"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("Failed to create txn B: %v", err)
	}

	// Compute group ID and assign to both
	gid, err := crypto.ComputeGroupID([]types.Transaction{txnA, txnB})
	if err != nil {
		t.Fatalf("Failed to compute group ID: %v", err)
	}
	txnA.Group = gid
	txnB.Group = gid
	t.Logf("Group ID: %x", gid[:8])

	// Sign txn B externally (simulates Party B signing their part)
	_, stxnBBytes, err := crypto.SignTransaction(fundingPrivKey, txnB)
	if err != nil {
		t.Fatalf("Failed to sign txn B externally: %v", err)
	}
	stxnBHex := hex.EncodeToString(stxnBBytes)
	t.Logf("Externally signed txn B (passthrough): %d bytes", len(stxnBBytes))

	// Encode txn A as unsigned (for server to sign)
	txnABytes := msgpack.Encode(txnA)
	txnAWithPrefix := append([]byte("TX"), txnABytes...)
	txnAHex := hex.EncodeToString(txnAWithPrefix)

	// Build the request with mixed sign + passthrough
	groupReq := util.GroupSignRequest{
		Requests: []util.SignRequest{
			{
				// Txn A: sign mode
				AuthAddress: fundingAddr.String(),
				TxnBytesHex: txnAHex,
			},
			{
				// Txn B: passthrough mode
				SignedTxnHex: stxnBHex,
			},
		},
	}

	// Read the API token
	tokenBytes, err := os.ReadFile(signerd.GetTokenPath())
	if err != nil {
		t.Fatalf("Failed to read API token from %s: %v", signerd.GetTokenPath(), err)
	}
	token := string(bytes.TrimSpace(tokenBytes))

	// Submit to /sign endpoint
	reqBody, _ := json.Marshal(groupReq)
	req, err := http.NewRequest("POST", signerd.GetURL()+"/sign", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+token)

	t.Log("Submitting mixed sign + passthrough request to /sign...")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	t.Logf("Response status: %d", resp.StatusCode)
	t.Logf("Response body: %s", string(respBody))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var groupResp util.GroupSignResponse
	if err := json.Unmarshal(respBody, &groupResp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if groupResp.Error != "" {
		t.Fatalf("Server returned error: %s", groupResp.Error)
	}

	// Verify we got 2 signed transactions back
	if len(groupResp.Signed) != 2 {
		t.Fatalf("Expected 2 signed transactions, got %d", len(groupResp.Signed))
	}
	t.Logf("Received %d signed transactions", len(groupResp.Signed))

	// Verify mutation report shows passthrough
	if groupResp.Mutations != nil {
		t.Logf("Mutations: passthrough_count=%d, reason=%s",
			groupResp.Mutations.PassthroughCount, groupResp.Mutations.Reason)
		if groupResp.Mutations.PassthroughCount != 1 {
			t.Errorf("Expected passthrough_count=1, got %d", groupResp.Mutations.PassthroughCount)
		}
	} else {
		t.Error("Expected mutations report with passthrough info")
	}

	// Verify the passthrough transaction is unchanged
	if groupResp.Signed[1] != stxnBHex {
		t.Error("Passthrough transaction was modified (should be unchanged)")
	} else {
		t.Log("Passthrough transaction preserved correctly")
	}

	// Decode and verify both signed transactions
	for i, stxnHex := range groupResp.Signed {
		stxnBytes, err := hex.DecodeString(stxnHex)
		if err != nil {
			t.Fatalf("Failed to decode signed txn %d: %v", i, err)
		}

		var stxn types.SignedTxn
		if err := msgpack.Decode(stxnBytes, &stxn); err != nil {
			t.Fatalf("Failed to unmarshal signed txn %d: %v", i, err)
		}

		// Verify group ID is correct
		if stxn.Txn.Group != gid {
			t.Errorf("Txn %d has wrong group ID: got %x, want %x", i, stxn.Txn.Group[:8], gid[:8])
		}

		// Verify signature is present
		if stxn.Sig == (types.Signature{}) && len(stxn.Lsig.Logic) == 0 {
			t.Errorf("Txn %d has no signature", i)
		}

		t.Logf("Txn %d: sender=%s, has_sig=%v", i, stxn.Txn.Sender.String(), stxn.Sig != types.Signature{})
	}

	t.Log("Passthrough mixed group test passed!")
}

// TestPassthroughResign tests the "strip and re-sign" flow:
// 1. Sign a 2-txn group (account1 <-> account2, 0 ALGO) through apsignerd
// 2. Strip the signature from one transaction
// 3. Resubmit with the stripped txn as sign mode and the other as passthrough
// 4. Verify a valid fully-signed group is returned
func TestPassthroughResign(t *testing.T) {
	fundingMnemonic := os.Getenv("TEST_FUNDING_MNEMONIC")
	if fundingMnemonic == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set, skipping passthrough resign test")
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

	// Create apadmin harness
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	// Import the funding account (account 1)
	t.Log("Importing funding account (account 1)...")
	addr1, err := apadmin.ImportKey(fundingMnemonic)
	if err != nil {
		t.Fatalf("Failed to import funding account: %v", err)
	}
	t.Logf("Account 1: %s", addr1)

	// Generate a second ed25519 account (account 2)
	t.Log("Generating second account (account 2)...")
	addr2, err := apadmin.GenerateKeyWithType("ed25519")
	if err != nil {
		t.Fatalf("Failed to generate account 2: %v", err)
	}
	t.Logf("Account 2: %s", addr2)

	// Start background unlock
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("Failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	// Read API token
	tokenBytes, err := os.ReadFile(signerd.GetTokenPath())
	if err != nil {
		t.Fatalf("Failed to read API token from %s: %v", signerd.GetTokenPath(), err)
	}
	token := string(bytes.TrimSpace(tokenBytes))
	client := &http.Client{}

	// Wait for the generated key to be available in the signer
	t.Logf("Waiting for key %s to be available...", addr2)
	if !waitForKey(t, signerd.GetURL(), token, addr2, 10*time.Second) {
		t.Fatalf("Timeout waiting for key %s to appear in signer", addr2)
	}
	t.Log("Key available")

	// Get suggested params
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("Failed to get suggested params: %v", err)
	}

	// Create two transactions: account1 -> account2 and account2 -> account1 (0 ALGO each)
	txn1, err := transaction.MakePaymentTxn(addr1, addr2, 0, []byte("txn1-a1-to-a2"), "", sp)
	if err != nil {
		t.Fatalf("Failed to create txn1: %v", err)
	}
	txn2, err := transaction.MakePaymentTxn(addr2, addr1, 0, []byte("txn2-a2-to-a1"), "", sp)
	if err != nil {
		t.Fatalf("Failed to create txn2: %v", err)
	}

	// Compute group ID
	gid, err := crypto.ComputeGroupID([]types.Transaction{txn1, txn2})
	if err != nil {
		t.Fatalf("Failed to compute group ID: %v", err)
	}
	txn1.Group = gid
	txn2.Group = gid
	t.Logf("Group ID: %x", gid[:8])

	// Encode both as unsigned for initial signing
	encodeTxn := func(txn types.Transaction) string {
		txnBytes := msgpack.Encode(txn)
		return hex.EncodeToString(append([]byte("TX"), txnBytes...))
	}

	// Step 1: Sign the full group through apsignerd
	t.Log("Step 1: Signing full group (both transactions)...")
	groupReq := util.GroupSignRequest{
		Requests: []util.SignRequest{
			{AuthAddress: addr1, TxnBytesHex: encodeTxn(txn1)},
			{AuthAddress: addr2, TxnBytesHex: encodeTxn(txn2)},
		},
	}

	reqBody, _ := json.Marshal(groupReq)
	req, _ := http.NewRequest("POST", signerd.GetURL()+"/sign", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+token)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send initial sign request: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Initial sign failed: %d: %s", resp.StatusCode, string(respBody))
	}

	var signResp util.GroupSignResponse
	if err := json.Unmarshal(respBody, &signResp); err != nil {
		t.Fatalf("Failed to parse sign response: %v", err)
	}
	if signResp.Error != "" {
		t.Fatalf("Initial sign returned error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 2 {
		t.Fatalf("Expected 2 signed transactions, got %d", len(signResp.Signed))
	}
	t.Log("Full group signed successfully")

	// Verify both are actually signed
	for i, stxnHex := range signResp.Signed {
		stxnBytes, _ := hex.DecodeString(stxnHex)
		var stxn types.SignedTxn
		if err := msgpack.Decode(stxnBytes, &stxn); err != nil {
			t.Fatalf("Failed to decode signed txn %d: %v", i, err)
		}
		if stxn.Sig == (types.Signature{}) {
			t.Fatalf("Txn %d has no signature after initial sign", i)
		}
		t.Logf("Txn %d signed: sender=%s", i, stxn.Txn.Sender.String())
	}

	// Step 2: Keep txn2 signed (passthrough), strip signature from txn1 (re-sign)
	t.Log("Step 2: Resubmitting with txn1 stripped (sign) + txn2 intact (passthrough)...")
	resignReq := util.GroupSignRequest{
		Requests: []util.SignRequest{
			{
				// Txn 1: strip signature, re-sign via server
				AuthAddress: addr1,
				TxnBytesHex: encodeTxn(txn1),
			},
			{
				// Txn 2: passthrough (keep existing signature)
				SignedTxnHex: signResp.Signed[1],
			},
		},
	}

	reqBody, _ = json.Marshal(resignReq)
	req, _ = http.NewRequest("POST", signerd.GetURL()+"/sign", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+token)

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send resign request: %v", err)
	}
	respBody, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	t.Logf("Resign response status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Resign failed: %d: %s", resp.StatusCode, string(respBody))
	}

	var resignResp util.GroupSignResponse
	if err := json.Unmarshal(respBody, &resignResp); err != nil {
		t.Fatalf("Failed to parse resign response: %v", err)
	}
	if resignResp.Error != "" {
		t.Fatalf("Resign returned error: %s", resignResp.Error)
	}
	if len(resignResp.Signed) != 2 {
		t.Fatalf("Expected 2 signed transactions from resign, got %d", len(resignResp.Signed))
	}

	// Verify mutations report
	if resignResp.Mutations != nil {
		t.Logf("Mutations: passthrough_count=%d", resignResp.Mutations.PassthroughCount)
		if resignResp.Mutations.PassthroughCount != 1 {
			t.Errorf("Expected passthrough_count=1, got %d", resignResp.Mutations.PassthroughCount)
		}
	} else {
		t.Error("Expected mutations report")
	}

	// Verify passthrough txn2 is byte-identical
	if resignResp.Signed[1] != signResp.Signed[1] {
		t.Error("Passthrough txn2 was modified (should be byte-identical)")
	} else {
		t.Log("Passthrough txn2 preserved correctly")
	}

	// Step 3: Verify both transactions in the result are properly signed with correct group ID
	t.Log("Step 3: Verifying final signed group...")
	for i, stxnHex := range resignResp.Signed {
		stxnBytes, _ := hex.DecodeString(stxnHex)
		var stxn types.SignedTxn
		if err := msgpack.Decode(stxnBytes, &stxn); err != nil {
			t.Fatalf("Failed to decode resign txn %d: %v", i, err)
		}
		if stxn.Txn.Group != gid {
			t.Errorf("Txn %d has wrong group ID after resign", i)
		}
		if stxn.Sig == (types.Signature{}) {
			t.Errorf("Txn %d has no signature after resign", i)
		}
		t.Logf("Txn %d: sender=%s, sig=%x...", i, stxn.Txn.Sender.String(), stxn.Sig[:4])
	}

	t.Log("Passthrough resign test passed!")
}

// waitForKey polls the /keys endpoint until the given address appears or timeout expires.
func waitForKey(t *testing.T, baseURL, token, address string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", baseURL+"/keys", nil)
		req.Header.Set("Authorization", "aplane "+token)
		resp, err := client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if bytes.Contains(body, []byte(address)) {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// TestPassthroughRequiresPreGrouped verifies that passthrough fails without group ID
func TestPassthroughRequiresPreGrouped(t *testing.T) {
	fundingMnemonic := os.Getenv("TEST_FUNDING_MNEMONIC")
	if fundingMnemonic == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}

	// Connect to testnet
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("Failed to connect to testnet: %v", err)
	}

	// Get funding account
	fundingPrivKey, _ := mnemonic.ToPrivateKey(fundingMnemonic)
	fundingAddr, _ := crypto.GenerateAddressFromSK(fundingPrivKey)

	// Start Signer
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	// Get suggested params
	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		t.Fatalf("Failed to get suggested params: %v", err)
	}

	// Create a transaction WITHOUT group ID
	txn, _ := transaction.MakePaymentTxn(
		fundingAddr.String(),
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		0,
		nil,
		"",
		sp,
	)

	// Sign it externally (but without group ID)
	_, stxnBytes, _ := crypto.SignTransaction(fundingPrivKey, txn)
	stxnHex := hex.EncodeToString(stxnBytes)

	// Try to submit as passthrough (should fail)
	groupReq := util.GroupSignRequest{
		Requests: []util.SignRequest{
			{SignedTxnHex: stxnHex},
		},
	}

	// Read token and make request
	tokenBytes, _ := os.ReadFile(signerd.GetTokenPath())
	token := string(bytes.TrimSpace(tokenBytes))

	reqBody, _ := json.Marshal(groupReq)
	req, _ := http.NewRequest("POST", signerd.GetURL()+"/sign", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "aplane "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)

	// Should fail because passthrough requires pre-grouped
	if resp.StatusCode == http.StatusOK {
		t.Error("Expected error for passthrough without group ID, but got success")
	} else {
		t.Logf("Correctly rejected: %s", string(respBody))
		if !bytes.Contains(respBody, []byte("pre-set group ID")) {
			t.Errorf("Expected error about pre-set group ID, got: %s", string(respBody))
		}
	}
}
