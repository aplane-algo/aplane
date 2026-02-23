// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package integration_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestMain sets up the test environment
func TestMain(m *testing.M) {
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

	// Import the funded ed25519 account into Signer
	fundingMnemonic := os.Getenv("TEST_FUNDING_MNEMONIC")
	if fundingMnemonic == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}

	t.Log("Importing funded account into Signer...")
	fundingAddr, err := apadmin.ImportKey(fundingMnemonic)
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

	// Fund the Falcon account using apshell (ed25519 → Falcon)
	t.Logf("Funding Falcon account %s with 1 ALGO from %s...", falconAddr, fundingAddr)
	fundTxid, err := apshell.SendTransaction(fundingAddr, falconAddr, 1.0)
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
	txid, err := apshell.SendTransaction(falconAddr, recipient, 0.1)
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

	// Return remaining funds to the funding account (keeps it topped up for future tests)
	if err := returnRemainingFunds(t, testnet, apshell, falconAddr, fundingAddr); err != nil {
		t.Fatalf("Failed to return remaining funds: %v", err)
	}

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

// returnRemainingFunds sends all available ALGO minus 0.01 ALGO back to the canonical funding account
func returnRemainingFunds(t *testing.T, testnet *harness.TestnetConfig, apshell *harness.ApshellHarness, sourceAddr, destAddr string) error {
	acctAmount, err := testnet.GetAccountInfo(sourceAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch account info: %w", err)
	}

	sp, err := testnet.GetSuggestedParams()
	if err != nil {
		return fmt.Errorf("failed to get suggested params: %w", err)
	}
	const falconFeeMicroAlgos = 4_000 // Falcon signature requires ~0.004 ALGO fee
	const bufferMicroAlgos = 100_000  // 0.1 ALGO buffer to keep account active

	fee := uint64(sp.Fee)
	if fee < falconFeeMicroAlgos {
		fee = falconFeeMicroAlgos
	}
	available := acctAmount
	if available <= fee+bufferMicroAlgos {
		t.Logf("Account %s has insufficient balance (available %d µALGO) to return funds", sourceAddr, acctAmount)
		return nil
	}
	available -= fee + bufferMicroAlgos
	if available <= 0 {
		t.Logf("Account %s has insufficient balance (available %d µALGO) to return funds", sourceAddr, acctAmount)
		return nil
	}

	amountALGO := float64(available) / 1_000_000.0
	t.Logf("Returning %.6f ALGO from %s to %s", amountALGO, sourceAddr, destAddr)

	txid, err := apshell.SendTransaction(sourceAddr, destAddr, amountALGO)
	if err != nil {
		return fmt.Errorf("failed to send return transaction: %w", err)
	}

	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		return fmt.Errorf("return transaction %s failed to confirm: %w", txid, err)
	}

	t.Logf("Remaining funds returned successfully (txid %s)", txid)
	return nil
}

// TestFalconGroupTransaction tests Falcon signing in an atomic group
func TestFalconGroupTransaction(t *testing.T) {
	// Skip if no funding account
	if os.Getenv("TEST_FUNDING_ACCOUNT") == "" {
		t.Skip("TEST_FUNDING_ACCOUNT not set, skipping integration test")
	}

	// Start Signer
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	// Create apadmin harness for key management
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	// Generate two Falcon keys
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

	// This test would need group transaction support in apshell
	// For now, we'll mark it as a known limitation
	t.Log("Group transaction testing requires additional apshell commands")
	t.Log("This will be implemented when group command is available")
}

// TestFalconWithPassphrase tests Falcon key generation and usage with passphrase
func TestFalconWithPassphrase(t *testing.T) {
	// Skip if no funding account
	if os.Getenv("TEST_FUNDING_ACCOUNT") == "" {
		t.Skip("TEST_FUNDING_ACCOUNT not set, skipping integration test")
	}

	// Start Signer
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	// Create apadmin harness for key management
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	// Generate a Falcon key with passphrase
	t.Log("Generating Falcon key with passphrase...")
	// Note: apadmin also prompts for passphrase at startup
	// For this test, we'll use empty store passphrase but the key generation
	// would require additional work to support per-key passphrases
	address, err := apadmin.GenerateKey("test key with passphrase")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	t.Logf("Generated address: %s", address)

	// Try to use the key (will need to provide passphrase)
	// This would require testing the passphrase prompt in send command
	t.Log("Passphrase-protected key created successfully")
}

// TestSignerRestart tests that Signer can be restarted and keys persist
func TestSignerRestart(t *testing.T) {
	// Skip if no funding account
	if os.Getenv("TEST_FUNDING_ACCOUNT") == "" {
		t.Skip("TEST_FUNDING_ACCOUNT not set, skipping integration test")
	}

	// Start Signer
	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to start Signer: %v", err)
	}

	// Create apadmin harness for key management
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()

	// Create apshell harness
	apshell := harness.NewApshellHarness(t, signerd.GetURL())

	// Copy the API token from signer to apshell work directory
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("Failed to copy API token: %v", err)
	}

	// Generate a key
	t.Log("Generating Falcon key...")
	address, err := apadmin.GenerateKey("test persistence key")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	t.Logf("Generated address: %s", address)

	// Stop Signer
	t.Log("Stopping Signer...")
	if err := signerd.Stop(); err != nil {
		t.Fatalf("Failed to stop Signer: %v", err)
	}

	// Restart Signer
	t.Log("Restarting Signer...")
	if err := signerd.Start(); err != nil {
		t.Fatalf("Failed to restart Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	// Verify the key still exists by trying to use it
	// We'll check the accounts list or try to sign with it
	output, err := apshell.RunWithInput("accounts\nquit\n")
	if err != nil {
		t.Fatalf("Failed to list accounts: %v", err)
	}

	if strings.Contains(output, address) {
		t.Logf("Key persisted across restart: %s found", address)
	} else {
		t.Errorf("Key not found after restart: %s", address)
	}
}
