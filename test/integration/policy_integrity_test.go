// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func TestPolicyIntegrityDirectEditRejectsAndReallowsAlgoPayment(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping policy integration test in short mode")
	}
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}

	env := harness.CloneSharedTestEnv(t, harness.TestEnvCloneOptions{})

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to integration network: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start signer: %v", err)
	}
	t.Cleanup(func() { _ = signerd.Stop() })

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	fundingAddr, err := apadmin.ImportFundingKey(os.Getenv("TEST_FUNDING_MNEMONIC"))
	if err != nil {
		t.Fatalf("failed to import funding account into signer: %v", err)
	}

	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock signer: %v", err)
	}

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	token := readSignerToken(t, signerd)
	requirePolicyTestKeyLoaded(t, signerd, token, fundingAddr)

	apstore := harness.NewApStoreHarness(t, env.SignerDataDir)
	passphrase := os.Getenv("TEST_PASSPHRASE")
	if passphrase == "" {
		t.Fatal("TEST_PASSPHRASE not set")
	}

	stopSigner(t, signerd)
	writeAndSignIntegrationPolicy(t, apstore, env.SignerDataDir, passphrase, restrictiveAlgoPaymentPolicy(testnet.Network))
	startSignerAndLoadKey(t, signerd, apadmin, token, fundingAddr)

	validateOutput, err := apshell.RunWithInput(fmt.Sprintf("validate %s\nquit\n", fundingAddr))
	if err != nil {
		t.Fatalf("0 ALGO validation transaction failed under restrictive policy: %v\noutput:\n%s", err, validateOutput)
	}
	if !strings.Contains(validateOutput, "Validated successfully") {
		t.Fatalf("validation output missing success marker:\n%s", validateOutput)
	}

	_, err = apshell.SendTransaction(fundingAddr, fundingAddr, 0.1)
	if err == nil {
		t.Fatal("0.1 ALGO self-send succeeded under restrictive policy, want policy rejection")
	}
	errText := err.Error()
	if !strings.Contains(errText, "policy engine rejected request") ||
		!strings.Contains(errText, "max_algo_payment_exceeded") {
		t.Fatalf("0.1 ALGO self-send failed for unexpected reason:\n%s", errText)
	}

	stopSigner(t, signerd)
	writeAndSignIntegrationPolicy(t, apstore, env.SignerDataDir, passphrase, permissiveIntegrationPolicy())
	startSignerAndLoadKey(t, signerd, apadmin, token, fundingAddr)

	txid, err := apshell.SendTransaction(fundingAddr, fundingAddr, 0.1)
	if err != nil {
		t.Fatalf("0.1 ALGO self-send failed after removing policy rule: %v", err)
	}
	if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
		t.Fatalf("0.1 ALGO self-send %s failed to confirm: %v", txid, err)
	}
}

func restrictiveAlgoPaymentPolicy(network string) string {
	// Zero means "unset" in policy threshold maps, so use 1 microAlgo to keep
	// the 0-ALGO validation path open while rejecting practical payments.
	return fmt.Sprintf(`reject_foreign_rekey: false
reject_close_remainder: false
reject_asset_close: false
reject_clawback: false
max_algo_payments:
  %s: 1
`, network)
}

func permissiveIntegrationPolicy() string {
	return `reject_foreign_rekey: false
reject_close_remainder: false
reject_asset_close: false
reject_clawback: false
`
}

func writeAndSignIntegrationPolicy(t *testing.T, apstore *harness.ApStoreHarness, signerDataDir, passphrase, policyYAML string) {
	t.Helper()

	path := policy.PolicyPath(signerDataDir, "default")
	if err := os.WriteFile(path, []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("failed to write policy file %s: %v", path, err)
	}

	output, err := apstore.RunWithInput(passphrase+"\n", "policy", "sign")
	if err != nil {
		t.Fatalf("apstore policy sign failed: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "policy.yaml sidecar signed") {
		t.Fatalf("apstore policy sign output missing success markers:\n%s", output)
	}

	output, err = apstore.RunWithInput(passphrase+"\n", "policy", "verify")
	if err != nil {
		t.Fatalf("apstore policy verify failed: %v\noutput:\n%s", err, output)
	}
	if !strings.Contains(output, "policy.yaml integrity verified") {
		t.Fatalf("apstore policy verify output missing success markers:\n%s", output)
	}
}

func stopSigner(t *testing.T, signerd *harness.SignerHarness) {
	t.Helper()
	if err := signerd.Stop(); err != nil {
		t.Fatalf("failed to stop signer: %v", err)
	}
}

func startSignerAndLoadKey(t *testing.T, signerd *harness.SignerHarness, apadmin *harness.ApAdminHarness, token, address string) {
	t.Helper()
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to restart signer: %v", err)
	}
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("failed to unlock restarted signer: %v", err)
	}
	requirePolicyTestKeyLoaded(t, signerd, token, address)
}

func requirePolicyTestKeyLoaded(t *testing.T, signerd *harness.SignerHarness, token, address string) {
	t.Helper()
	if !waitForKey(t, signerd.GetURL(), token, address, 10*time.Second) {
		t.Fatalf("signer did not load policy test key %s", address)
	}
}
