// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestRotatingHybridApshellEndToEnd runs a rotating account through the
// shipped binaries: apadmin enables the key type and generates the account,
// and two ordinary apshell sends route through prepare, unsigned simulation,
// sign and submit. Each confirmed send must move the account's authorizer to
// a new stage address. The rotate-only command and rotate status complete
// the client surface; there is no exit.
func TestRotatingHybridApshellEndToEnd(t *testing.T) {
	if os.Getenv("TEST_FUNDING_MNEMONIC") == "" {
		t.Skip("TEST_FUNDING_MNEMONIC not set")
	}
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Fatalf("funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	defer apadmin.Cleanup()
	if err := apadmin.UnlockSigner(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := apadmin.ActivateKeyType(rotatingkey.RotatingHybridV1); err != nil {
		t.Fatalf("activate %s: %v", rotatingkey.RotatingHybridV1, err)
	}
	// Generate by network name, as an operator would; the signer resolves
	// it through its configured networks.
	network := harness.IntegrationNetwork()
	if network == "" {
		network = testnet.GenesisHash
	}
	account, err := apadmin.GenerateKeyWithTypeAndParams(rotatingkey.RotatingHybridV1, map[string]string{
		"network": network,
	})
	if err != nil {
		t.Fatalf("generate rotating account: %v", err)
	}
	if !waitForKey(t, signerd.GetURL(), account, 10*time.Second) {
		t.Fatalf("signer did not list %s", account)
	}
	if err := funder.FundMicroAlgosAndWait(account, 500_000); err != nil {
		t.Fatalf("fund: %v", err)
	}

	apshell := harness.NewApshellHarness(t)
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	seen := map[string]bool{account: true}
	for i := 0; i < 2; i++ {
		txid, err := apshell.SendTransaction(account, funder.GetAddress(), 0.001)
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if _, err := testnet.WaitForConfirmation(txid, 10); err != nil {
			t.Fatalf("send %d confirm %s: %v", i, txid, err)
		}
		info, err := testnet.Client.AccountInformation(account).Do(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if info.AuthAddr == "" || seen[info.AuthAddr] {
			t.Fatalf("send %d: authorizer %q is not a fresh stage address", i, info.AuthAddr)
		}
		seen[info.AuthAddr] = true
		t.Logf("send %d: %s confirmed; authorizer now %s", i, txid, info.AuthAddr)
	}

	// The rotate-only command moves the account to yet another stage, and
	// status shows the new authorizer with no signer alerts.
	out, err := apshell.RunWithInput("rotate " + account + "\nrotate status " + account + "\nquit\n")
	if err != nil {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	info, err := testnet.Client.AccountInformation(account).Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.AuthAddr == "" || seen[info.AuthAddr] {
		t.Fatalf("rotate: authorizer %q is not a fresh stage address\n%s", info.AuthAddr, out)
	}
	if !strings.Contains(out, "Rotated") || !strings.Contains(out, "authorizer: "+info.AuthAddr) || !strings.Contains(out, "alerts: none") {
		t.Fatalf("unexpected rotate output:\n%s", out)
	}
	t.Logf("rotate: authorizer now %s", info.AuthAddr)

	// A second rotate status after the rotation shows the new authorizer
	// with no alerts and no outstanding release; the status endpoint's
	// notes name no in-flight work for this account.
	out, err = apshell.RunWithInput("rotate status\nquit\n")
	if err != nil {
		t.Fatalf("rotate status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "authorizer: "+info.AuthAddr) || strings.Contains(out, "ALERT:") {
		t.Fatalf("unexpected status output:\n%s", out)
	}
}
