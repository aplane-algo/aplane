// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package soak_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

const commandCoverageFundMicroAlgos = 4_000_000

var algorandAddressRE = regexp.MustCompile(`\b[A-Z2-7]{58}\b`)

func TestLocalNetApshellCommandCoverage(t *testing.T) {
	if os.Getenv(commandCoverageOptInEnv) != "1" {
		t.Skipf("set %s=1 to run the LocalNet command coverage test", commandCoverageOptInEnv)
	}
	if got := harness.IntegrationNetwork(); got != harness.IntegrationNetworkLocalnet {
		t.Fatalf("%s must be %q for soak tests, got %q", harness.IntegrationNetworkEnv, harness.IntegrationNetworkLocalnet, got)
	}

	network, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("connect to localnet algod: %v", err)
	}
	if network.Network != harness.IntegrationNetworkLocalnet {
		t.Fatalf("network = %q, want %q", network.Network, harness.IntegrationNetworkLocalnet)
	}

	funder, err := harness.NewFundTestAccount(network.Client)
	if err != nil {
		t.Fatalf("create localnet funding account: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("start signer: %v", err)
	}
	t.Cleanup(func() {
		if err := signerd.Stop(); err != nil {
			t.Logf("stop signer: %v", err)
		}
	})

	token := readSignerToken(t, signerd.GetTokenPath())
	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	t.Cleanup(apadmin.Cleanup)

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("copy signer token to apshell fixture: %v", err)
	}

	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("start background unlock: %v", err)
	}
	t.Cleanup(apadmin.StopUnlockBackground)

	primary := generateFundedCommandCoverageKey(t, network, funder, apshell, signerd.GetURL(), token, "primary")
	auth := generateFundedCommandCoverageKey(t, network, funder, apshell, signerd.GetURL(), token, "auth")

	app := deployCommandCoverageApp(t, network, funder)
	assetID := createCommandCoverageAsset(t, network, funder)
	defer destroyCommandCoverageAsset(t, network, funder, assetID)

	unsignedTxnFile := writeUnsignedPaymentTxnFile(t, network, primary, integrationBurnAddress, 1_000)
	scriptFile := writeCoverageScript(t)
	aliasName := fmt.Sprintf("soak_%d", time.Now().UnixNano())
	setName := aliasName + "_set"
	jsName := aliasName + ".js"

	runCoverageSession(t, apshell, "read-only/config/cache commands", []string{
		"connect",
		"network localnet",
		"status",
		"config",
		"help send",
		"keys",
		"keytypes",
		"accounts",
		fmt.Sprintf("alias %s %s", aliasName, primary),
		"alias list",
		fmt.Sprintf("alias %s", aliasName),
		fmt.Sprintf("sets %s %s %s", setName, primary, auth),
		"sets list",
		fmt.Sprintf("sets %s", setName),
		fmt.Sprintf("balance %s algo", aliasName),
		"holders algo",
		fmt.Sprintf("participation %s", aliasName),
		"write on",
		"write",
		"verbose on",
		"verbose",
		"simulate",
		fmt.Sprintf("simulate send 0.001 algo from %s to %s", aliasName, aliasName),
		fmt.Sprintf("simulate keyreg %s offline", aliasName),
		fmt.Sprintf("simulate sign %s", unsignedTxnFile),
		fmt.Sprintf("script %s", scriptFile),
		`js 21 + 21`,
		fmt.Sprintf("jssave -f %s -last", jsName),
		"jslist",
		fmt.Sprintf("js %s", jsName),
		"clear",
	}, "Switched to localnet", "Providers:", "Added alias:", "Created set", "Simulate mode:", "Saved to", jsName)

	runCoverageSession(t, apshell, "app and ASA read/cache commands", []string{
		fmt.Sprintf("app read info %d", app.AppID),
		fmt.Sprintf("app read global %d", app.AppID),
		fmt.Sprintf("app read boxes %d", app.AppID),
		fmt.Sprintf("info %d", assetID),
		"asa list",
		fmt.Sprintf("asa add %d", assetID),
		"asa list",
		fmt.Sprintf("asa remove %d", assetID),
		"asa clear",
	}, `"app_id":`, fmt.Sprintf("ASA ID: %d", assetID), "added to localnet cache", "removed from localnet cache")

	runCoverageSession(t, apshell, "ASA opt-in", []string{
		fmt.Sprintf("optin %d for %s", assetID, primary),
	}, "Opt-in submitted:", "Opt-in confirmed")

	transferCommandCoverageAsset(t, network, funder, assetID, primary, 1)

	runCoverageSession(t, apshell, "transaction commands", []string{
		fmt.Sprintf("validate %s", aliasName),
		fmt.Sprintf("keyreg %s offline", aliasName),
		fmt.Sprintf("rekey %s to %s", aliasName, auth),
		"rekey list",
		fmt.Sprintf("rekey refresh %s", aliasName),
		fmt.Sprintf("unrekey %s", aliasName),
		fmt.Sprintf("send 0.001 algo from %s to %s note=coverage", aliasName, auth),
		fmt.Sprintf("sweep algo from [%s] to %s leaving 1", primary, funder.GetAddress()),
		fmt.Sprintf("optout %d from %s to %s", assetID, primary, funder.GetAddress()),
	}, "Validated successfully", "Key registration submitted:", "Rekey transaction submitted:", "Unrekey transaction submitted:", "Sweep complete:", "Opt-out submitted:")

	runCoverageSession(t, apshell, "cleanup commands", []string{
		fmt.Sprintf("sets remove %s from %s", auth, setName),
		fmt.Sprintf("sets delete %s", setName),
		fmt.Sprintf("alias delete %s", aliasName),
		fmt.Sprintf("close %s to %s", primary, funder.GetAddress()),
		fmt.Sprintf("close %s to %s", auth, funder.GetAddress()),
		fmt.Sprintf("delete %s", primary),
		"y",
		fmt.Sprintf("delete %s", auth),
		"y",
	}, "Deleted set", "Removed alias:", "Close transaction submitted:", "Key deleted.")

	waitForSignerKeyMissing(t, signerd.GetURL(), token, primary, 15*time.Second)
	waitForSignerKeyMissing(t, signerd.GetURL(), token, auth, 15*time.Second)

	t.Logf("completed localnet apshell command coverage: primary=%s auth=%s asset=%d app=%d",
		primary, auth, assetID, app.AppID)
}

func generateFundedCommandCoverageKey(
	t *testing.T,
	network *harness.TestnetConfig,
	funder *harness.FundTestAccount,
	apshell *harness.ApshellHarness,
	signerURL string,
	token string,
	label string,
) string {
	t.Helper()

	output := runCoverageSession(t, apshell, "generate "+label+" command coverage key", []string{
		"generate ed25519",
	}, "Generated ed25519 key:")
	address := firstAlgorandAddress(output)
	if address == "" {
		t.Fatalf("could not find generated %s command coverage address in output:\n%s", label, output)
	}
	waitForSignerKey(t, signerURL, token, address, 15*time.Second)
	if err := funder.FundMicroAlgosAndWait(address, commandCoverageFundMicroAlgos); err != nil {
		t.Fatalf("fund %s command coverage key %s: %v", label, address, err)
	}
	if _, err := network.GetAccountInfo(address); err != nil {
		t.Fatalf("read funded %s command coverage key %s: %v", label, address, err)
	}
	return address
}

func deployCommandCoverageApp(t *testing.T, network *harness.TestnetConfig, funder *harness.FundTestAccount) *harness.TestApp {
	t.Helper()

	app, err := harness.DeployTestApp(t, network.Client, funder)
	if err != nil {
		t.Fatalf("deploy command coverage app: %v", err)
	}
	t.Cleanup(func() {
		if err := app.DestroyTestApp(funder); err != nil {
			t.Logf("destroy command coverage app %d: %v", app.AppID, err)
		}
	})
	return app
}

func createCommandCoverageAsset(t *testing.T, network *harness.TestnetConfig, funder *harness.FundTestAccount) uint64 {
	t.Helper()

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get suggested params for command coverage ASA: %v", err)
	}

	creator := funder.GetAddress()
	txn, err := transaction.MakeAssetCreateTxn(
		creator,
		[]byte("aplane command coverage"),
		sp,
		100,
		0,
		false,
		creator,
		creator,
		creator,
		creator,
		"APCOV",
		"APlane Command Coverage",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("create command coverage ASA transaction: %v", err)
	}

	txid := signAndSubmitCommandCoverageTxn(t, network, funder, txn)
	confirmed, err := transaction.WaitForConfirmation(network.Client, txid, 10, context.Background())
	if err != nil {
		t.Fatalf("wait for command coverage ASA create %s: %v", txid, err)
	}
	if confirmed.AssetIndex == 0 {
		t.Fatalf("command coverage ASA create %s confirmed without asset index", txid)
	}
	return confirmed.AssetIndex
}

func destroyCommandCoverageAsset(t *testing.T, network *harness.TestnetConfig, funder *harness.FundTestAccount, assetID uint64) {
	t.Helper()
	if assetID == 0 {
		return
	}

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Logf("get suggested params for command coverage ASA destroy: %v", err)
		return
	}
	txn, err := transaction.MakeAssetDestroyTxn(funder.GetAddress(), []byte("aplane command coverage cleanup"), sp, assetID)
	if err != nil {
		t.Logf("create command coverage ASA destroy transaction: %v", err)
		return
	}
	txid := signAndSubmitCommandCoverageTxn(t, network, funder, txn)
	if _, err := network.WaitForConfirmation(txid, defaultConfirmMaxRounds); err != nil {
		t.Logf("wait for command coverage ASA destroy %s: %v", txid, err)
	}
}

func transferCommandCoverageAsset(
	t *testing.T,
	network *harness.TestnetConfig,
	funder *harness.FundTestAccount,
	assetID uint64,
	recipient string,
	amount uint64,
) {
	t.Helper()

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get suggested params for command coverage ASA transfer: %v", err)
	}
	txn, err := transaction.MakeAssetTransferTxn(
		funder.GetAddress(),
		recipient,
		amount,
		[]byte("aplane command coverage"),
		sp,
		"",
		assetID,
	)
	if err != nil {
		t.Fatalf("create command coverage ASA transfer transaction: %v", err)
	}
	txid := signAndSubmitCommandCoverageTxn(t, network, funder, txn)
	if _, err := network.WaitForConfirmation(txid, defaultConfirmMaxRounds); err != nil {
		t.Fatalf("wait for command coverage ASA transfer %s: %v", txid, err)
	}
}

func signAndSubmitCommandCoverageTxn(
	t *testing.T,
	network *harness.TestnetConfig,
	funder *harness.FundTestAccount,
	txn types.Transaction,
) string {
	t.Helper()

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get suggested params for command coverage transaction: %v", err)
	}
	txid, signedBytes, err := funder.PrepareAndSignTransaction(txn, sp.MinFee)
	if err != nil {
		t.Fatalf("sign command coverage transaction: %v", err)
	}
	if _, err := network.Client.SendRawTransaction(signedBytes).Do(context.Background()); err != nil {
		t.Fatalf("submit command coverage transaction: %v", err)
	}
	return txid
}

func writeUnsignedPaymentTxnFile(
	t *testing.T,
	network *harness.TestnetConfig,
	from string,
	to string,
	amountMicroAlgos uint64,
) string {
	t.Helper()

	sp, err := network.GetSuggestedParams()
	if err != nil {
		t.Fatalf("get suggested params for unsigned payment file: %v", err)
	}
	txn, err := transaction.MakePaymentTxn(from, to, amountMicroAlgos, []byte("aplane command coverage"), "", sp)
	if err != nil {
		t.Fatalf("create unsigned payment transaction file: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(msgpack.Encode(txn))
	path := filepath.Join(t.TempDir(), "unsigned-payment.txn")
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatalf("write unsigned payment transaction file: %v", err)
	}
	return path
}

func writeCoverageScript(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "coverage.apsh")
	body := strings.Join([]string{
		"# command coverage script",
		"status",
		"write off",
		"verbose off",
	}, "\n")
	if err := os.WriteFile(path, []byte(body+"\n"), 0o600); err != nil {
		t.Fatalf("write command coverage script: %v", err)
	}
	return path
}

func runCoverageSession(
	t *testing.T,
	apshell *harness.ApshellHarness,
	name string,
	commands []string,
	expected ...string,
) string {
	t.Helper()

	input := strings.Join(append(append([]string{}, commands...), "quit"), "\n") + "\n"
	output, err := apshell.RunWithInput(input)
	if err != nil {
		t.Fatalf("%s failed: %v\noutput:\n%s", name, err, output)
	}
	for _, want := range expected {
		if !strings.Contains(output, want) {
			t.Fatalf("%s output missing %q:\n%s", name, want, output)
		}
	}
	return output
}

func firstAlgorandAddress(output string) string {
	for _, candidate := range algorandAddressRE.FindAllString(output, -1) {
		if candidate != integrationBurnAddress {
			return candidate
		}
	}
	return ""
}
