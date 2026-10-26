// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestRotatingTripleTransactionTypes sends every single-transaction type
// apshell offers, other than payments, from a rotating account: asset opt-in,
// transfer and close-out, application calls with an opt-in and a box
// reference, and online and offline key registration. Each must confirm and
// move the account's authorizer to a fresh stage address.
func TestRotatingTripleTransactionTypes(t *testing.T) {
	runRotatingTransactionTypes(t, rotatingkey.RotatingTripleWotsV1)
}

func TestRotatingXmssTransactionTypes(t *testing.T) {
	runRotatingTransactionTypes(t, rotatingkey.RotatingTripleXmssV1)
}

func runRotatingTransactionTypes(t *testing.T, keyType string) {
	t.Helper()
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
	if err := apadmin.ActivateKeyType(keyType); err != nil {
		t.Fatalf("activate %s: %v", keyType, err)
	}
	account, err := apadmin.GenerateKeyWithTypeAndParams(keyType, map[string]string{
		"network": testnet.GenesisHash,
	})
	if err != nil {
		t.Fatalf("generate rotating account: %v", err)
	}
	if !waitForKey(t, signerd.GetURL(), account, 10*time.Second) {
		t.Fatalf("signer did not list %s", account)
	}
	// Covers the asset and app opt-in minimum balances, the box and fees.
	if err := funder.FundMicroAlgosAndWait(account, 1_000_000); err != nil {
		t.Fatalf("fund: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()
	apshell := harness.NewApshellHarness(t)

	seen := map[string]bool{account: true}
	// run sends one apshell command from the rotating account and checks
	// that it confirmed and rotated the account to an unseen stage.
	run := func(t *testing.T, command string) string {
		t.Helper()
		before := authorizer(t, testnet, account)
		out := runApshellScript(t, apshell, command)
		if !strings.Contains(out, "Confirmed in round") {
			t.Fatalf("%s: not confirmed:\n%s", command, out)
		}
		after := authorizer(t, testnet, account)
		if after == "" || after == before || seen[after] {
			t.Fatalf("%s: authorizer %q is not a fresh stage address (was %q)\n%s", command, after, before, out)
		}
		seen[after] = true
		return out
	}

	t.Run("Asset", func(t *testing.T) {
		assetID := createRotatingTestAsset(t, testnet, funder)
		run(t, fmt.Sprintf("optin %d for %s", assetID, account))
		sendFunderAsset(t, testnet, funder, account, assetID, 10)
		run(t, fmt.Sprintf("send 3 %d from %s to %s", assetID, account, funder.GetAddress()))
		if got := assetHolding(t, testnet, account, assetID); got != 7 {
			t.Fatalf("asset balance after send = %d, want 7", got)
		}
		// Opting out with a balance closes the holding to the funder; the
		// stage program allows this, unlike closing the account.
		run(t, fmt.Sprintf("optout %d from %s to %s", assetID, account, funder.GetAddress()))
		if got := assetHolding(t, testnet, account, assetID); got != -1 {
			t.Fatalf("account still holds asset %d after opt-out (amount %d)", assetID, got)
		}
		destroyRotatingTestAsset(t, testnet, funder, assetID)
	})

	t.Run("App", func(t *testing.T) {
		app, err := harness.DeployTestApp(t, testnet.Client, funder)
		if err != nil {
			t.Fatalf("deploy: %v", err)
		}
		defer func() {
			if err := app.DestroyTestApp(funder); err != nil {
				t.Logf("warning: destroy test app: %v", err)
			}
		}()
		if err := app.FundApp(funder, 200_000); err != nil {
			t.Fatalf("fund app: %v", err)
		}

		run(t, fmt.Sprintf("app call raw %d from %s arg-raw=hex:%s oncomp=optin",
			app.AppID, account, hex.EncodeToString(harness.OptInSelector())))
		local, err := app.ReadLocalState(account)
		if err != nil {
			t.Fatalf("read local state: %v", err)
		}
		if _, ok := local["balance"].(uint64); !ok {
			t.Fatalf("local state after opt-in = %v", local)
		}

		run(t, fmt.Sprintf("app call raw %d from %s arg-raw=hex:%s arg-raw=hex:%s",
			app.AppID, account, hex.EncodeToString(harness.IncrementSelector()),
			hex.EncodeToString(harness.EncodeUint64(5))))
		global, err := app.ReadGlobalState()
		if err != nil {
			t.Fatalf("read global state: %v", err)
		}
		if counter, _ := global["counter"].(uint64); counter != 5 {
			t.Fatalf("counter = %v, want 5", global["counter"])
		}

		// A box reference adds a resource to the group the signer forms
		// around the spend.
		boxName, boxValue := "rotating", "rotating-box-value"
		run(t, fmt.Sprintf("app call raw %d from %s arg-raw=hex:%s arg-raw=hex:%s arg-raw=hex:%s box=%s",
			app.AppID, account, hex.EncodeToString(harness.SetBoxSelector()),
			hex.EncodeToString(harness.EncodeBytes([]byte(boxName))),
			hex.EncodeToString(harness.EncodeBytes([]byte(boxValue))), boxName))
		box, err := testnet.Client.GetApplicationBoxByName(app.AppID, []byte(boxName)).Do(context.Background())
		if err != nil {
			t.Fatalf("read box: %v", err)
		}
		if string(box.Value) != boxValue {
			t.Fatalf("box value = %q, want %q", box.Value, boxValue)
		}
	})

	t.Run("AppRejectsRekey", func(t *testing.T) {
		// Every rotating spend carries a rekey to the next stage, including
		// app calls. A contract hardened to refuse rekeying calls therefore
		// refuses every call from a rotating account. The client simulates
		// the prepared group before signing, so the refusal costs nothing:
		// no stage signs and the authorizer does not move.
		app, err := harness.DeployTEALApp(t, testnet.Client, funder,
			[]byte(rekeyRejectingApproval), []byte(rekeyRejectingClear), types.StateSchema{}, types.StateSchema{})
		if err != nil {
			t.Fatalf("deploy: %v", err)
		}
		defer func() {
			if err := app.DestroyTestApp(funder); err != nil {
				t.Logf("warning: destroy rekey-rejecting app: %v", err)
			}
		}()

		// Control: the same call from an ordinary account, which rekeys
		// nothing, is approved.
		if err := app.CallMethod(nil, funder, nil); err != nil {
			t.Fatalf("control call from the funder: %v", err)
		}

		before := authorizer(t, testnet, account)
		scriptPath := filepath.Join(t.TempDir(), "rekey_rejecting.ap")
		command := fmt.Sprintf("app call raw %d from %s", app.AppID, account)
		if err := os.WriteFile(scriptPath, []byte(command+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := apshell.Run("-script", scriptPath)
		if err == nil {
			t.Fatalf("%s: unexpectedly succeeded against a rekey-rejecting contract:\n%s", command, out)
		}
		if !strings.Contains(out, "failed simulation") || !strings.Contains(out, "nothing was signed") {
			t.Fatalf("%s: want a pre-signing simulation refusal, got:\n%s", command, out)
		}
		if after := authorizer(t, testnet, account); after != before {
			t.Fatalf("%s: authorizer moved from %q to %q although nothing should have been signed", command, before, after)
		}
	})

	t.Run("KeyReg", func(t *testing.T) {
		// Random participation keys: the account goes online without a
		// participation node, which is harmless for a test account.
		first := mustSuggestedParams(t, testnet).FirstRoundValid
		run(t, fmt.Sprintf("keyreg %s online votekey=%s selkey=%s sproofkey=%s votefirst=%d votelast=%d keydilution=10000",
			account, randomBase64(t, 32), randomBase64(t, 32), randomBase64(t, 64), first, first+100_000))
		if status := accountStatus(t, testnet, account); status != "Online" {
			t.Fatalf("status after online keyreg = %q", status)
		}
		run(t, fmt.Sprintf("keyreg %s offline", account))
		if status := accountStatus(t, testnet, account); status != "Offline" {
			t.Fatalf("status after offline keyreg = %q", status)
		}
	})
}

func authorizer(t *testing.T, testnet *harness.TestnetConfig, account string) string {
	t.Helper()
	info, err := testnet.Client.AccountInformation(account).Do(context.Background())
	if err != nil {
		t.Fatalf("read %s: %v", account, err)
	}
	return info.AuthAddr
}

func accountStatus(t *testing.T, testnet *harness.TestnetConfig, account string) string {
	t.Helper()
	info, err := testnet.Client.AccountInformation(account).Do(context.Background())
	if err != nil {
		t.Fatalf("read %s: %v", account, err)
	}
	return info.Status
}

// assetHolding returns account's balance of assetID, or -1 when the account
// does not hold it.
func assetHolding(t *testing.T, testnet *harness.TestnetConfig, account string, assetID uint64) int64 {
	t.Helper()
	info, err := testnet.Client.AccountInformation(account).Do(context.Background())
	if err != nil {
		t.Fatalf("read %s: %v", account, err)
	}
	for _, holding := range info.Assets {
		if holding.AssetId == assetID {
			return int64(holding.Amount)
		}
	}
	return -1
}

func randomBase64(t *testing.T, size int) string {
	t.Helper()
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// createRotatingTestAsset creates a small asset held by the funder; the test
// destroys it once every unit is back.
func createRotatingTestAsset(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount) uint64 {
	t.Helper()
	funderAddr := funder.GetAddress()
	txn, err := transaction.MakeAssetCreateTxn(funderAddr, nil, mustSuggestedParams(t, testnet),
		1_000, 0, false, funderAddr, "", "", "", "RTEST", "rotating-txntypes", "", "")
	if err != nil {
		t.Fatalf("build asset create: %v", err)
	}
	txid := submitFundingTxnExpectSuccess(t, testnet, funder, txn)
	info, _, err := testnet.Client.PendingTransactionInformation(txid).Do(context.Background())
	if err != nil {
		t.Fatalf("read asset create %s: %v", txid, err)
	}
	if info.AssetIndex == 0 {
		t.Fatalf("asset create %s returned no asset index", txid)
	}
	return info.AssetIndex
}

func sendFunderAsset(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount, to string, assetID, amount uint64) {
	t.Helper()
	txn, err := transaction.MakeAssetTransferTxn(funder.GetAddress(), to, amount, nil, mustSuggestedParams(t, testnet), "", assetID)
	if err != nil {
		t.Fatalf("build asset transfer: %v", err)
	}
	submitFundingTxnExpectSuccess(t, testnet, funder, txn)
}

func destroyRotatingTestAsset(t *testing.T, testnet *harness.TestnetConfig, funder *harness.FundTestAccount, assetID uint64) {
	t.Helper()
	txn, err := transaction.MakeAssetDestroyTxn(funder.GetAddress(), nil, mustSuggestedParams(t, testnet), assetID)
	if err != nil {
		t.Fatalf("build asset destroy: %v", err)
	}
	submitFundingTxnExpectSuccess(t, testnet, funder, txn)
}

// rekeyRejectingApproval is the hardening pattern many audited contracts
// use: refuse any call whose transaction rekeys the sender. Creation and
// deletion by the creator are allowed so the fixture can be cleaned up.
const rekeyRejectingApproval = `#pragma version 10
txn ApplicationID
bz approve
txn OnCompletion
int DeleteApplication
==
bnz delete
txn RekeyTo
global ZeroAddress
==
assert
approve:
int 1
return
delete:
txn Sender
global CreatorAddress
==
return
`

const rekeyRejectingClear = `#pragma version 10
int 1
return
`

func TestRotatingSlhdsaTransactionTypes(t *testing.T) {
	runRotatingTransactionTypes(t, rotatingkey.RotatingTripleSlhdsaV1)
}
