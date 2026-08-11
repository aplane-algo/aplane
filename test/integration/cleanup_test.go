// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/abi"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

// TestCleanupLeakedApps deletes leaked test apps left behind by previous
// integration runs that failed to destroy their apps (e.g. due to outstanding
// boxes). Run with:
//
//	CLEANUP=1 go test -v -run TestCleanupLeakedApps -timeout 10m ./test/integration
//
// It identifies test apps by their schema (2 global uint, 2 global bytes,
// 2 local uint, 0 local bytes) and skips any app that doesn't match.
func TestCleanupLeakedApps(t *testing.T) {
	if os.Getenv("CLEANUP") == "" {
		t.Skip("skipping cleanup: set CLEANUP=1 to run")
	}

	mn := os.Getenv("TEST_FUNDING_MNEMONIC")
	if mn == "" {
		t.Fatal("TEST_FUNDING_MNEMONIC not set")
	}
	algodURL := os.Getenv("ALGOD_URL")
	if algodURL == "" {
		algodURL = "https://testnet-api.4160.nodely.dev"
	}
	client, err := algod.MakeClient(algodURL, os.Getenv("ALGOD_TOKEN"))
	if err != nil {
		t.Fatalf("failed to create algod client: %v", err)
	}
	funder, err := harness.NewFundTestAccount(client)
	if err != nil {
		t.Fatalf("invalid native Falcon funding mnemonic: %v", err)
	}
	addr := funder.GetAddress()

	sp, err := client.SuggestedParams().Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get network params: %v", err)
	}
	if sp.GenesisID != "testnet-v1.0" {
		t.Fatalf("cleanup refused: network is %q, only testnet-v1.0 is allowed", sp.GenesisID)
	}
	t.Logf("network: %s, account: %s", sp.GenesisID, addr)

	acct, err := client.AccountInformation(addr).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to get account info: %v", err)
	}

	// Compile the current approval.teal (which has delete_box) for updating
	// leaked apps before deletion.
	approvalBytes, clearBytes := compileCleanupPrograms(t, client)

	var cleaned, skipped, failed int
	for _, app := range acct.CreatedApps {
		gs := app.Params.GlobalStateSchema
		ls := app.Params.LocalStateSchema
		if gs.NumUint != 2 || gs.NumByteSlice != 2 || ls.NumUint != 2 || ls.NumByteSlice != 0 {
			skipped++
			continue
		}

		t.Logf("cleaning app %d...", app.Id)
		if err := cleanupLeakedApp(client, app.Id, funder, approvalBytes, clearBytes); err != nil {
			t.Logf("  FAILED: %v", err)
			failed++
		} else {
			t.Logf("  deleted app %d", app.Id)
			cleaned++
		}
	}

	t.Logf("cleanup complete: %d deleted, %d skipped (non-test), %d failed", cleaned, skipped, failed)
	if failed > 0 {
		t.Fatalf("%d app(s) failed to clean up", failed)
	}
}

func compileCleanupPrograms(t *testing.T, client *algod.Client) (approval, clear []byte) {
	t.Helper()

	// Find project root by walking up from the test file
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find project root (go.mod)")
		}
		dir = parent
	}

	approvalSrc, err := os.ReadFile(filepath.Join(dir, "test", "fixtures", "testapp", "approval.teal"))
	if err != nil {
		t.Fatalf("failed to read approval.teal: %v", err)
	}
	clearSrc, err := os.ReadFile(filepath.Join(dir, "test", "fixtures", "testapp", "clear.teal"))
	if err != nil {
		t.Fatalf("failed to read clear.teal: %v", err)
	}

	ctx := context.Background()
	approvalResult, err := client.TealCompile(approvalSrc).Do(ctx)
	if err != nil {
		t.Fatalf("failed to compile approval.teal: %v", err)
	}
	approval, err = base64.StdEncoding.DecodeString(approvalResult.Result)
	if err != nil {
		t.Fatalf("failed to decode compiled approval: %v", err)
	}

	clearResult, err := client.TealCompile(clearSrc).Do(ctx)
	if err != nil {
		t.Fatalf("failed to compile clear.teal: %v", err)
	}
	clear, err = base64.StdEncoding.DecodeString(clearResult.Result)
	if err != nil {
		t.Fatalf("failed to decode compiled clear: %v", err)
	}
	return approval, clear
}

func cleanupLeakedApp(client *algod.Client, appID uint64, funder *harness.FundTestAccount, approvalBytes, clearBytes []byte) error {
	sender, err := types.DecodeAddress(funder.GetAddress())
	if err != nil {
		return err
	}

	// Step 1: Update the app's program so it has delete_box support.
	if err := updateAppProgram(client, appID, sender, funder, approvalBytes, clearBytes); err != nil {
		return fmt.Errorf("update program: %w", err)
	}

	// Step 2: Delete all boxes.
	if err := deleteAppBoxes(client, appID, sender, funder); err != nil {
		return fmt.Errorf("delete boxes: %w", err)
	}

	// Step 3: Delete the app.
	if err := deleteApp(client, appID, sender, funder); err != nil {
		return fmt.Errorf("delete app: %w", err)
	}
	return nil
}

func updateAppProgram(client *algod.Client, appID uint64, sender types.Address, funder *harness.FundTestAccount, approval, clear []byte) error {
	ctx := context.Background()
	sp, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return err
	}
	txn, err := transaction.MakeApplicationCallTx(
		appID, nil, nil, nil, nil,
		types.UpdateApplicationOC,
		approval, clear,
		types.StateSchema{}, types.StateSchema{},
		sp, sender,
		nil, types.Digest{}, [32]byte{}, types.Address{},
	)
	if err != nil {
		return err
	}
	return signSubmitWait(client, funder, txn, sp.MinFee)
}

func deleteAppBoxes(client *algod.Client, appID uint64, sender types.Address, funder *harness.FundTestAccount) error {
	ctx := context.Background()
	resp, err := client.GetApplicationBoxes(appID).Do(ctx)
	if err != nil {
		return err
	}

	deleteBoxMethod, _ := abi.MethodFromSignature("delete_box(byte[])void")

	for _, box := range resp.Boxes {
		sp, err := client.SuggestedParams().Do(ctx)
		if err != nil {
			return err
		}

		nameBytes := box.Name
		abiName := make([]byte, 2+len(nameBytes))
		abiName[0] = byte(len(nameBytes) >> 8)
		abiName[1] = byte(len(nameBytes))
		copy(abiName[2:], nameBytes)

		txn, err := transaction.MakeApplicationCallTxWithBoxes(
			appID,
			[][]byte{deleteBoxMethod.GetSelector(), abiName},
			nil, nil, nil,
			[]types.AppBoxReference{{AppID: appID, Name: nameBytes}},
			types.NoOpOC,
			nil, nil,
			types.StateSchema{}, types.StateSchema{},
			0, 0, sp, sender,
			nil, types.Digest{}, [32]byte{}, types.Address{},
		)
		if err != nil {
			return fmt.Errorf("build delete_box for %q: %w", string(nameBytes), err)
		}
		if err := signSubmitWait(client, funder, txn, sp.MinFee); err != nil {
			return fmt.Errorf("delete_box %q: %w", string(nameBytes), err)
		}
	}
	return nil
}

func deleteApp(client *algod.Client, appID uint64, sender types.Address, funder *harness.FundTestAccount) error {
	ctx := context.Background()
	sp, err := client.SuggestedParams().Do(ctx)
	if err != nil {
		return err
	}

	appAddr := crypto.GetApplicationAddress(appID)

	txn, err := transaction.MakeApplicationCallTxWithBoxes(
		appID, nil,
		[]string{appAddr.String()},
		nil, nil,
		[]types.AppBoxReference{
			{AppID: appID, Name: []byte("config")},
			{AppID: appID, Name: []byte("settings")},
		},
		types.DeleteApplicationOC,
		nil, nil,
		types.StateSchema{}, types.StateSchema{},
		0, 0, sp, sender,
		nil, types.Digest{}, [32]byte{}, types.Address{},
	)
	if err != nil {
		return err
	}
	return signSubmitWait(client, funder, txn, sp.MinFee)
}

func signSubmitWait(client *algod.Client, funder *harness.FundTestAccount, txn types.Transaction, minFee uint64) error {
	ctx := context.Background()
	txid, stxnBytes, err := funder.PrepareAndSignTransaction(txn, minFee)
	if err != nil {
		return err
	}
	if _, err := client.SendRawTransaction(stxnBytes).Do(ctx); err != nil {
		return err
	}
	_, err = transaction.WaitForConfirmation(client, txid, 10, ctx)
	return err
}
