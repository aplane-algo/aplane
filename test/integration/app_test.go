// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/engine"
	util "github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/test/integration/harness"
)

func requireOutputContainsAll(t *testing.T, output string, expected ...string) {
	t.Helper()
	for _, want := range expected {
		if !strings.Contains(output, want) {
			t.Fatalf("unexpected output, missing %q:\n%s", want, output)
		}
	}
}

func signableAddressText(address string) string {
	return address + " @"
}

// TestAppDeployAndExercise is a smoke test that validates the entire test app
// harness: deploy, call methods, read state, exercise boxes and grouped
// transactions, then clean up. This proves the TEAL contract and Go harness
// work end-to-end on testnet before building Phase 1 features on top of them.
func TestAppDeployAndExercise(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// --- Setup ---
	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	// --- Deploy ---
	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	t.Logf("app deployed: ID=%d address=%s", app.AppID, app.AppAddress)

	// --- Test increment (global state mutation) ---
	t.Run("Increment", func(t *testing.T) {
		err := app.CallMethod(
			[][]byte{harness.IncrementSelector(), harness.EncodeUint64(5)},
			creatorAddr, creatorSK, nil,
		)
		if err != nil {
			t.Fatalf("increment(5) failed: %v", err)
		}

		state, err := app.ReadGlobalState()
		if err != nil {
			t.Fatalf("read global state failed: %v", err)
		}

		counter, ok := state["counter"].(uint64)
		if !ok {
			t.Fatalf("counter not found or wrong type: %v", state["counter"])
		}
		if counter != 5 {
			t.Fatalf("expected counter=5, got %d", counter)
		}

		admin, ok := state["admin"].([]byte)
		if !ok {
			t.Fatalf("admin not found or wrong type: %v", state["admin"])
		}
		t.Logf("global state: counter=%d admin=%x", counter, admin)
	})

	// --- Test increment again (additive) ---
	t.Run("IncrementAdditive", func(t *testing.T) {
		err := app.CallMethod(
			[][]byte{harness.IncrementSelector(), harness.EncodeUint64(7)},
			creatorAddr, creatorSK, nil,
		)
		if err != nil {
			t.Fatalf("increment(7) failed: %v", err)
		}

		state, err := app.ReadGlobalState()
		if err != nil {
			t.Fatalf("read global state failed: %v", err)
		}

		counter := state["counter"].(uint64)
		if counter != 12 {
			t.Fatalf("expected counter=12 (5+7), got %d", counter)
		}
		t.Logf("counter after second increment: %d", counter)
	})

	// --- Test opt-in (local state) ---
	t.Run("OptIn", func(t *testing.T) {
		err := app.OptIn(creatorAddr, creatorSK)
		if err != nil {
			t.Fatalf("opt-in failed: %v", err)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}

		balance, ok := localState["balance"].(uint64)
		if !ok {
			t.Fatalf("balance not found or wrong type: %v", localState["balance"])
		}
		if balance != 0 {
			t.Fatalf("expected balance=0 after opt-in, got %d", balance)
		}
		t.Logf("local state after opt-in: balance=%d", balance)
	})

	// --- Test set_box (box storage) ---
	t.Run("SetBox", func(t *testing.T) {
		// Fund app for box MBR: 2500 + 400*(6+10) = 8900 microAlgos
		// Fund generously to avoid flaky failures
		err := app.FundApp(funder, 200_000)
		if err != nil {
			t.Fatalf("fund app failed: %v", err)
		}

		boxName := []byte("config")
		boxValue := []byte("test-value")
		err = app.CallMethod(
			[][]byte{harness.SetBoxSelector(), harness.EncodeBytes(boxName), harness.EncodeBytes(boxValue)},
			creatorAddr, creatorSK,
			[]types.AppBoxReference{{AppID: app.AppID, Name: boxName}},
		)
		if err != nil {
			t.Fatalf("set_box failed: %v", err)
		}
		t.Log("box 'config' set successfully")
	})

	// --- Test grouped deposit (payment + app call) ---
	t.Run("GroupedDeposit", func(t *testing.T) {
		depositAmount := uint64(100_000) // 0.1 ALGO
		err := app.SubmitGroupedPaymentAndAppCall(
			creatorAddr, creatorSK,
			depositAmount,
			[][]byte{harness.DepositSelector()},
		)
		if err != nil {
			t.Fatalf("grouped deposit failed: %v", err)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state after deposit failed: %v", err)
		}

		balance, ok := localState["balance"].(uint64)
		if !ok {
			t.Fatalf("balance not found after deposit: %v", localState["balance"])
		}
		if balance != depositAmount {
			t.Fatalf("expected balance=%d, got %d", depositAmount, balance)
		}
		t.Logf("local balance after deposit: %d microAlgos", balance)
	})
}

func TestAppReadCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	if err := app.CallMethod(
		[][]byte{harness.IncrementSelector(), harness.EncodeUint64(9)},
		creatorAddr, creatorSK, nil,
	); err != nil {
		t.Fatalf("increment setup failed: %v", err)
	}

	if err := app.OptIn(creatorAddr, creatorSK); err != nil {
		t.Fatalf("opt-in setup failed: %v", err)
	}
	if err := app.FundApp(funder, 200_000); err != nil {
		t.Fatalf("app funding failed: %v", err)
	}

	boxName := []byte("config")
	boxValue := []byte("test-value")
	if err := app.CallMethod(
		[][]byte{harness.SetBoxSelector(), harness.EncodeBytes(boxName), harness.EncodeBytes(boxValue)},
		creatorAddr, creatorSK,
		[]types.AppBoxReference{{AppID: app.AppID, Name: boxName}},
	); err != nil {
		t.Fatalf("set_box setup failed: %v", err)
	}

	apshell := harness.NewApshellHarness(t, "")

	t.Run("Info", func(t *testing.T) {
		var result struct {
			AppID               uint64 `json:"app_id"`
			AppAddress          string `json:"app_address"`
			Creator             string `json:"creator"`
			ApprovalProgramSize int    `json:"approval_program_size"`
			ClearProgramSize    int    `json:"clear_state_program_size"`
			ApprovalProgramB64  string `json:"approval_program_base64"`
			ClearProgramB64     string `json:"clear_state_program_base64"`
			ApprovalProgramHash string `json:"approval_program_hash"`
			ClearProgramHash    string `json:"clear_state_program_hash"`
			GlobalStateSchema   struct {
				NumUint uint64 `json:"num_uint"`
			} `json:"global_state_schema"`
			LocalStateSchema struct {
				NumUint uint64 `json:"num_uint"`
			} `json:"local_state_schema"`
		}

		readAppJSON(t, apshell, fmt.Sprintf("app read info %d", app.AppID), &result)

		if result.AppID != app.AppID {
			t.Fatalf("app_id = %d, want %d", result.AppID, app.AppID)
		}
		if result.AppAddress != app.AppAddress {
			t.Fatalf("app_address = %s, want %s", result.AppAddress, app.AppAddress)
		}
		if result.Creator != creatorAddr {
			t.Fatalf("creator = %s, want %s", result.Creator, creatorAddr)
		}
		if result.ApprovalProgramSize <= 0 || result.ClearProgramSize <= 0 {
			t.Fatalf("unexpected program sizes: approval=%d clear=%d", result.ApprovalProgramSize, result.ClearProgramSize)
		}
		if result.ApprovalProgramB64 == "" || result.ClearProgramB64 == "" {
			t.Fatal("expected approval and clear programs to be populated")
		}
		if result.ApprovalProgramHash == "" || result.ClearProgramHash == "" {
			t.Fatal("expected program hashes to be populated")
		}
		if result.GlobalStateSchema.NumUint == 0 || result.LocalStateSchema.NumUint == 0 {
			t.Fatalf("unexpected schemas: global=%+v local=%+v", result.GlobalStateSchema, result.LocalStateSchema)
		}
	})

	t.Run("Global", func(t *testing.T) {
		var result struct {
			AppID       uint64 `json:"app_id"`
			Creator     string `json:"creator"`
			GlobalState []struct {
				KeyText string `json:"key_text"`
				Value   struct {
					Type string `json:"type"`
					Uint uint64 `json:"uint"`
				} `json:"value"`
			} `json:"global_state"`
		}

		readAppJSON(t, apshell, fmt.Sprintf("app read global %d", app.AppID), &result)

		if result.AppID != app.AppID {
			t.Fatalf("app_id = %d, want %d", result.AppID, app.AppID)
		}
		if result.Creator != creatorAddr {
			t.Fatalf("creator = %s, want %s", result.Creator, creatorAddr)
		}

		counter := uint64(0)
		foundCounter := false
		for _, entry := range result.GlobalState {
			if entry.KeyText == "counter" {
				foundCounter = true
				counter = entry.Value.Uint
			}
		}
		if !foundCounter {
			t.Fatal("counter key missing from global state")
		}
		if counter != 9 {
			t.Fatalf("counter = %d, want 9", counter)
		}
	})

	t.Run("Local", func(t *testing.T) {
		var result struct {
			AppID      uint64 `json:"app_id"`
			Account    string `json:"account"`
			LocalState []struct {
				KeyText string `json:"key_text"`
				Value   struct {
					Type string `json:"type"`
					Uint uint64 `json:"uint"`
				} `json:"value"`
			} `json:"local_state"`
		}

		readAppJSON(t, apshell, fmt.Sprintf("app read local %d %s", app.AppID, creatorAddr), &result)

		if result.AppID != app.AppID {
			t.Fatalf("app_id = %d, want %d", result.AppID, app.AppID)
		}
		if result.Account != creatorAddr {
			t.Fatalf("account = %s, want %s", result.Account, creatorAddr)
		}

		foundBalance := false
		for _, entry := range result.LocalState {
			if entry.KeyText == "balance" {
				foundBalance = true
				if entry.Value.Uint != 0 {
					t.Fatalf("balance = %d, want 0", entry.Value.Uint)
				}
			}
		}
		if !foundBalance {
			t.Fatal("balance key missing from local state")
		}
	})

	t.Run("Box", func(t *testing.T) {
		var result struct {
			AppID       uint64 `json:"app_id"`
			NameText    string `json:"name_text"`
			ValueText   string `json:"value_text"`
			NameBase64  string `json:"name_base64"`
			ValueBase64 string `json:"value_base64"`
		}

		readAppJSON(t, apshell, fmt.Sprintf("app read box %d config", app.AppID), &result)

		if result.AppID != app.AppID {
			t.Fatalf("app_id = %d, want %d", result.AppID, app.AppID)
		}
		if result.NameText != "config" {
			t.Fatalf("name_text = %q, want %q", result.NameText, "config")
		}
		if result.ValueText != "test-value" {
			t.Fatalf("value_text = %q, want %q", result.ValueText, "test-value")
		}
		if result.NameBase64 == "" || result.ValueBase64 == "" {
			t.Fatal("expected base64 fields to be populated")
		}
	})

	t.Run("Boxes", func(t *testing.T) {
		var result struct {
			AppID uint64 `json:"app_id"`
			Boxes []struct {
				NameText string `json:"name_text"`
			} `json:"boxes"`
		}

		readAppJSON(t, apshell, fmt.Sprintf("app read boxes %d", app.AppID), &result)

		if result.AppID != app.AppID {
			t.Fatalf("app_id = %d, want %d", result.AppID, app.AppID)
		}
		foundConfig := false
		for _, box := range result.Boxes {
			if box.NameText == "config" {
				foundConfig = true
			}
		}
		if !foundConfig {
			t.Fatalf("expected box list to include %q, got %+v", "config", result.Boxes)
		}
	})
}

func TestAppDeployCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	approvalPath := appFixturePath(t, "approval.teal")
	clearPath := appFixturePath(t, "clear.teal")

	t.Run("Source", func(t *testing.T) {
		command := fmt.Sprintf(
			"app deploy from %s approval=%s clear=%s global-uint=2 global-bytes=2 local-uint=2 local-bytes=0",
			creatorAddr,
			approvalPath,
			clearPath,
		)

		output := runApshellScript(t, apshell, command)
		appID, appAddr := parseCreatedAppFromOutput(t, output)

		defer func() {
			if err := harness.DestroyApp(t, testnet.Client, appID, creatorAddr, creatorSK); err != nil {
				t.Logf("warning: failed to destroy source-deployed app %d: %v", appID, err)
			}
		}()

		var result struct {
			AppID      uint64 `json:"app_id"`
			AppAddress string `json:"app_address"`
			Creator    string `json:"creator"`
		}
		readAppJSON(t, apshell, fmt.Sprintf("app read info %d", appID), &result)

		if result.AppID != appID {
			t.Fatalf("app_id = %d, want %d", result.AppID, appID)
		}
		if result.AppAddress != appAddr {
			t.Fatalf("app_address = %s, want %s", result.AppAddress, appAddr)
		}
		if result.Creator != creatorAddr {
			t.Fatalf("creator = %s, want %s", result.Creator, creatorAddr)
		}
	})

	t.Run("Compiled", func(t *testing.T) {
		approvalBin, clearBin := compileFixturePrograms(t, testnet.Client, approvalPath, clearPath)
		command := fmt.Sprintf(
			"app deploy from %s approval-bin=%s clear-bin=%s global-uint=2 global-bytes=2 local-uint=2 local-bytes=0",
			creatorAddr,
			approvalBin,
			clearBin,
		)

		output := runApshellScript(t, apshell, command)
		appID, appAddr := parseCreatedAppFromOutput(t, output)

		defer func() {
			if err := harness.DestroyApp(t, testnet.Client, appID, creatorAddr, creatorSK); err != nil {
				t.Logf("warning: failed to destroy compiled-deployed app %d: %v", appID, err)
			}
		}()

		var result struct {
			AppID               uint64 `json:"app_id"`
			AppAddress          string `json:"app_address"`
			ApprovalProgramSize int    `json:"approval_program_size"`
			ClearProgramSize    int    `json:"clear_state_program_size"`
		}
		readAppJSON(t, apshell, fmt.Sprintf("app read info %d", appID), &result)

		if result.AppID != appID {
			t.Fatalf("app_id = %d, want %d", result.AppID, appID)
		}
		if result.AppAddress != appAddr {
			t.Fatalf("app_address = %s, want %s", result.AppAddress, appAddr)
		}
		if result.ApprovalProgramSize <= 0 || result.ClearProgramSize <= 0 {
			t.Fatalf("unexpected program sizes: approval=%d clear=%d", result.ApprovalProgramSize, result.ClearProgramSize)
		}
	})
}

func TestAppUpdateAndDeleteCommands(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}

	deleted := false
	defer func() {
		if deleted {
			return
		}
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	updatedApprovalPath := appFixturePath(t, "approval_updated.teal")
	clearPath := appFixturePath(t, "clear.teal")
	wantApproval := compileFixtureProgramBytes(t, testnet.Client, updatedApprovalPath)
	wantClear := compileFixtureProgramBytes(t, testnet.Client, clearPath)

	updateCommand := fmt.Sprintf(
		"app call raw %d from %s oncomp=update approval=%s clear=%s",
		app.AppID,
		creatorAddr,
		updatedApprovalPath,
		clearPath,
	)
	updateOutput := runApshellScript(t, apshell, updateCommand)
	requireOutputContainsAll(t, updateOutput,
		"✓ Confirmed in round ",
		fmt.Sprintf("Calling app %d from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
	)

	appInfo, err := testnet.Client.GetApplicationByID(app.AppID).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to read updated app info: %v", err)
	}
	if !bytes.Equal(appInfo.Params.ApprovalProgram, wantApproval) {
		t.Fatal("updated approval program does not match expected compiled bytes")
	}
	if !bytes.Equal(appInfo.Params.ClearStateProgram, wantClear) {
		t.Fatal("updated clear program does not match expected compiled bytes")
	}

	if err := app.CallMethod(
		[][]byte{harness.IncrementSelector(), harness.EncodeUint64(5)},
		creatorAddr, creatorSK, nil,
	); err != nil {
		t.Fatalf("increment after update failed: %v", err)
	}
	globalState, err := app.ReadGlobalState()
	if err != nil {
		t.Fatalf("read global state failed: %v", err)
	}
	if counter := globalState["counter"].(uint64); counter != 10 {
		t.Fatalf("counter after update = %d, want 10", counter)
	}

	deleteCommand := fmt.Sprintf(
		"app call raw %d from %s oncomp=delete account=%s box=config box=settings",
		app.AppID,
		creatorAddr,
		app.AppAddress,
	)
	deleteOutput := runApshellScript(t, apshell, deleteCommand)
	requireOutputContainsAll(t, deleteOutput,
		"✓ Confirmed in round ",
		fmt.Sprintf("Calling app %d from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
	)

	if _, err := testnet.Client.GetApplicationByID(app.AppID).Do(context.Background()); err == nil {
		t.Fatalf("app %d still exists after delete", app.AppID)
	}
	deleted = true
}

func TestAppCallRawCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	t.Run("Increment", func(t *testing.T) {
		command := fmt.Sprintf(
			"app call raw %d from %s arg-raw=hex:%s arg-raw=hex:%s",
			app.AppID,
			creatorAddr,
			hex.EncodeToString(harness.IncrementSelector()),
			hex.EncodeToString(harness.EncodeUint64(11)),
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
		)

		state, err := app.ReadGlobalState()
		if err != nil {
			t.Fatalf("read global state failed: %v", err)
		}

		counter, ok := state["counter"].(uint64)
		if !ok {
			t.Fatalf("counter missing or wrong type: %v", state["counter"])
		}
		if counter != 11 {
			t.Fatalf("counter = %d, want 11", counter)
		}
	})

	t.Run("SetBoxWithBoxRef", func(t *testing.T) {
		// Fund app for box MBR
		if err := app.FundApp(funder, 200_000); err != nil {
			t.Fatalf("app funding failed: %v", err)
		}

		boxName := "settings"
		boxValue := "raw-call-value"
		command := fmt.Sprintf(
			"app call raw %d from %s arg-raw=hex:%s arg-raw=hex:%s arg-raw=hex:%s box=%s",
			app.AppID,
			creatorAddr,
			hex.EncodeToString(harness.SetBoxSelector()),
			hex.EncodeToString(harness.EncodeBytes([]byte(boxName))),
			hex.EncodeToString(harness.EncodeBytes([]byte(boxValue))),
			boxName,
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
		)

		// Verify box via algod direct read
		box, err := testnet.Client.GetApplicationBoxByName(app.AppID, []byte(boxName)).Do(context.Background())
		if err != nil {
			t.Fatalf("read box failed: %v", err)
		}
		if string(box.Value) != boxValue {
			t.Fatalf("box value = %q, want %q", string(box.Value), boxValue)
		}
	})

	t.Run("OptInWithOnComp", func(t *testing.T) {
		// Use the creator account — not yet opted into this fresh app instance.
		command := fmt.Sprintf(
			"app call raw %d from %s arg-raw=hex:%s oncomp=optin",
			app.AppID,
			creatorAddr,
			hex.EncodeToString(harness.OptInSelector()),
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
		)

		// Verify local state exists via harness direct read
		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}
		balance, ok := localState["balance"].(uint64)
		if !ok {
			t.Fatalf("balance missing or wrong type: %v", localState["balance"])
		}
		if balance != 0 {
			t.Fatalf("balance = %d, want 0", balance)
		}
	})
}

func TestAppCallRawPayCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	if err := app.OptIn(creatorAddr, creatorSK); err != nil {
		t.Fatalf("opt-in setup failed: %v", err)
	}
	if err := app.FundApp(funder, 200_000); err != nil {
		t.Fatalf("app funding failed: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	depositAmount := uint64(100_000)

	t.Run("Simulate", func(t *testing.T) {
		command := fmt.Sprintf(
			"simulate app call raw %d from %s --pay %d arg-raw=hex:%s",
			app.AppID,
			creatorAddr,
			depositAmount,
			hex.EncodeToString(harness.DepositSelector()),
		)
		output := runApshellScript(t, apshell, command)
		if !strings.Contains(output, "Simulation successful") {
			t.Fatalf("unexpected simulate output:\n%s", output)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}
		if balance := localState["balance"].(uint64); balance != 0 {
			t.Fatalf("balance after simulate = %d, want 0", balance)
		}
	})

	t.Run("Execute", func(t *testing.T) {
		command := fmt.Sprintf(
			"app call raw %d from %s --pay %d arg-raw=hex:%s",
			app.AppID,
			creatorAddr,
			depositAmount,
			hex.EncodeToString(harness.DepositSelector()),
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d raw from %s with companion payment of %d microAlgos using Ed25519 key...", app.AppID, signableAddressText(creatorAddr), depositAmount),
		)

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}
		if balance := localState["balance"].(uint64); balance != depositAmount {
			t.Fatalf("balance after execute = %d, want %d", balance, depositAmount)
		}
	})
}

func TestAppCallMethodCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	t.Run("Increment", func(t *testing.T) {
		command := fmt.Sprintf(
			"app call %d increment --abi %s from %s --arg 13",
			app.AppID,
			app.ABIPath,
			creatorAddr,
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d method increment(uint64)void from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
		)

		state, err := app.ReadGlobalState()
		if err != nil {
			t.Fatalf("read global state failed: %v", err)
		}
		counter := state["counter"].(uint64)
		if counter != 13 {
			t.Fatalf("counter = %d, want 13", counter)
		}
	})

	t.Run("SetBox", func(t *testing.T) {
		if err := app.FundApp(funder, 200_000); err != nil {
			t.Fatalf("app funding failed: %v", err)
		}

		command := fmt.Sprintf(
			"app call %d set_box --abi %s from %s --arg text:cfg --arg text:abi-value box=cfg",
			app.AppID,
			app.ABIPath,
			creatorAddr,
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d method set_box(byte[],byte[])void from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
		)

		box, err := testnet.Client.GetApplicationBoxByName(app.AppID, []byte("cfg")).Do(context.Background())
		if err != nil {
			t.Fatalf("read box failed: %v", err)
		}
		if string(box.Value) != "abi-value" {
			t.Fatalf("box value = %q, want abi-value", string(box.Value))
		}
	})

	t.Run("OptIn", func(t *testing.T) {
		command := fmt.Sprintf(
			"app call %d optin --abi %s from %s oncomp=optin",
			app.AppID,
			app.ABIPath,
			creatorAddr,
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d method optin()void from %s using Ed25519 key...", app.AppID, signableAddressText(creatorAddr)),
		)

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}
		balance := localState["balance"].(uint64)
		if balance != 0 {
			t.Fatalf("balance = %d, want 0", balance)
		}
	})
}

func TestAppCallMethodPayCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	if err := app.OptIn(creatorAddr, creatorSK); err != nil {
		t.Fatalf("opt-in setup failed: %v", err)
	}
	if err := app.FundApp(funder, 200_000); err != nil {
		t.Fatalf("app funding failed: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	depositAmount := uint64(100_000)

	t.Run("Simulate", func(t *testing.T) {
		command := fmt.Sprintf(
			"simulate app call %d deposit --abi %s from %s --pay %d",
			app.AppID,
			app.ABIPath,
			creatorAddr,
			depositAmount,
		)
		output := runApshellScript(t, apshell, command)
		if !strings.Contains(output, "Simulation successful") {
			t.Fatalf("unexpected simulate output:\n%s", output)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}
		if balance := localState["balance"].(uint64); balance != 0 {
			t.Fatalf("balance after simulate = %d, want 0", balance)
		}
	})

	t.Run("Execute", func(t *testing.T) {
		command := fmt.Sprintf(
			"app call %d deposit --abi %s from %s --pay %d",
			app.AppID,
			app.ABIPath,
			creatorAddr,
			depositAmount,
		)
		output := runApshellScript(t, apshell, command)
		requireOutputContainsAll(t, output,
			"✓ Confirmed in round ",
			fmt.Sprintf("Calling app %d method deposit()void from %s with companion payment of %d microAlgos...", app.AppID, signableAddressText(creatorAddr), depositAmount),
		)

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state failed: %v", err)
		}
		if balance := localState["balance"].(uint64); balance != depositAmount {
			t.Fatalf("balance after execute = %d, want %d", balance, depositAmount)
		}
	})
}

func TestAppJSAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	if err := app.OptIn(creatorAddr, creatorSK); err != nil {
		t.Fatalf("opt-in setup failed: %v", err)
	}
	if err := app.FundApp(funder, 200_000); err != nil {
		t.Fatalf("app funding failed: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	apshell := harness.NewApshellHarness(t, signerd.GetURL())
	if err := apshell.CopyTokenFrom(signerd.GetWorkDir()); err != nil {
		t.Fatalf("failed to copy API token: %v", err)
	}

	depositAmount := uint64(100_000)
	command := fmt.Sprintf(
		"js const info = appInfo(%d); "+
			"print('appaddr=' + info.app_address); "+
			"const raw = appCallRaw(%d, '%s', ['hex:%s', 'hex:%s']); "+
			"const global = appGlobal(%d); "+
			"print('counter=' + global.global_state.find(e => e.key_text === 'counter').value.uint); "+
			"appCall(%d, 'set_box', '%s', '%s', ['text:cfg', 'text:js-value'], {boxes: ['cfg']}); "+
			"const box = appBox(%d, 'cfg'); "+
			"print('box=' + box.value_text); "+
			"const boxes = appBoxes(%d); "+
			"print('hascfg=' + boxes.boxes.some(b => b.name_text === 'cfg')); "+
			"const dep = appCall(%d, 'deposit', '%s', '%s', [], {pay: %d}); "+
			"const local = appLocal(%d, '%s'); "+
			"print('balance=' + local.local_state.find(e => e.key_text === 'balance').value.uint);",
		app.AppID,
		app.AppID,
		creatorAddr,
		hex.EncodeToString(harness.IncrementSelector()),
		hex.EncodeToString(harness.EncodeUint64(7)),
		app.AppID,
		app.AppID,
		app.ABIPath,
		creatorAddr,
		app.AppID,
		app.AppID,
		app.AppID,
		app.ABIPath,
		creatorAddr,
		depositAmount,
		app.AppID,
		creatorAddr,
	)

	output := runApshellScript(t, apshell, command)
	if !strings.Contains(output, "appaddr="+app.AppAddress) {
		t.Fatalf("unexpected JS output, missing app info address:\n%s", output)
	}
	if !strings.Contains(output, "counter=7") {
		t.Fatalf("unexpected JS output, missing counter value:\n%s", output)
	}
	if !strings.Contains(output, "box=js-value") {
		t.Fatalf("unexpected JS output, missing box value:\n%s", output)
	}
	if !strings.Contains(output, "hascfg=true") {
		t.Fatalf("unexpected JS output, missing box listing confirmation:\n%s", output)
	}
	if !strings.Contains(output, fmt.Sprintf("balance=%d", depositAmount)) {
		t.Fatalf("unexpected JS output, missing balance value:\n%s", output)
	}

	globalState, err := app.ReadGlobalState()
	if err != nil {
		t.Fatalf("read global state failed: %v", err)
	}
	if counter := globalState["counter"].(uint64); counter != 7 {
		t.Fatalf("counter after JS script = %d, want 7", counter)
	}

	box, err := testnet.Client.GetApplicationBoxByName(app.AppID, []byte("cfg")).Do(context.Background())
	if err != nil {
		t.Fatalf("read box failed: %v", err)
	}
	if string(box.Value) != "js-value" {
		t.Fatalf("box value after JS script = %q, want %q", string(box.Value), "js-value")
	}

	localState, err := app.ReadLocalState(creatorAddr)
	if err != nil {
		t.Fatalf("read local state failed: %v", err)
	}
	if balance := localState["balance"].(uint64); balance != depositAmount {
		t.Fatalf("balance after JS script = %d, want %d", balance, depositAmount)
	}
}

func appFixturePath(t *testing.T, name string) string {
	t.Helper()

	path, err := filepath.Abs(filepath.Join("..", "..", "test", "fixtures", "testapp", name))
	if err != nil {
		t.Fatalf("failed to resolve fixture path for %s: %v", name, err)
	}
	return path
}

func compileFixturePrograms(t *testing.T, client *algod.Client, approvalPath, clearPath string) (string, string) {
	t.Helper()

	approvalSrc, err := os.ReadFile(approvalPath)
	if err != nil {
		t.Fatalf("failed to read approval program: %v", err)
	}
	clearSrc, err := os.ReadFile(clearPath)
	if err != nil {
		t.Fatalf("failed to read clear program: %v", err)
	}

	approvalCompiled, err := client.TealCompile(approvalSrc).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to compile approval program: %v", err)
	}
	clearCompiled, err := client.TealCompile(clearSrc).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to compile clear program: %v", err)
	}

	approvalBytes, err := base64.StdEncoding.DecodeString(approvalCompiled.Result)
	if err != nil {
		t.Fatalf("failed to decode compiled approval program: %v", err)
	}
	clearBytes, err := base64.StdEncoding.DecodeString(clearCompiled.Result)
	if err != nil {
		t.Fatalf("failed to decode compiled clear program: %v", err)
	}

	approvalBin := filepath.Join(t.TempDir(), "approval.bin")
	clearBin := filepath.Join(t.TempDir(), "clear.bin")
	if err := os.WriteFile(approvalBin, approvalBytes, 0o600); err != nil {
		t.Fatalf("failed to write approval bin: %v", err)
	}
	if err := os.WriteFile(clearBin, clearBytes, 0o600); err != nil {
		t.Fatalf("failed to write clear bin: %v", err)
	}

	return approvalBin, clearBin
}

func compileFixtureProgramBytes(t *testing.T, client *algod.Client, path string) []byte {
	t.Helper()

	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read program %s: %v", path, err)
	}

	compiled, err := client.TealCompile(source).Do(context.Background())
	if err != nil {
		t.Fatalf("failed to compile program %s: %v", path, err)
	}

	programBytes, err := base64.StdEncoding.DecodeString(compiled.Result)
	if err != nil {
		t.Fatalf("failed to decode compiled program %s: %v", path, err)
	}
	return programBytes
}

func parseCreatedAppFromOutput(t *testing.T, output string) (uint64, string) {
	t.Helper()

	re := regexp.MustCompile(`Created app ([0-9]+) at ([A-Z2-7]+)`)
	matches := re.FindStringSubmatch(output)
	if len(matches) != 3 {
		t.Fatalf("failed to parse created app from output:\n%s", output)
	}

	appID, err := strconv.ParseUint(matches[1], 10, 64)
	if err != nil {
		t.Fatalf("invalid parsed app id %q: %v", matches[1], err)
	}
	return appID, matches[2]
}

func TestPreparedGroupDepositFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	if err := app.OptIn(creatorAddr, creatorSK); err != nil {
		t.Fatalf("opt-in setup failed: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	eng, err := newIntegrationEngine(t, testnet.Client, signerd.GetURL(), signerd.GetTokenPath())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	depositAmount := uint64(100_000)

	t.Run("Simulate", func(t *testing.T) {
		eng.SetSimulate(true)

		group, err := engine.PreparePaymentAppGroupWithContext(context.Background(), eng,
			engine.SendPaymentParams{
				From:   creatorAddr,
				To:     app.AppAddress,
				Amount: depositAmount,
			},
			engine.RawAppCallParams{
				AppID:        app.AppID,
				From:         creatorAddr,
				AppArgs:      [][]byte{harness.DepositSelector()},
				OnCompletion: types.NoOpOC,
			},
		)
		if err != nil {
			t.Fatalf("PreparePaymentAndAppCall() error = %v", err)
		}

		result, err := eng.ExecutePreparedGroup(context.Background(), group, true)
		if err != nil {
			t.Fatalf("ExecutePreparedGroup(simulate) error = %v", err)
		}
		if result.Confirmed {
			t.Fatal("simulation reported confirmed=true, want false")
		}
		if len(result.TxIDs) != 2 {
			t.Fatalf("len(result.TxIDs) = %d, want 2", len(result.TxIDs))
		}
		if !strings.Contains(result.Output, "Simulation successful") {
			t.Fatalf("simulate output did not contain success marker:\n%s", result.Output)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state after simulate failed: %v", err)
		}
		balance := localState["balance"].(uint64)
		if balance != 0 {
			t.Fatalf("balance after simulate = %d, want 0", balance)
		}
	})

	t.Run("Execute", func(t *testing.T) {
		eng.SetSimulate(false)

		group, err := engine.PreparePaymentAppGroupWithContext(context.Background(), eng,
			engine.SendPaymentParams{
				From:   creatorAddr,
				To:     app.AppAddress,
				Amount: depositAmount,
			},
			engine.RawAppCallParams{
				AppID:        app.AppID,
				From:         creatorAddr,
				AppArgs:      [][]byte{harness.DepositSelector()},
				OnCompletion: types.NoOpOC,
			},
		)
		if err != nil {
			t.Fatalf("PreparePaymentAndAppCall() error = %v", err)
		}

		result, err := eng.ExecutePreparedGroup(context.Background(), group, true)
		if err != nil {
			t.Fatalf("ExecutePreparedGroup() error = %v", err)
		}
		if !result.Confirmed {
			t.Fatal("execution reported confirmed=false, want true")
		}
		if len(result.TxIDs) != 2 {
			t.Fatalf("len(result.TxIDs) = %d, want 2", len(result.TxIDs))
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state after execute failed: %v", err)
		}
		balance := localState["balance"].(uint64)
		if balance != depositAmount {
			t.Fatalf("balance after execute = %d, want %d", balance, depositAmount)
		}
	})
}

func TestPreparedGroupDepositMethodFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testnet, err := harness.NewTestnetConfig()
	if err != nil {
		t.Fatalf("failed to connect to testnet: %v", err)
	}

	funder, err := harness.NewFundTestAccount(testnet.Client)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	creatorAddr := funder.GetAddress()
	creatorSK := funder.GetPrivateKey()

	app, err := harness.DeployTestApp(t, testnet.Client, creatorAddr, creatorSK)
	if err != nil {
		t.Fatalf("deploy failed: %v", err)
	}
	defer func() {
		if err := app.DestroyTestApp(creatorSK); err != nil {
			t.Logf("warning: failed to destroy test app: %v", err)
		}
	}()

	if err := app.OptIn(creatorAddr, creatorSK); err != nil {
		t.Fatalf("opt-in setup failed: %v", err)
	}

	signerd := harness.NewSignerHarness(t)
	if err := signerd.Start(); err != nil {
		t.Fatalf("failed to start Signer: %v", err)
	}
	defer func() { _ = signerd.Stop() }()

	apadmin := harness.NewApAdminHarness(t, signerd.GetWorkDir())
	if _, err := apadmin.ImportKey(os.Getenv("TEST_FUNDING_MNEMONIC")); err != nil {
		t.Fatalf("failed to import funding account into Signer: %v", err)
	}
	if err := apadmin.StartUnlockBackground(); err != nil {
		t.Fatalf("failed to start background unlock: %v", err)
	}
	defer apadmin.StopUnlockBackground()

	eng, err := newIntegrationEngine(t, testnet.Client, signerd.GetURL(), signerd.GetTokenPath())
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	depositAmount := uint64(100_000)

	t.Run("Simulate", func(t *testing.T) {
		eng.SetSimulate(true)

		group, err := engine.PreparePaymentMethodGroupWithContext(context.Background(), eng,
			engine.SendPaymentParams{
				From:   creatorAddr,
				To:     app.AppAddress,
				Amount: depositAmount,
			},
			engine.MethodAppCallParams{
				ABIPath: app.ABIPath,
				Method:  "deposit",
				RawAppCallParams: engine.RawAppCallParams{
					AppID:        app.AppID,
					From:         creatorAddr,
					OnCompletion: types.NoOpOC,
				},
			},
		)
		if err != nil {
			t.Fatalf("PreparePaymentAndMethodCall() error = %v", err)
		}

		result, err := eng.ExecutePreparedGroup(context.Background(), group, true)
		if err != nil {
			t.Fatalf("ExecutePreparedGroup(simulate) error = %v", err)
		}
		if result.Confirmed {
			t.Fatal("simulation reported confirmed=true, want false")
		}
		if len(result.TxIDs) != 2 || len(result.Transactions) != 2 {
			t.Fatalf("result sizes = (%d txids, %d txns), want (2, 2)", len(result.TxIDs), len(result.Transactions))
		}
		if result.Transactions[0].Type != types.PaymentTx {
			t.Fatalf("first transaction type = %v, want payment", result.Transactions[0].Type)
		}
		if result.Transactions[1].Type != types.ApplicationCallTx {
			t.Fatalf("second transaction type = %v, want app call", result.Transactions[1].Type)
		}
		if !strings.Contains(result.Output, "Simulation successful") {
			t.Fatalf("simulate output did not contain success marker:\n%s", result.Output)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state after simulate failed: %v", err)
		}
		balance := localState["balance"].(uint64)
		if balance != 0 {
			t.Fatalf("balance after simulate = %d, want 0", balance)
		}
	})

	t.Run("Execute", func(t *testing.T) {
		eng.SetSimulate(false)

		group, err := engine.PreparePaymentMethodGroupWithContext(context.Background(), eng,
			engine.SendPaymentParams{
				From:   creatorAddr,
				To:     app.AppAddress,
				Amount: depositAmount,
			},
			engine.MethodAppCallParams{
				ABIPath: app.ABIPath,
				Method:  "deposit",
				RawAppCallParams: engine.RawAppCallParams{
					AppID:        app.AppID,
					From:         creatorAddr,
					OnCompletion: types.NoOpOC,
				},
			},
		)
		if err != nil {
			t.Fatalf("PreparePaymentAndMethodCall() error = %v", err)
		}

		result, err := eng.ExecutePreparedGroup(context.Background(), group, true)
		if err != nil {
			t.Fatalf("ExecutePreparedGroup() error = %v", err)
		}
		if !result.Confirmed {
			t.Fatal("execution reported confirmed=false, want true")
		}
		if len(result.TxIDs) != 2 || len(result.Transactions) != 2 {
			t.Fatalf("result sizes = (%d txids, %d txns), want (2, 2)", len(result.TxIDs), len(result.Transactions))
		}
		if result.Transactions[0].Type != types.PaymentTx {
			t.Fatalf("first transaction type = %v, want payment", result.Transactions[0].Type)
		}
		if result.Transactions[1].Type != types.ApplicationCallTx {
			t.Fatalf("second transaction type = %v, want app call", result.Transactions[1].Type)
		}

		localState, err := app.ReadLocalState(creatorAddr)
		if err != nil {
			t.Fatalf("read local state after execute failed: %v", err)
		}
		balance := localState["balance"].(uint64)
		if balance != depositAmount {
			t.Fatalf("balance after execute = %d, want %d", balance, depositAmount)
		}
	})
}

func newIntegrationEngine(t *testing.T, algodClient *algod.Client, signerURL, tokenPath string) (*engine.Engine, error) {
	t.Helper()

	cache.InitLogger()
	cacheStore := cache.NewStore(t.TempDir())

	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signer token: %w", err)
	}

	eng, err := engine.NewEngine(harness.IntegrationNetwork(),
		engine.WithAlgodClient(algodClient),
		engine.WithCacheStore(cacheStore),
		engine.WithSignerCache(cache.NewSignerCache()),
		engine.WithAuthCache(cache.NewAuthAddressCache()),
	)
	if err != nil {
		return nil, err
	}

	eng.Connection.SignerClient = util.NewSignerClientWithToken(signerURL, strings.TrimSpace(string(tokenBytes)))
	if err := eng.EnsureSignerCache(context.Background()); err != nil {
		return nil, err
	}
	return eng, nil
}

func readAppJSON(t *testing.T, apshell *harness.ApshellHarness, command string, out interface{}) {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "app_read.ap")
	if err := os.WriteFile(scriptPath, []byte(command+"\n"), 0600); err != nil {
		t.Fatalf("failed to write script file: %v", err)
	}

	output, err := apshell.Run("-script", scriptPath)
	if err != nil {
		t.Fatalf("apshell command failed: %v", err)
	}

	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start == -1 || end == -1 || end < start {
		t.Fatalf("failed to locate JSON payload in output:\n%s", output)
	}

	payload := output[start : end+1]
	if err := json.Unmarshal([]byte(payload), out); err != nil {
		t.Fatalf("failed to decode JSON payload %q: %v", payload, err)
	}
}

func runApshellScript(t *testing.T, apshell *harness.ApshellHarness, command string) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "app_cmd.ap")
	if err := os.WriteFile(scriptPath, []byte(command+"\n"), 0600); err != nil {
		t.Fatalf("failed to write script file: %v", err)
	}

	output, err := apshell.Run("-script", scriptPath)
	if err != nil {
		t.Fatalf("apshell command failed: %v", err)
	}
	return output
}
