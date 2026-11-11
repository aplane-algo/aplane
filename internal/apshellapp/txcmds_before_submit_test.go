// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

var (
	beforeSubmitFrom = types.Address{1}.String()
	beforeSubmitTo   = types.Address{2}.String()
	// beforeSubmitRekeyed is rekeyed to beforeSubmitAuth on the fake network.
	beforeSubmitRekeyed = types.Address{3}.String()
	beforeSubmitAuth    = types.Address{4}.String()
)

// beforeSubmitApp is an app whose network answers enough to prepare a rekey
// or a close, and which has no signer: preparing succeeds and signing fails.
func beforeSubmitApp(t *testing.T) *App {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), Fee: 0, MinFee: 1000, LastRound: 100,
				GenesisId: "testnet-v1.0", GenesisHash: make([]byte, 32),
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			account := models.Account{
				Address: address, Amount: 5_000_000, MinBalance: 100_000, Status: "Offline",
			}
			if address == beforeSubmitRekeyed {
				account.AuthAddr = beforeSubmitAuth
			}
			_ = json.NewEncoder(w).Encode(account)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// The source accounts' keys are listed, but no signer is connected.
	eng.SignerCache.Keys = map[string]string{beforeSubmitFrom: "ed25519", beforeSubmitAuth: "ed25519"}
	return New(eng, config.DefaultConfig(), t.TempDir())
}

// The rekey warning is handed to the host once the transaction is prepared
// and before it is signed. Signing fails here, so a warning that was only
// built after submission would never have been delivered.
func TestRekeyAnnouncesBeforeSigning(t *testing.T) {
	app := beforeSubmitApp(t)
	var announced *RekeyCommandResult
	_, err := app.Rekey(context.Background(), RekeyRequest{
		Account: beforeSubmitFrom,
		Target:  beforeSubmitTo,
		BeforeSubmit: func(result *RekeyCommandResult) {
			copied := *result
			announced = &copied
		},
	})
	if err == nil {
		t.Fatal("Rekey() succeeded without a signer")
	}
	if announced == nil {
		t.Fatalf("nothing was announced before signing failed: %v", err)
	}
	if announced.TxID != "" {
		t.Fatalf("announced result carries a transaction ID %q: it was built after submission", announced.TxID)
	}
	text := strings.Join(announced.PreSubmitLines, "\n")
	if !strings.Contains(text, "cannot sign for this target address") {
		t.Fatalf("the announcement lacks the warning about a target this system cannot sign for:\n%s", text)
	}
}

func TestUnrekeyAnnouncesBeforeSigning(t *testing.T) {
	app := beforeSubmitApp(t)
	var announced *RekeyCommandResult
	_, err := app.Unrekey(context.Background(), UnrekeyRequest{
		Account: beforeSubmitRekeyed,
		BeforeSubmit: func(result *RekeyCommandResult) {
			copied := *result
			announced = &copied
		},
	})
	if err == nil {
		t.Fatal("Unrekey() succeeded without a signer")
	}
	if announced == nil {
		t.Fatalf("nothing was announced before signing failed: %v", err)
	}
	if announced.CurrentAuthAddress != beforeSubmitAuth || len(announced.PreSubmitLines) == 0 ||
		!strings.Contains(announced.PreSubmitLines[0], "currently rekeyed to") {
		t.Fatalf("announcement = %+v", announced)
	}
}

func TestCloseAnnouncesBeforeSigning(t *testing.T) {
	app := beforeSubmitApp(t)
	var lines []string
	_, err := app.Close(context.Background(), CloseRequest{
		Account: beforeSubmitFrom,
		CloseTo: beforeSubmitTo,
		BeforeSubmit: func(result *CloseCommandResult) {
			lines = append([]string(nil), result.PreSubmitLines...)
		},
	})
	if err == nil {
		t.Fatal("Close() succeeded without a signer")
	}
	if len(lines) == 0 || !strings.Contains(lines[0], "Closing account {from}") {
		t.Fatalf("announcement before signing = %q (error %v)", lines, err)
	}
}

// sweep() in a script reaches the shell's sweep workflow.
func TestScriptSweepRunsTheShellsSweep(t *testing.T) {
	app := beforeSubmitApp(t)
	runner := app.Scripts.EnsureRunner(func(string) {}, nil)
	_, err := runner.Run(`sweep("no-such-alias", "` + beforeSubmitTo + `")`)
	if err == nil || !strings.Contains(err.Error(), "failed to resolve source addresses") {
		t.Fatalf("sweep() error = %v, want the shell sweep's own resolution error", err)
	}

	// Every transaction failing is raised, with the account's reason.
	_, err = runner.Run(`sweep("` + beforeSubmitFrom + `", "` + beforeSubmitTo + `", {leaving: 1000000})`)
	if err == nil || !strings.Contains(err.Error(), "all 1 transaction(s) failed") ||
		!strings.Contains(err.Error(), beforeSubmitFrom+": ") {
		t.Fatalf("sweep() error = %v, want every-transaction-failed with the account's reason", err)
	}

	// An account with nothing above what is to be left is skipped, not failed.
	v, err := runner.Run(`const r = sweep("` + beforeSubmitFrom + `", "` + beforeSubmitTo + `", {leaving: 5000000}); r.succeeded + "|" + r.failed + "|" + r.items[0].skipped`)
	if err != nil {
		t.Fatalf("sweep() error = %v", err)
	}
	if got, ok := v.Value.(string); !ok || !strings.HasPrefix(got, "0|0|balance ") {
		t.Fatalf("sweep() result = %v, want a skipped account", v.Value)
	}
}

// What a script is told when a sweep fails.
func TestSweepResultForScript(t *testing.T) {
	failed := errors.New("all 2 transaction(s) failed")
	result := &SweepCommandResult{
		ToAddress:    "DEST",
		FailureCount: 2,
		Items: []SweepItemResult{
			// Sent, and the wait for confirmation failed: it may still confirm.
			{From: "A", TxID: "TXA", Error: "transaction failed: timed out waiting"},
			// A simulation failure has no Error in the shell's result.
			{From: "B", TxID: "SIMB", SimulationFailure: "simulation failed: logic eval error", Output: "a long dump\nof many lines\n"},
		},
	}

	_, err := sweepResultForScript(result, failed)
	if err == nil {
		t.Fatal("a sweep where every transaction failed was not raised")
	}
	for _, want := range []string{
		"A: transaction failed: timed out waiting [sent as TXA; check it before retrying]",
		"B: simulation failed: logic eval error",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "sent as SIMB") || strings.Contains(err.Error(), "a long dump") {
		t.Fatalf("a simulated transaction is reported as sent: %q", err)
	}

	// Partly failed: returned, and the simulation failure has a reason.
	out, err := sweepResultForScript(result, nil)
	if err != nil {
		t.Fatalf("a partly failed sweep was raised: %v", err)
	}
	if out.Failed != 2 || out.Items[0].TxID != "TXA" || out.Items[1].Error != "simulation failed: logic eval error" {
		t.Fatalf("result = %+v", out)
	}
}
