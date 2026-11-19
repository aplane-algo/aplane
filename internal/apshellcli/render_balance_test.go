// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
)

// "Algo" names ALGO, as the resolver reads it, everywhere balances are
// drawn and projected: the account's ALGO balance, not "0 Algo (not opted
// in)", "No accounts found" or, to MCP, a made-up 0-ALGO asset entry.
func TestBalanceOfAlgoInAnyCase(t *testing.T) {
	var out bytes.Buffer
	state, n := keyregShell(t, &out, false) // two accounts the signer holds, 10 ALGO each
	account := n.eligible.Address.String()

	for _, line := range []string{"balance " + account + " Algo", "balance @all Algo", "balance Algo", "holders Algo"} {
		t.Run(line, func(t *testing.T) {
			out.Reset()
			cmd, err := parseShellCommand(line)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.executeCommand(cmd); err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			text := out.String()
			if !strings.Contains(text, "10 ALGO") || strings.Contains(text, "not opted in") || strings.Contains(text, "No accounts") {
				t.Fatalf("%s drew:\n%s\nwant each account's 10 ALGO", line, text)
			}
		})
	}

	cmd, err := parseShellCommand("balance " + account + " Algo")
	if err != nil {
		t.Fatal(err)
	}
	result := mcpExecuteCommand(state, cmd)
	if result.IsError {
		t.Fatalf("MCP balance failed: %s", mcpResultText(t, result))
	}
	var balance appresult.MCPBalance
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &balance); err != nil {
		t.Fatal(err)
	}
	if balance.AlgoBalance != 10_000_000 || len(balance.Assets) != 0 {
		t.Fatalf("MCP balance = %+v, want the ALGO balance and no asset entry", balance)
	}
}

// A full balance of one account gives MCP every holding, as the shell shows
// them, not the ALGO balance alone.
func TestMCPFullBalanceHasEveryHolding(t *testing.T) {
	f := newSubmitFixture(t, nodeConfirms) // a holds asset 77
	var out bytes.Buffer
	f.state.SetOutput(&out)
	account := f.a.Address.String()

	if err := f.state.executeCommand(Command{Name: "balance", Args: []string{account}}); err != nil {
		t.Fatalf("balance: %v", err)
	}
	if !strings.Contains(out.String(), "TST") {
		t.Fatalf("the shell drew:\n%s\nwant the TST holding", out.String())
	}

	result := mcpExecuteCommand(f.state, Command{Name: "balance", Args: []string{account}})
	if result.IsError {
		t.Fatalf("MCP balance failed: %s", mcpResultText(t, result))
	}
	var balance appresult.MCPBalance
	if err := json.Unmarshal([]byte(mcpResultText(t, result)), &balance); err != nil {
		t.Fatal(err)
	}
	if len(balance.Assets) != 1 || balance.Assets[0].AssetID != submitTestAsset {
		t.Fatalf("MCP balance = %s, want the account's asset %d", mcpResultText(t, result), submitTestAsset)
	}
}

// balanceQueryShell is a shell whose aliases name the accounts given, on an
// algod that answers each account's query with 1 ALGO except for the
// accounts in failing, whose queries fail.
func balanceQueryShell(t *testing.T, aliases map[string]string, failing map[string]bool) (*REPLState, *bytes.Buffer) {
	t.Helper()
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, ok := strings.CutPrefix(r.URL.Path, "/v2/accounts/")
		if !ok {
			http.NotFound(w, r)
			return
		}
		if failing[address] {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Account{Address: address, Amount: 1_000_000, MinBalance: 100_000, Status: "Offline"})
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.AlgodClient = client
	eng.AliasCache.Aliases = aliases
	var out bytes.Buffer
	state := &REPLState{App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), Out: &out}
	state.CommandRegistry = state.initCommandRegistry()
	return state, &out
}

// An account balance @all or holders could not query is a warning in the
// shell and a balance_query_failed warning in the MCP result, and the shell's
// total says it leaves the account out. When no account can be queried, both
// fail with the same error.
func TestMultiAccountReadsReportFailedQueries(t *testing.T) {
	alice, bob := crypto.GenerateAccount().Address.String(), crypto.GenerateAccount().Address.String()
	aliases := map[string]string{"alice": alice, "bob": bob}
	warning := "could not query bob (" + bob + "): "
	for _, line := range []string{"balance @all", "holders"} {
		t.Run(line, func(t *testing.T) {
			state, out := balanceQueryShell(t, aliases, map[string]bool{bob: true})
			cmd, err := parseShellCommand(line)
			if err != nil {
				t.Fatal(err)
			}
			if err := state.executeCommand(cmd); err != nil {
				t.Fatalf("%s: %v", line, err)
			}
			text := out.String()
			if !strings.Contains(text, "Warning: "+warning) || !strings.Contains(text, "rate limited") ||
				!strings.Contains(text, "Total: 1 ALGO across 1 accounts, leaving out 1 that could not be queried\n") {
				t.Fatalf("%s drew:\n%s\nwant bob's failed query and a total that says it leaves him out", line, text)
			}

			result := mcpExecuteCommand(state, cmd)
			if result.IsError {
				t.Fatalf("MCP %s failed: %s", line, mcpResultText(t, result))
			}
			var got struct {
				Balances []appresult.MCPBalance     `json:"balances"`
				Holders  []appresult.MCPHolderEntry `json:"holders"`
				Warnings []map[string]string        `json:"warnings"`
			}
			if err := json.Unmarshal([]byte(mcpResultText(t, result)), &got); err != nil {
				t.Fatal(err)
			}
			if listed := len(got.Balances) + len(got.Holders); listed != 1 {
				t.Fatalf("MCP %s = %s, want alice alone listed", line, mcpResultText(t, result))
			}
			if len(got.Warnings) != 1 || !reflect.DeepEqual(got.Warnings[0]["code"], "balance_query_failed") ||
				!strings.HasPrefix(got.Warnings[0]["message"], warning) {
				t.Fatalf("MCP %s warnings = %v, want one balance_query_failed warning naming bob", line, got.Warnings)
			}
		})
		t.Run(line+" with no account queried", func(t *testing.T) {
			state, _ := balanceQueryShell(t, aliases, map[string]bool{alice: true, bob: true})
			cmd, err := parseShellCommand(line)
			if err != nil {
				t.Fatal(err)
			}
			// The first account queried, which the error names, is either.
			const want = "none of the 2 account(s) could be queried: "
			err = state.runCommand(cmd)
			if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "rate limited") {
				t.Fatalf("%s: %v, want the error %q", line, err, want)
			}
			result := mcpExecuteCommand(state, cmd)
			if text := mcpResultText(t, result); !result.IsError || !strings.HasPrefix(text, want) || !strings.Contains(text, "rate limited") {
				t.Fatalf("MCP %s = %q (error %v), want the shell's error %q", line, text, result.IsError, want)
			}
		})
	}
}
