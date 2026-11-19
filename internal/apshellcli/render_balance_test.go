// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/appresult"
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
