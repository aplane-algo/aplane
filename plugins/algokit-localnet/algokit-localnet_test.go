// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func execute(t *testing.T, params ExecuteParams) *Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return handleExecute(&Request{Jsonrpc: "2.0", Method: "execute", Params: raw, ID: 1})
}

// The subcommand is the first argument, whatever command name the host
// sends: the manifest's "localnet", or the plugin's own name, which JS
// plugin("algokit-localnet", ...) sends.
func TestExecuteTakesTheSubcommandFromTheArguments(t *testing.T) {
	cfg.network = "localnet"
	for _, tc := range []struct {
		name    string
		params  ExecuteParams
		unknown string // the subcommand refused, when one is
	}{
		{name: "manifest command", params: ExecuteParams{Command: "localnet", Args: []string{"help"}}},
		{name: "no arguments", params: ExecuteParams{Command: "localnet"}},
		{name: "plugin name", params: ExecuteParams{Command: "algokit-localnet", Args: []string{"help"}}},
		{name: "unknown subcommand", params: ExecuteParams{Command: "localnet", Args: []string{"bogus"}}, unknown: "bogus"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := execute(t, tc.params)
			if tc.unknown != "" {
				if resp.Error == nil || resp.Error.Message != "Unknown localnet subcommand" || resp.Error.Data != tc.unknown {
					t.Fatalf("response = %+v (error %+v), want %q refused", resp, resp.Error, tc.unknown)
				}
				return
			}
			result, ok := resp.Result.(ExecuteResult)
			if resp.Error != nil || !ok || !result.Success || result.Message != "AlgoKit LocalNet operations" {
				t.Fatalf("response = %+v (error %+v), want the help", resp, resp.Error)
			}
		})
	}
}

// A command for another network is refused, and one with no network runs on
// the network the plugin was initialized for, which stays as it was.
func TestExecuteRunsOnLocalNetOnly(t *testing.T) {
	cfg.network = "localnet"
	resp := execute(t, ExecuteParams{Command: "localnet", Args: []string{"help"}, Context: Context{Network: "testnet"}})
	if resp.Error == nil || resp.Error.Message != "algokit-localnet only supports localnet" || resp.Error.Data != "testnet" {
		t.Fatalf("response = %+v (error %+v), want testnet refused", resp, resp.Error)
	}
	resp = execute(t, ExecuteParams{Command: "localnet", Args: []string{"help"}})
	if resp.Error != nil {
		t.Fatalf("error = %+v, want the help", resp.Error)
	}
	if cfg.network != "localnet" {
		t.Fatalf("network = %q, want localnet", cfg.network)
	}
}

// An address means itself, in either case, before any alias is consulted:
// an alias named after address A that points to B does not make `fund A`
// fund B. Other input still resolves as an alias, ignoring case.
func TestResolveAddressNeverRedirectsAnAddress(t *testing.T) {
	a, b, c := testAddress(1), testAddress(2), testAddress(3)
	// "ALICE" and the Kelvin-sign "\u212Aate" are planted entries in a case
	// apshell never stores; neither may shadow the lowercase alias.
	aliases := map[string]string{strings.ToLower(a): b, "alice": c, "ALICE": b, "kate": c, "\u212Aate": b}
	for _, tc := range []struct{ input, want string }{
		{a, a},
		{strings.ToLower(a), a},
		{"alice", c},
		{"ALICE", c},
		{"Alice", c},
		{"Kate", c},
	} {
		got, err := parseFundArgs([]string{tc.input, "from", tc.input}, aliases)
		if err != nil || got.to != tc.want || got.from != tc.want {
			t.Fatalf("parseFundArgs(%q) = %+v, %v; want to and from %s", tc.input, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ input, want string }{
		{"bob", `"bob" is neither an Algorand address nor a known alias`},
		{"broken", `alias "broken": `},
	} {
		_, err := resolveAddress(tc.input, map[string]string{"broken": "not-an-address"})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("resolveAddress(%q) error = %v, want %q", tc.input, err, tc.want)
		}
	}
}

func testAddress(i byte) string {
	var addr types.Address
	addr[0] = i
	addr[31] = i + 1
	return addr.String()
}
