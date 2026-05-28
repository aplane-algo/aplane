// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

func TestNormalizePluginAddressArgs(t *testing.T) {
	specs := []cmdspec.ArgSpec{
		{Type: cmdspec.ArgTypeAddress},
		{Type: cmdspec.ArgTypeKeyword},
		{Type: cmdspec.ArgTypeFile},
	}
	args := []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq",
		"to",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}

	got := normalizePluginAddressArgs(specs, args)

	if got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
		t.Fatalf("arg0 = %q, want uppercase address", got[0])
	}
	if got[1] != "to" {
		t.Fatalf("arg1 = %q, want unchanged keyword", got[1])
	}
	if got[2] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("arg2 = %q, want unchanged non-address", got[2])
	}
}

func TestValidatePluginResult(t *testing.T) {
	tests := []struct {
		name    string
		result  *jsonrpc.ExecuteResult
		wantErr bool
	}{
		{name: "success with txns", result: &jsonrpc.ExecuteResult{Success: true, Transactions: []jsonrpc.TransactionIntent{{Type: "raw"}}}},
		{name: "failure without txns", result: &jsonrpc.ExecuteResult{Success: false, Message: "nope"}},
		{name: "failure with txns", result: &jsonrpc.ExecuteResult{Success: false, Transactions: []jsonrpc.TransactionIntent{{Type: "raw"}}}, wantErr: true},
		{name: "failure with continuation", result: &jsonrpc.ExecuteResult{Success: false, Continuation: &jsonrpc.Continuation{Command: "next"}}, wantErr: true},
		{name: "empty continuation command", result: &jsonrpc.ExecuteResult{Success: true, Continuation: &jsonrpc.Continuation{}}, wantErr: true},
		{name: "nil result", result: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePluginResult(tt.result)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePluginResult() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNormalizePluginCommandArgs(t *testing.T) {
	plugin := &discovery.Plugin{
		Manifest: &manifest.Manifest{
			Commands: []manifest.Command{{
				Name: "next",
				ArgSpecs: []cmdspec.ArgSpec{
					{Type: cmdspec.ArgTypeAddress},
					{Type: cmdspec.ArgTypeKeyword},
				},
			}},
		},
	}

	got := normalizePluginCommandArgs(plugin, "next", []string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq",
		"to",
	})

	if got[0] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
		t.Fatalf("arg0 = %q, want uppercase address", got[0])
	}
	if got[1] != "to" {
		t.Fatalf("arg1 = %q, want unchanged keyword", got[1])
	}
}
