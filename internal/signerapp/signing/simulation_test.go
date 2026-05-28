// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
)

func TestSimulatorRejectsEmptyGroupBeforeAlgodLookup(t *testing.T) {
	called := false
	sim := Simulator{
		MakeAlgod: func(string, string) (*algod.Client, error) {
			called = true
			return nil, nil
		},
	}

	_, _, _, err := sim.SimulateSignedGroup(context.Background(), nil)
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("SimulateSignedGroup(empty) err = %#v, want bad_request", err)
	}
	if called {
		t.Fatalf("MakeAlgod was called for empty group")
	}
}

func TestSimulatorRejectsMixedGenesisHashesBeforeAlgodLookup(t *testing.T) {
	called := false
	sim := Simulator{
		Config: func() apconfig.ServerConfig {
			cfg := apconfig.DefaultServerConfig()
			cfg.Algod = apconfig.AlgodConfig{
				apconfig.NetworkTestnet: {Server: "http://localhost:4001", Token: "token"},
			}
			return cfg
		},
		MakeAlgod: func(string, string) (*algod.Client, error) {
			called = true
			return nil, nil
		},
	}

	_, err := sim.AlgodForTransactionGroup([]types.SignedTxn{
		{Txn: types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}}},
		{Txn: types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandMainnetGenesisHash)}}},
	})
	if err == nil || err.Kind != ErrorBadRequest {
		t.Fatalf("AlgodForTransactionGroup(mixed genesis) err = %#v, want bad_request", err)
	}
	if !strings.Contains(err.Message, "transaction 2") {
		t.Fatalf("error %q does not identify the mismatched transaction", err.Message)
	}
	if called {
		t.Fatalf("MakeAlgod was called for mixed genesis group")
	}
}

func TestSimulatorReportsMissingAlgodServerForResolvedNetwork(t *testing.T) {
	sim := Simulator{
		Config: func() apconfig.ServerConfig {
			cfg := apconfig.DefaultServerConfig()
			cfg.Algod = apconfig.AlgodConfig{
				apconfig.NetworkTestnet: {Token: "token"},
			}
			return cfg
		},
	}

	_, err := sim.AlgodForTransactionGroup([]types.SignedTxn{
		{Txn: types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}}},
	})
	if err == nil || err.Kind != ErrorUnavailable {
		t.Fatalf("AlgodForTransactionGroup(missing server) err = %#v, want unavailable", err)
	}
	if !strings.Contains(err.Message, apconfig.NetworkTestnet) {
		t.Fatalf("error %q does not include resolved network", err.Message)
	}
}

func TestSimulatorPassesResolvedNetworkAlgodConfigToFactory(t *testing.T) {
	var gotServer, gotToken string
	sim := Simulator{
		Config: func() apconfig.ServerConfig {
			cfg := apconfig.DefaultServerConfig()
			cfg.Algod = apconfig.AlgodConfig{
				apconfig.NetworkTestnet: {Server: "http://algod.example", Token: "secret-token"},
			}
			return cfg
		},
		MakeAlgod: func(serverURL, token string) (*algod.Client, error) {
			gotServer = serverURL
			gotToken = token
			return nil, nil
		},
	}

	_, err := sim.AlgodForTransactionGroup([]types.SignedTxn{
		{Txn: types.Transaction{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}}},
	})
	if err == nil || err.Kind != ErrorUnavailable {
		t.Fatalf("AlgodForTransactionGroup(nil client) err = %#v, want unavailable", err)
	}
	if gotServer != "http://algod.example" {
		t.Fatalf("factory server = %q, want configured server", gotServer)
	}
	if gotToken != "secret-token" {
		t.Fatalf("factory token = %q, want configured token", gotToken)
	}
}
