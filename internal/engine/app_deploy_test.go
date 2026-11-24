// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestPrepareAppDeploy_NoAlgodClient(t *testing.T) {
	eng := NewEngine("testnet")

	_, err := eng.PrepareAppDeploy(context.Background(), AppDeployParams{
		From: "alice",
		Approval: AppProgramSource{
			Path: "approval.teal",
		},
		Clear: AppProgramSource{
			Path: "clear.teal",
		},
	})
	if err != ErrNoAlgodClient {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

// deployTestParams is a deploy of two compiled programs from sender.
func deployTestParams(t *testing.T, sender string, useFlatFee bool) AppDeployParams {
	t.Helper()
	dir := t.TempDir()
	approval, clear := filepath.Join(dir, "approval.bin"), filepath.Join(dir, "clear.bin")
	if err := os.WriteFile(approval, []byte{0x0a, 0x81, 0x01}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clear, []byte{0x0a, 0x81, 0x01, 0x43}, 0o600); err != nil {
		t.Fatal(err)
	}
	return AppDeployParams{
		From:       sender,
		Approval:   AppProgramSource{Path: approval, Compiled: true},
		Clear:      AppProgramSource{Path: clear, Compiled: true},
		GlobalUint: 1, GlobalBytes: 2, LocalUint: 3, LocalBytes: 4, ExtraPages: 1,
		Note: "deploy", Fee: 0, UseFlatFee: useFlatFee,
	}
}

// TestPrepareAppDeployRequiresProgramsBeforeNetwork pins that a deploy
// missing a program is refused before any algod request.
func TestPrepareAppDeployRequiresProgramsBeforeNetwork(t *testing.T) {
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, refuseAlgodTransport{t: t})
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	program := AppProgramSource{Path: "program.teal"}
	tests := []struct {
		name   string
		params AppDeployParams
		want   string
	}{
		{"no programs", AppDeployParams{}, "missing approval program"},
		{"no approval program", AppDeployParams{Clear: program}, "missing approval program"},
		{"no clear program", AppDeployParams{Approval: program}, "missing clear program"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := NewEngine("testnet", WithAlgodClient(client))
			tt.params.From = testAddress(1).String()
			_, err := eng.PrepareAppDeploy(context.Background(), tt.params)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("PrepareAppDeploy() error = %v, want %q", err, tt.want)
			}
		})
	}
}

// A deploy is built from algod's suggested parameters, with the fee the
// caller set when it asked for a flat one, an explicit zero included.
func TestPrepareAppDeployBuildsFromSuggestedParams(t *testing.T) {
	testnet := testGenesisHash(t, config.AlgorandTestnetGenesisHash)
	sender := types.Address{9}
	for _, flat := range []bool{false, true} {
		client, _, _ := networkTestAlgod(t, testnet, "testnet-v1.0")
		eng := NewEngine("testnet", WithAlgodClient(client))
		if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
			{Address: sender.String(), KeyType: "ed25519", AuthorizationKind: "ed25519"},
		}); err != nil {
			t.Fatalf("PopulateSignerCache() error = %v", err)
		}
		eng.AuthCache.AuthAddresses = map[string]string{sender.String(): ""}

		prep, err := eng.PrepareAppDeploy(context.Background(), deployTestParams(t, sender.String(), flat))
		if err != nil {
			t.Fatalf("flat fee %v: PrepareAppDeploy() error = %v", flat, err)
		}
		txn := prep.Transaction
		wantFee := types.MicroAlgos(1000)
		if flat {
			wantFee = 0
		}
		if txn.Type != types.ApplicationCallTx || txn.Sender != sender || txn.ApplicationID != 0 || txn.Fee != wantFee ||
			txn.FirstValid != 1000 || txn.LastValid != 2000 || txn.GenesisID != "testnet-v1.0" || !bytes.Equal(txn.GenesisHash[:], testnet) ||
			!bytes.Equal(txn.ApprovalProgram, []byte{0x0a, 0x81, 0x01}) || !bytes.Equal(txn.ClearStateProgram, []byte{0x0a, 0x81, 0x01, 0x43}) ||
			txn.GlobalStateSchema != (types.StateSchema{NumUint: 1, NumByteSlice: 2}) || txn.LocalStateSchema != (types.StateSchema{NumUint: 3, NumByteSlice: 4}) ||
			txn.ExtraProgramPages != 1 || string(txn.Note) != "deploy" {
			t.Fatalf("flat fee %v: deploy transaction = %+v", flat, txn)
		}
		if prep.SigningContext == nil || prep.SigningContext.Address != sender.String() || prep.AppCallInfo != nil {
			t.Fatalf("flat fee %v: signing context %+v, app call info %+v", flat, prep.SigningContext, prep.AppCallInfo)
		}
	}
}

// Like every transaction apshell builds, a deploy's network check reuses
// the suggested parameters it was built from.
func TestPrepareAppDeployRemembersTheConsensusRead(t *testing.T) {
	testnet := testGenesisHash(t, config.AlgorandTestnetGenesisHash)
	sender := types.Address{9}.String()
	client, paramsCalls, _ := networkTestAlgod(t, testnet, "testnet-v1.0")
	eng := NewEngine("testnet", WithAlgodClient(client))
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: sender, KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	eng.AuthCache.AuthAddresses = map[string]string{sender: ""}

	prep, err := eng.PrepareAppDeploy(context.Background(), deployTestParams(t, sender, false))
	if err != nil {
		t.Fatalf("PrepareAppDeploy() error = %v", err)
	}
	if err := eng.checkActiveNetwork(context.Background(), []types.Transaction{prep.Transaction}); err != nil {
		t.Fatalf("checkActiveNetwork() error = %v", err)
	}
	if got := paramsCalls.Load(); got != 1 {
		t.Fatalf("SuggestedParams calls = %d, want 1", got)
	}
}
