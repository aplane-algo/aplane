// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestAlgodForTransactionGroupRejectsUnrecognizedGenesisHashBeforeAlgod(t *testing.T) {
	cfg := apconfig.DefaultServerConfig()
	calledMakeAlgod := false
	signer := &Signer{
		config: &cfg,
		makeAlgod: func(serverURL, token string) (*algod.Client, error) {
			calledMakeAlgod = true
			return nil, nil
		},
	}

	var unknownGenesis types.Digest
	unknownGenesis[0] = 0xaa
	_, err := signer.algodForTransactionGroup([]types.SignedTxn{{
		Txn: types.Transaction{Header: types.Header{GenesisHash: unknownGenesis}},
	}})

	if err == nil {
		t.Fatal("algodForTransactionGroup() error = nil, want unrecognized genesis hash")
		return
	}
	if err.Kind != signersigning.ErrorBadRequest {
		t.Fatalf("error kind = %s, want %s", err.Kind, signersigning.ErrorBadRequest)
	}
	if !strings.Contains(err.Message, "unrecognized genesis hash") {
		t.Fatalf("error message = %q, want unrecognized genesis hash", err.Message)
	}
	if calledMakeAlgod {
		t.Fatal("makeAlgod was called for unrecognized genesis hash")
	}
}
