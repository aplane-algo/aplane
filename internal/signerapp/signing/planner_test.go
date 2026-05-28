// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/base64"
	"strings"
	"testing"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestCategorizeRequests_AllowsForeign(t *testing.T) {
	_, foreign, err := categorizeRequests([]signerapi.SignRequest{{TxnBytesHex: "deadbeef"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(foreign) != 1 {
		t.Fatalf("expected 1 foreign request, got %d", len(foreign))
	}
}

func TestValidateKnownNetwork_AcceptsKnownNetworks(t *testing.T) {
	for _, hash := range []string{
		apconfig.AlgorandMainnetGenesisHash,
		apconfig.AlgorandTestnetGenesisHash,
		apconfig.AlgorandBetanetGenesisHash,
	} {
		err := validateKnownNetwork([]types.Transaction{
			{Header: types.Header{GenesisHash: testGenesisDigest(t, hash)}},
		}, apconfig.DefaultGenesisHashNetworkResolver())
		if err != nil {
			t.Errorf("validateKnownNetwork(%q) = %v, want nil", hash, err)
		}
	}
}

func TestValidateKnownNetwork_RejectsUnknownGenesisHash(t *testing.T) {
	for _, hash := range []types.Digest{{}, {1, 2, 3}, {9, 9, 9}} {
		err := validateKnownNetwork([]types.Transaction{
			{Header: types.Header{GenesisHash: hash}},
		}, apconfig.DefaultGenesisHashNetworkResolver())
		if err == nil {
			t.Errorf("validateKnownNetwork(%x) = nil, want error", hash[:])
		}
	}
}

func TestValidateKnownNetwork_RejectsIfAnyTxnHasUnknownNetwork(t *testing.T) {
	err := validateKnownNetwork([]types.Transaction{
		{Header: types.Header{GenesisHash: testGenesisDigest(t, apconfig.AlgorandTestnetGenesisHash)}},
		{Header: types.Header{GenesisHash: types.Digest{}}},
	}, apconfig.DefaultGenesisHashNetworkResolver())
	if err == nil {
		t.Fatal("expected error for mixed known/unknown genesis hashes")
	}
	if !strings.Contains(err.Error(), "transaction 2") {
		t.Fatalf("error should reference transaction 2, got: %v", err)
	}
}

func testGenesisDigest(t *testing.T, encoded string) types.Digest {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	var out types.Digest
	copy(out[:], decoded)
	return out
}
