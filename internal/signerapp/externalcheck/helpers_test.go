// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package externalcheck

import (
	"fmt"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
)

const testWitnessKey = "MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ"

// compileChecks decodes a cosigner document holding sources and checks, as
// the node would, and returns its compiled policy.
func compileChecks(t *testing.T, sources, checks string) *policy.Config {
	t.Helper()
	doc := fmt.Sprintf(`{
  "format": "aplane.policy.v1", "role": "cosigner", "key": %q,
  "reject_close_remainder": false, "reject_asset_close": false, "reject_clawback": false, "reject_rekey": false,
  "max_fee_microalgos": "0",
  "transaction_types": {"*": "allow"},
  "transfer_policy": {"routes": []},
  "external_sources": %s,
  "external_checks": %s
}`, testWitnessKey, sources, checks)
	decoded, err := policy.DecodePolicyV1([]byte(doc), testWitnessKey, noderole.RoleCosigner)
	if err != nil {
		t.Fatalf("DecodePolicyV1() error = %v", err)
	}
	cfg, err := decoded.Compile(policy.DefaultConfig())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	return cfg
}

func addr(b byte) types.Address { return types.Address{b} }

func payment(sender, receiver types.Address, amount uint64) types.Transaction {
	return types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1000, FirstValid: 1, LastValid: 2},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: types.MicroAlgos(amount)},
	}
}

func assetTransfer(sender, receiver types.Address, asset, amount uint64) types.Transaction {
	return types.Transaction{
		Type:   types.AssetTransferTx,
		Header: types.Header{Sender: sender, Fee: 1000, FirstValid: 1, LastValid: 2},
		AssetTransferTxnFields: types.AssetTransferTxnFields{
			XferAsset: types.AssetIndex(asset), AssetReceiver: receiver, AssetAmount: amount,
		},
	}
}

// requestOf is a request for every transaction of group, all on mainnet.
func requestOf(group ...types.Transaction) Request {
	targets := make([]int, len(group))
	for i := range group {
		targets[i] = i
	}
	return Request{
		WitnessKey: testWitnessKey, Group: group, Targets: targets,
		NetworkOf: func(types.Transaction) string { return "mainnet" },
	}
}
