// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txdesc

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policycontext"
)

func TestGenerateTransactionDescriptionFromTxn_ShowsResolvedNetwork(t *testing.T) {
	genesisHash, err := base64.StdEncoding.DecodeString(apconfig.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	sender, err := types.DecodeAddress("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ")
	if err != nil {
		t.Fatalf("decode sender: %v", err)
	}
	receiver, err := types.DecodeAddress("7777777777777777777777777777777777777777777777777774MSJUVU")
	if err != nil {
		t.Fatalf("decode receiver: %v", err)
	}
	var digest types.Digest
	copy(digest[:], genesisHash)
	txn := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender:      sender,
			GenesisHash: digest,
			GenesisID:   "testnet-v1.0",
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: receiver,
			Amount:   1,
		},
	}

	desc := DescribeTxn(txn)
	for _, want := range []string{
		"Network: testnet",
		"GenesisID: testnet-v1.0",
	} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description missing %q:\n%s", want, desc)
		}
	}
}

// describeContext is a signer that maps private-dev and has confirmed asset
// 9 on it with 2 decimals.
func describeContext(t *testing.T) (*policycontext.Context, types.Digest) {
	t.Helper()
	const hash = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	networks, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{hash: "private-dev"})
	if err != nil {
		t.Fatal(err)
	}
	genesis, err := asaset.ParseGenesisHash(hash)
	if err != nil {
		t.Fatal(err)
	}
	set, err := asaset.New([]asaset.Entry{{
		Identity: asaset.Identity{Genesis: genesis, AssetID: 9}, UnitName: "XYZ", Decimals: 2,
		Creator: types.Address{1}.String(), ConfirmedAt: time.Unix(1_700_000_000, 0), NetworkAtConfirmation: "private-dev",
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.New(noderole.RoleSigner, networks, set)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, types.Digest(genesis)
}

func TestDescribeInContextLabelsKnownAssets(t *testing.T) {
	ctx, genesis := describeContext(t)
	transfer := func(id uint64) types.Transaction {
		return types.Transaction{Type: types.AssetTransferTx, Header: types.Header{GenesisHash: genesis},
			AssetTransferTxnFields: types.AssetTransferTxnFields{XferAsset: types.AssetIndex(id), AssetAmount: 150}}
	}
	known := DescribeTxnInContext(transfer(9), ctx)
	if !strings.Contains(known, "ASA Transfer: 1.5 XYZ (150 base units), asset #9, private-dev") || strings.Contains(known, "Not in this node's ASA set") {
		t.Fatalf("known asset:\n%s", known)
	}
	unknown := DescribeTxnInContext(transfer(10), ctx)
	if !strings.Contains(unknown, "ASA Transfer: 150 base units, asset #10, private-dev\n  Not in this node's ASA set") {
		t.Fatalf("unknown asset:\n%s", unknown)
	}
	// The same ID on another chain is another asset.
	elsewhere := transfer(9)
	elsewhere.GenesisHash = types.Digest{7}
	if other := DescribeTxnInContext(elsewhere, ctx); !strings.Contains(other, "ASA Transfer: 150 base units, asset #9\n  Not in this node's ASA set") {
		t.Fatalf("asset 9 on another chain:\n%s", other)
	}
	freeze := types.Transaction{Type: types.AssetFreezeTx, Header: types.Header{GenesisHash: genesis},
		AssetFreezeTxnFields: types.AssetFreezeTxnFields{FreezeAsset: 9}}
	if got := DescribeTxnInContext(freeze, ctx); !strings.Contains(got, "Asset Freeze: asset #9 (XYZ)") {
		t.Fatalf("freeze:\n%s", got)
	}
	// Without a context, the description says only what the bytes say.
	if plain := DescribeTxnWithResolver(transfer(9), apconfig.DefaultGenesisHashNetworkResolver()); !strings.Contains(plain, "ASA Transfer: 150 base units, asset #9") || strings.Contains(plain, "ASA set") {
		t.Fatalf("without a context:\n%s", plain)
	}
}

// An asset's name, unit and URL, and a transaction's genesis ID and type, are
// whatever bytes the issuer or the client chose. A description shows them
// escaped, so none of them can clear the operator's screen, move the cursor
// over lines already printed, start a new line of its own, or reorder text.
