// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

func reviewTestAddress(first byte) types.Address {
	var address types.Address
	address[0] = first
	return address
}

// The review of a slot is the signer's own description of the transaction,
// then every finding the signer would warn about, marked `!!`. What each
// transaction type's description says, and which fields are findings, is
// tested where both are built, in internal/txnreview.
func TestPluginReviewIsTheSharedDescriptionPlusMarkedFindings(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)

	rekey := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, RekeyTo: other},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender, CloseRemainderTo: other},
	}
	lines := pluginReviewLines(rekey, nil)
	description := strings.Split(txnreview.Describe(rekey, txnreview.View{}), "\n")
	for i, want := range description {
		if i >= len(lines) || lines[i] != want {
			t.Fatalf("line %d is not the shared description's %q:\n%s", i, want, strings.Join(lines, "\n"))
		}
	}
	got := strings.Join(lines[len(description):], "\n")
	for _, finding := range txnreview.Findings(rekey, txnreview.FindingContext{}) {
		if want := "!! " + finding.Field + " = " + finding.Value; !strings.Contains(got, want) {
			t.Errorf("review missing %q:\n%s", want, got)
		}
	}
	for _, want := range []string{
		"!! RekeyTo = " + other.String(),
		"YOU WILL LOSE CONTROL OF THIS ACCOUNT",
		"!! CloseRemainderTo = " + other.String(),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("review missing %q:\n%s", want, got)
		}
	}

	plain := strings.Join(pluginReviewLinesOf(types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1000},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: other, Amount: 5},
	}), "\n")
	if strings.Contains(plain, "!!") {
		t.Errorf("a plain payment carries a finding:\n%s", plain)
	}
	if !strings.Contains(plain, "Payment: 0.000005 ALGO") || !strings.Contains(plain, "To:   "+other.String()) {
		t.Errorf("a plain payment is not described:\n%s", plain)
	}
}

// A rekey is flagged whatever the transaction's type, including one the
// describer does not know.
func TestPluginReviewFlagsARekeyOnAnyType(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)
	for _, txType := range []types.TxType{
		types.PaymentTx, types.AssetTransferTx, types.ApplicationCallTx,
		types.KeyRegistrationTx, types.AssetConfigTx, types.AssetFreezeTx, types.TxType("zzz"),
	} {
		got := strings.Join(pluginReviewLinesOf(types.Transaction{
			Type: txType, Header: types.Header{Sender: sender, RekeyTo: other},
		}), "\n")
		if !strings.Contains(got, "!! RekeyTo = "+other.String()) {
			t.Errorf("type %q: the rekey is not flagged:\n%s", txType, got)
		}
	}
}

func TestPluginReviewEscapesThePluginsTransactionType(t *testing.T) {
	var out strings.Builder
	r := &REPLState{Out: &out}
	renderPluginGroupReview(r, "REVIEW", []pluginReviewSlot{{
		txn:  types.Transaction{Type: types.TxType("pay\x1b[2K\r  [1] forged"), Header: types.Header{Sender: reviewTestAddress(1)}},
		role: slotRolePluginSigned,
	}})
	if strings.ContainsAny(out.String(), "\x1b\r") {
		t.Fatalf("the review printed raw control bytes from the transaction type:\n%q", out.String())
	}
}

func pluginReviewLinesOf(txn types.Transaction) []string { return pluginReviewLines(txn, nil) }

func TestPluginReviewNamesTheNetworkAndKnowsHeldKeys(t *testing.T) {
	sender, other := reviewTestAddress(1), reviewTestAddress(2)
	hash, err := base64.StdEncoding.DecodeString(apconfig.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	var genesis types.Digest
	copy(genesis[:], hash)

	// The network comes from the genesis hash, whatever the genesis ID says.
	onTestnet := strings.Join(pluginReviewLines(types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, GenesisHash: genesis, GenesisID: "mainnet-v1.0"},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: other},
	}, nil), "\n")
	if !strings.Contains(onTestnet, "Network: testnet") {
		t.Errorf("the review does not name the chain from the genesis hash:\n%s", onTestnet)
	}

	unknown := strings.Join(pluginReviewLines(types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, GenesisHash: types.Digest{9}},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: other},
	}, nil), "\n")
	if !strings.Contains(unknown, "Genesis hash: ") {
		t.Errorf("a chain with no known name shows no genesis hash:\n%s", unknown)
	}

	rekey := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, RekeyTo: other},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
	}
	lost := strings.Join(pluginReviewLines(rekey, nil), "\n")
	kept := strings.Join(pluginReviewLines(rekey, map[string]bool{other.String(): true}), "\n")
	if !strings.Contains(lost, "YOU WILL LOSE CONTROL") {
		t.Errorf("a rekey to an address nobody here holds does not warn of losing control:\n%s", lost)
	}
	if strings.Contains(kept, "YOU WILL LOSE CONTROL") || !strings.Contains(kept, txnreview.RekeyHeldText) {
		t.Errorf("a rekey to a held address is not shown as keeping control:\n%s", kept)
	}
}

// The irreversible key registration and the half-set one are marked.
func TestPluginReviewMarksIrreversibleAndIncompleteKeyRegistrations(t *testing.T) {
	sender := reviewTestAddress(1)
	nonpart := strings.Join(pluginReviewLines(types.Transaction{
		Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
		KeyregTxnFields: types.KeyregTxnFields{Nonparticipation: true},
	}, nil), "\n")
	if !strings.Contains(nonpart, "!! Nonparticipation = true") || !strings.Contains(nonpart, "cannot be undone") {
		t.Errorf("a nonparticipation keyreg is not marked:\n%s", nonpart)
	}
	half := strings.Join(pluginReviewLines(types.Transaction{
		Type: types.KeyRegistrationTx, Header: types.Header{Sender: sender},
		KeyregTxnFields: types.KeyregTxnFields{SelectionPK: types.VRFPK{2}},
	}, nil), "\n")
	if !strings.Contains(half, "!! KeyRegistration = incomplete") {
		t.Errorf("a key registration with one key missing is not marked:\n%s", half)
	}
}
