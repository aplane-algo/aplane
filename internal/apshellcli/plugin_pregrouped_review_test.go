// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// pregroupedSignedResult builds a valid fully signed two-transaction group,
// as a pregrouped-signed plugin would emit it. No chain access.
func pregroupedSignedResult(t *testing.T) *jsonrpc.ExecuteResult {
	t.Helper()
	acct := crypto.GenerateAccount()
	sp := types.SuggestedParams{
		Fee:             1000,
		FirstRoundValid: 1,
		LastRoundValid:  1001,
		GenesisHash:     make([]byte, 32),
		GenesisID:       "pregrouped-review-test",
		FlatFee:         true,
	}
	notes := []string{"a", "b"}
	txns := make([]types.Transaction, len(notes))
	for i, note := range notes {
		txn, err := transaction.MakePaymentTxn(acct.Address.String(), acct.Address.String(), 0, []byte(note), "", sp)
		if err != nil {
			t.Fatalf("make txn %d: %v", i, err)
		}
		txns[i] = txn
	}
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("compute group id: %v", err)
	}
	intents := make([]jsonrpc.TransactionIntent, len(txns))
	for i := range txns {
		txns[i].Group = gid
		_, raw, err := signing.SignTransactionWithKey(acct.PrivateKey, txns[i])
		if err != nil {
			t.Fatalf("sign txn %d: %v", i, err)
		}
		intents[i] = jsonrpc.TransactionIntent{
			Type:    jsonrpc.TransactionIntentSigned,
			Encoded: base64.StdEncoding.EncodeToString(raw),
		}
	}
	return &jsonrpc.ExecuteResult{
		GroupMode:    jsonrpc.GroupModePregroupedSigned,
		Transactions: intents,
	}
}

// PS3 (FORMAL_PLUGIN_SIGNING_MODEL.md): non-interactive contexts fail closed —
// a pregrouped-signed group is never submitted without an operator seeing it.
func TestReviewPregroupedSignedFailsClosedWhenAutoConfirm(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: true,
	}

	_, cancelled, err := reviewPluginTransactions(state, pregroupedSignedResult(t), nil)
	if err == nil || !strings.Contains(err.Error(), "non-interactive") {
		t.Fatalf("reviewPluginTransactions() error = %v, want non-interactive rejection", err)
	}
	if cancelled {
		t.Fatal("fail-closed path should report an error, not a user cancellation")
	}
}

// PS3: review is mandatory — the plugin's RequiresApproval flag cannot waive
// the prompt for pregrouped-signed groups.
func TestReviewPregroupedSignedIgnoresRequiresApprovalFalse(t *testing.T) {
	var out bytes.Buffer
	prompted := false
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		LineReader: func() (string, error) {
			prompted = true
			return "n", nil
		},
	}

	result := pregroupedSignedResult(t)
	result.RequiresApproval = false

	_, cancelled, err := reviewPluginTransactions(state, result, nil)
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if !prompted {
		t.Fatal("pregrouped-signed review must prompt even when the plugin sets RequiresApproval=false")
	}
	if !cancelled {
		t.Fatal("negative response should cancel the submission")
	}
}

// PS3: the review renders the decoded actual bytes before asking.
func TestReviewPregroupedSignedRendersDecodedGroupAndApproves(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{
		Out:         &out,
		AutoConfirm: false,
		LineReader: func() (string, error) {
			return "y", nil
		},
	}

	_, cancelled, err := reviewPluginTransactions(state, pregroupedSignedResult(t), nil)
	if err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	if cancelled {
		t.Fatal("affirmative response should not cancel")
	}
	rendered := out.String()
	if !strings.Contains(rendered, "plugin-signed") {
		t.Fatalf("review output missing plugin-signed role tag:\n%s", rendered)
	}
	if !strings.Contains(strings.ToLower(rendered), "fee") {
		t.Fatalf("review output missing decoded fee field:\n%s", rendered)
	}
}

// reviewSlotBlocks splits a rendered plugin group review into its slots: each
// slot's header line and the lines under it, with their indentation removed.
func reviewSlotBlocks(rendered string) [][]string {
	var blocks [][]string
	for _, line := range strings.Split(rendered, "\n") {
		switch {
		case strings.HasPrefix(line, "  ["):
			blocks = append(blocks, []string{strings.TrimSpace(line)})
		case strings.HasPrefix(line, "        ") && len(blocks) > 0:
			blocks[len(blocks)-1] = append(blocks[len(blocks)-1], strings.TrimSpace(line))
		}
	}
	return blocks
}

// signedGroupIntents groups the signed transactions as a pregrouped-signed
// plugin would emit them. Nothing checks a signature before submission.
func signedGroupIntents(t *testing.T, stxns ...types.SignedTxn) []jsonrpc.TransactionIntent {
	t.Helper()
	txns := make([]types.Transaction, len(stxns))
	for i, stxn := range stxns {
		txns[i] = stxn.Txn
	}
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	intents := make([]jsonrpc.TransactionIntent, len(stxns))
	for i, stxn := range stxns {
		stxn.Txn.Group = gid
		intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentSigned, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(stxn))}
	}
	return intents
}

// The pregrouped-signed review is the only gate such a group gets, so for
// each slot it says who the envelope names as authorizing it and with what,
// and the rounds the slot is valid in. A slot that spends from, or is
// authorized by, an address the signer holds an aplane key for is marked: the
// plugin, not apsigner, signs it. Here a delegated LogicSig spends from a held
// account, and another from an account rekeyed to a held key.
func TestReviewPregroupedSignedSaysWhoAuthorizesEachSlot(t *testing.T) {
	program := []byte{0x06, 0x81, 0x01}
	logicSigAccount := crypto.AddressFromProgram(program)
	first, second := crypto.GenerateAccount(), crypto.GenerateAccount()
	multisig, err := crypto.MultisigAccountWithParams(1, 2, []types.Address{first.Address, second.Address})
	if err != nil {
		t.Fatal(err)
	}
	multisigAddress, err := multisig.Address()
	if err != nil {
		t.Fatal(err)
	}
	plainSender, rekeyed, authorizer := reviewTestAddress(31), reviewTestAddress(32), reviewTestAddress(33)
	held, rekeyedToHeld, heldAuthorizer := reviewTestAddress(34), reviewTestAddress(35), reviewTestAddress(36)
	pay := func(sender types.Address) types.Transaction {
		return types.Transaction{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: sender, Fee: 1000, FirstValid: 1000, LastValid: 2000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: reviewTestAddress(2), Amount: 1},
		}
	}
	stxns := []types.SignedTxn{
		{Sig: types.Signature{1}, Txn: pay(plainSender)},
		{Sig: types.Signature{1}, AuthAddr: authorizer, Txn: pay(rekeyed)},
		{Lsig: types.LogicSig{Logic: program}, Txn: pay(logicSigAccount)},
		{Lsig: types.LogicSig{Logic: program, Sig: types.Signature{1}}, Txn: pay(held)},
		{Msig: types.MultisigSig{Version: 1, Threshold: 2, Subsigs: []types.MultisigSubsig{
			{Key: first.PublicKey, Sig: types.Signature{1}}, {Key: second.PublicKey, Sig: types.Signature{2}},
		}}, Txn: pay(multisigAddress)},
		{Lsig: types.LogicSig{Logic: program, Sig: types.Signature{1}}, AuthAddr: heldAuthorizer, Txn: pay(rekeyedToHeld)},
	}

	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: held.String(), KeyType: "ed25519"}, {Address: heldAuthorizer.String(), KeyType: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	var out bytes.Buffer
	state := &REPLState{Out: &out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), LineReader: func() (string, error) { return "n", nil }}
	if _, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode: jsonrpc.GroupModePregroupedSigned, Transactions: signedGroupIntents(t, stxns...),
	}, nil); err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}

	wants := [][]string{
		{"Authorized by: " + plainSender.String() + " (single signature, not verified here)"},
		{"Authorized by: " + authorizer.String() + " (single signature, named as the sender's authorizer, not verified here)"},
		{"Authorized by: " + logicSigAccount.String() + " (LogicSig account, not verified here)"},
		{"Authorized by: " + held.String() + " (LogicSig delegated by a single signature, not verified here)", heldSenderText},
		{"Authorized by: " + multisigAddress.String() + " (multisig, 2 of 2, not verified here)"},
		{"Authorized by: " + heldAuthorizer.String() + " (LogicSig delegated by a single signature, named as the sender's authorizer, not verified here)", heldAuthorizerText},
	}
	blocks := reviewSlotBlocks(out.String())
	if len(blocks) != len(wants) {
		t.Fatalf("review has %d slot(s), want %d:\n%s", len(blocks), len(wants), out.String())
	}
	for i, want := range wants {
		block := blocks[i]
		if got := block[1 : 1+len(want)]; !reflect.DeepEqual(got, want) {
			t.Errorf("slot %d opens with %q, want %q", i+1, got, want)
		}
		if len(want) == 1 && (block[2] == heldSenderText || block[2] == heldAuthorizerText) {
			t.Errorf("slot %d is marked as held: %q", i+1, block)
		}
		if !slices.Contains(block, "Valid rounds: 1000 - 2000") {
			t.Errorf("slot %d does not show its valid rounds:\n%s", i+1, strings.Join(block, "\n"))
		}
	}
}

// A presign-plan slot the plugin signs from an account the signer holds is
// marked too; a slot apsigner signs is not, and no draft slot claims an
// authorizer, since none is signed before the review.
func TestReviewPresignPlanMarksAPluginSignedSlotFromAHeldAccount(t *testing.T) {
	plugin := approvalTestPayment(34, 2, 1)
	managed := approvalTestPayment(1, 34, 2)
	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: plugin.Sender.String(), KeyType: "ed25519"}, {Address: managed.Sender.String(), KeyType: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	var out bytes.Buffer
	state := &REPLState{Out: &out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), AutoConfirm: true}
	if _, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode:     jsonrpc.GroupModePresignPlan,
		Transactions:  rawIntents(plugin, managed),
		PluginSigners: []jsonrpc.PluginSigner{{Address: plugin.Sender.String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
	}, nil); err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}
	rendered := out.String()
	blocks := reviewSlotBlocks(rendered)
	if len(blocks) != 2 || blocks[0][1] != heldSenderText || slices.Contains(blocks[1], heldSenderText) {
		t.Errorf("the plugin-signed slot from a held account is not marked, or the apsigner slot is:\n%s", rendered)
	}
	if strings.Contains(rendered, "Authorized by:") {
		t.Errorf("a draft slot claims an authorizer:\n%s", rendered)
	}
}
