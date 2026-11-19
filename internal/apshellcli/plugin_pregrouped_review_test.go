// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"bytes"
	"encoding/base64"
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
// and the rounds the slot is valid in. Two marks follow, each on its own: one
// when the signer holds the aplane key for the slot's sender, whoever the
// envelope names, and one for each other address the envelope names in its
// authorization (its auth address and every multisig subsignature key, its
// own or its LogicSig's) that the signer holds the aplane key for.
func TestReviewPregroupedSignedSaysWhoAuthorizesEachSlot(t *testing.T) {
	program := []byte{0x06, 0x81, 0x01}
	logicSigAccount := crypto.AddressFromProgram(program)
	// heldKey and heldLsigKey are subsignature keys the signer holds; the
	// others it does not.
	first, second, heldKey, heldLsigKey := crypto.GenerateAccount(), crypto.GenerateAccount(), crypto.GenerateAccount(), crypto.GenerateAccount()
	multisigOf := func(accounts ...crypto.Account) (types.MultisigSig, types.Address) {
		t.Helper()
		addresses := make([]types.Address, len(accounts))
		subsigs := make([]types.MultisigSubsig, len(accounts))
		for i, account := range accounts {
			addresses[i] = account.Address
			subsigs[i] = types.MultisigSubsig{Key: account.PublicKey, Sig: types.Signature{byte(i + 1)}}
		}
		account, err := crypto.MultisigAccountWithParams(1, uint8(len(accounts)), addresses)
		if err != nil {
			t.Fatal(err)
		}
		address, err := account.Address()
		if err != nil {
			t.Fatal(err)
		}
		return types.MultisigSig{Version: 1, Threshold: uint8(len(accounts)), Subsigs: subsigs}, address
	}
	unheldMsig, unheldMsigAddress := multisigOf(first, second)
	heldMsig, heldMsigAddress := multisigOf(first, heldKey)
	lsigMsig, lsigMsigAddress := multisigOf(second, heldLsigKey)

	held, heldToo, heldBoth := reviewTestAddress(34), reviewTestAddress(37), reviewTestAddress(38)
	heldAuthorizer, heldAuthorizerToo := reviewTestAddress(36), reviewTestAddress(39)
	plainSender, rekeyed, authorizer, rekeyedToHeld := reviewTestAddress(31), reviewTestAddress(32), reviewTestAddress(33), reviewTestAddress(35)
	pay := func(sender types.Address) types.Transaction {
		return types.Transaction{
			Type:             types.PaymentTx,
			Header:           types.Header{Sender: sender, Fee: 1000, FirstValid: 1000, LastValid: 2000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: reviewTestAddress(2), Amount: 1},
		}
	}
	delegated := types.LogicSig{Logic: program, Sig: types.Signature{1}}
	cases := []struct {
		name       string
		stxn       types.SignedTxn
		authorized string
		marks      []string
	}{
		{"plain signature", types.SignedTxn{Sig: types.Signature{1}, Txn: pay(plainSender)},
			plainSender.String() + " (single signature, not verified here)", nil},
		{"signature by another address", types.SignedTxn{Sig: types.Signature{1}, AuthAddr: authorizer, Txn: pay(rekeyed)},
			authorizer.String() + " (single signature, named as the sender's authorizer, not verified here)", nil},
		{"LogicSig account", types.SignedTxn{Lsig: types.LogicSig{Logic: program}, Txn: pay(logicSigAccount)},
			logicSigAccount.String() + " (LogicSig account, not verified here)", nil},
		{"LogicSig delegated by a held sender", types.SignedTxn{Lsig: delegated, Txn: pay(held)},
			held.String() + " (LogicSig delegated by a single signature, not verified here)", []string{heldSenderText}},
		{"multisig with no held key", types.SignedTxn{Msig: unheldMsig, Txn: pay(unheldMsigAddress)},
			unheldMsigAddress.String() + " (multisig, 2 of 2, not verified here)", nil},
		{"multisig with a held subsignature key", types.SignedTxn{Msig: heldMsig, Txn: pay(heldMsigAddress)},
			heldMsigAddress.String() + " (multisig, 2 of 2, not verified here)", []string{heldAuthorizationKeyText(heldKey.Address)}},
		{"LogicSig delegated by a held authorizer", types.SignedTxn{Lsig: delegated, AuthAddr: heldAuthorizer, Txn: pay(rekeyedToHeld)},
			heldAuthorizer.String() + " (LogicSig delegated by a single signature, named as the sender's authorizer, not verified here)",
			[]string{heldAuthorizationKeyText(heldAuthorizer)}},
		{"held sender, foreign authorizer", types.SignedTxn{Sig: types.Signature{1}, AuthAddr: authorizer, Txn: pay(heldToo)},
			authorizer.String() + " (single signature, named as the sender's authorizer, not verified here)", []string{heldSenderText}},
		{"held sender and held authorizer", types.SignedTxn{Sig: types.Signature{1}, AuthAddr: heldAuthorizerToo, Txn: pay(heldBoth)},
			heldAuthorizerToo.String() + " (single signature, named as the sender's authorizer, not verified here)",
			[]string{heldSenderText, heldAuthorizationKeyText(heldAuthorizerToo)}},
		{"LogicSig delegated by a multisig with a held subsignature key",
			types.SignedTxn{Lsig: types.LogicSig{Logic: program, Msig: lsigMsig}, Txn: pay(lsigMsigAddress)},
			lsigMsigAddress.String() + " (LogicSig delegated by multisig, 2 of 2, not verified here)",
			[]string{heldAuthorizationKeyText(heldLsigKey.Address)}},
	}
	stxns := make([]types.SignedTxn, len(cases))
	for i, tc := range cases {
		stxns[i] = tc.stxn
	}

	eng := newIsolatedTestEngine(t, "testnet")
	var keys []signerapi.KeyInfo
	for _, address := range []types.Address{held, heldToo, heldBoth, heldAuthorizer, heldAuthorizerToo, heldKey.Address, heldLsigKey.Address} {
		keys = append(keys, signerapi.KeyInfo{Address: address.String(), KeyType: "ed25519"})
	}
	if err := eng.PopulateSignerCache(keys); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	var out bytes.Buffer
	state := &REPLState{Out: &out, App: apshellapp.New(eng, config.DefaultConfig(), t.TempDir()), LineReader: func() (string, error) { return "n", nil }}
	if _, _, err := reviewPluginTransactions(state, &jsonrpc.ExecuteResult{
		GroupMode: jsonrpc.GroupModePregroupedSigned, Transactions: signedGroupIntents(t, stxns...),
	}, nil); err != nil {
		t.Fatalf("reviewPluginTransactions() error = %v", err)
	}

	blocks := reviewSlotBlocks(out.String())
	if len(blocks) != len(cases) {
		t.Fatalf("review has %d slot(s), want %d:\n%s", len(blocks), len(cases), out.String())
	}
	for i, tc := range cases {
		block := blocks[i]
		if want := "Authorized by: " + tc.authorized; block[1] != want {
			t.Errorf("%s: slot opens with %q, want %q", tc.name, block[1], want)
		}
		var marks []string
		for _, line := range block {
			if strings.HasPrefix(line, "THIS SIGNER HOLDS") {
				marks = append(marks, line)
			}
		}
		if !slices.Equal(marks, tc.marks) || !slices.Equal(block[2:2+len(tc.marks)], tc.marks) {
			t.Errorf("%s: marks %q, want %q right after the authorization", tc.name, marks, tc.marks)
		}
		if !slices.Contains(block, "Valid rounds: 1000 - 2000") {
			t.Errorf("%s: no valid rounds:\n%s", tc.name, strings.Join(block, "\n"))
		}
	}
}

// A presign-plan slot the plugin signs from an account the signer holds is
// marked too; a slot apsigner signs is not. A draft slot is not signed before
// the review, so it claims no authorizer and only its sender is judged.
func TestReviewPresignPlanMarksAPluginSignedSlotFromAHeldAccount(t *testing.T) {
	plugin := approvalTestPayment(34, 2, 1)
	managed := approvalTestPayment(1, 34, 2)
	eng := newIsolatedTestEngine(t, "testnet")
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
