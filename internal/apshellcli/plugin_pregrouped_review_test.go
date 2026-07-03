// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Developers

package apshellcli

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
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
		_, raw, err := crypto.SignTransaction(acct.PrivateKey, txns[i])
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

	cancelled, err := reviewPluginTransactions(state, pregroupedSignedResult(t))
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

	cancelled, err := reviewPluginTransactions(state, result)
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

	cancelled, err := reviewPluginTransactions(state, pregroupedSignedResult(t))
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
