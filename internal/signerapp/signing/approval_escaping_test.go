// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/txdesc"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// printedConsole keeps what the signer prints to its console.
type printedConsole struct{ strings.Builder }

func (c *printedConsole) Printf(format string, args ...any) { fmt.Fprintf(&c.Builder, format, args...) }
func (c *printedConsole) Println(args ...any)               { fmt.Fprintln(&c.Builder, args...) }
func (c *printedConsole) Sync()                             {}

// escapingTestCapture is what one signing request showed: the approval request
// and the daemon's console.
type escapingTestCapture struct {
	approvals   int
	address     string
	sender      string
	description string
	console     *printedConsole
}

// requireTerminalSafe fails if text could drive a terminal: a control byte
// other than newline or tab, DEL, or a format character.
func requireTerminalSafe(t *testing.T, what, text string) {
	t.Helper()
	for i := 0; i < len(text); i++ {
		if c := text[i]; (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f {
			t.Fatalf("%s holds raw byte 0x%02x:\n%q", what, c, text)
		}
	}
	for _, r := range []rune{'\u202e', '\u2028', '\ufffd'} {
		if strings.ContainsRune(text, r) {
			t.Fatalf("%s holds %U:\n%q", what, r, text)
		}
	}
}

// signForEscapingTest runs req through /sign with manual approval and returns
// what the operator and the console were shown.
func signForEscapingTest(t *testing.T, req signerapi.GroupSignRequest, plan *PlanResult) escapingTestCapture {
	t.Helper()
	got := escapingTestCapture{console: &printedConsole{}}
	describe := func(txn types.Transaction) string { return txdesc.DescribeTxn(txn) }
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove:               userAutoApproveDefault(false),
			GenerateTxnDescriptionFromTxn: describe,
			HasClient:                     func() bool { return true },
			KnownAddresses:                func() map[string]bool { return nil },
			Console:                       got.console,
			RequestSigningApproval: func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				got.approvals++
				got.address, got.sender, got.description = address, txnSender, description
				return true, nil
			},
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: describe,
		IsUnlocked:                    func() bool { return true },
		Console:                       got.console,
		BeforeExecute: func() (func(), *ServiceError) {
			return nil, forbidden("stop after approval")
		},
		PolicyFor: fixedPolicy(&policy.Config{TransactionTypes: policytest.AllowAllTypes(), Rekeys: policy.RekeysRejectForeign}),
	}
	if _, err := service.signGroupWithPlanContext(context.Background(), req, nil, plan); err == nil || !strings.Contains(err.Message, "stop after approval") {
		t.Fatalf("signGroupWithPlanContext() error = %#v, want the stop after approval", err)
	}
	if got.approvals != 1 {
		t.Fatalf("approval requests = %d, want 1", got.approvals)
	}
	return got
}

// The audit's scenario: the victim's payment to the attacker is signed here,
// and the attacker adds its own app call (foreign) whose ABI method label
// clears the screen and draws a harmless-looking payment, plus an asset
// creation whose URL moves the cursor over lines already printed. The
// selector check binds only the label's hash, which the attacker computes.
// What reaches the operator, and the daemon's console, shows every one of
// those bytes escaped, on the line it belongs to.
func TestApprovalPromptEscapesClientAndChainText(t *testing.T) {
	const forged = "\x1b[2J\x1b[H=== SINGLE TRANSACTION ===\r\nPayment: 1.000000 ALGO\n  To:   FRIEND\u202e"
	method := "x" + forged + "(uint64)void"
	selector, err := appspec.SignatureSelector(method)
	if err != nil {
		t.Fatalf("SignatureSelector(hostile method) error = %v; the attack needs it to pass", err)
	}
	victim, attacker := types.Address{1}, types.Address{2}
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Sender: victim, Fee: 1000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: attacker, Amount: 1_000_000_000}},
		{Type: types.ApplicationCallTx, Header: types.Header{Sender: attacker, Fee: 1000},
			ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
				ApplicationID: 7, OnCompletion: types.NoOpOC, ApplicationArgs: [][]byte{selector},
			}}},
		{Type: types.AssetConfigTx, Header: types.Header{Sender: attacker, Fee: 1000},
			AssetConfigTxnFields: types.AssetConfigTxnFields{AssetParams: types.AssetParams{
				Total: 1, AssetName: "N" + forged, UnitName: "U\x1b[1A", URL: "https://x\x1b[1A\x1b[2K" + forged,
			}}},
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: "AUTH\x1b[2J", TxnBytesHex: "5458aa"},
		{TxnBytesHex: "5458bb", AppCallInfo: &signerapi.AppCallInfo{Mode: "abi", Method: method}},
		{TxnBytesHex: "5458cc"},
	}}
	plan := &PlanResult{
		AllTxns:               txns,
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{1: true, 2: true},
		HasForeign:            true,
	}

	got := signForEscapingTest(t, req, plan)
	requireTerminalSafe(t, "approval description", got.description)
	requireTerminalSafe(t, "approval address", got.address)
	requireTerminalSafe(t, "console", got.console.String())

	if want := abiMethodLabel + "x" + `\x1b[2J\x1b[H=== SINGLE TRANSACTION ===\r\nPayment: 1.000000 ALGO\n  To:   FRIEND\u202e(uint64)void`; !strings.Contains(got.description, want) {
		t.Fatalf("description does not show the method escaped on its own line, want %q:\n%s", want, got.description)
	}
	for _, line := range strings.Split(got.description, "\n") {
		if strings.Contains(line, "FRIEND") && !strings.Contains(line, `\x1b`) {
			t.Fatalf("forged text reached a line of its own: %q\n%s", line, got.description)
		}
	}
	if !strings.Contains(got.description, "To:   "+attacker.String()) {
		t.Fatalf("description lost the real recipient:\n%s", got.description)
	}
}

// A single request takes its own prompt path, which escapes the same way.
func TestSingleRequestPromptEscapesTheMethodLabel(t *testing.T) {
	method := "x\x1b[2J\r\n  Amount: 1(uint64)void"
	selector, err := appspec.SignatureSelector(method)
	if err != nil {
		t.Fatalf("SignatureSelector(hostile method) error = %v", err)
	}
	txn := types.Transaction{Type: types.ApplicationCallTx, Header: types.Header{Sender: types.Address{1}, Fee: 1000},
		ApplicationFields: types.ApplicationFields{ApplicationCallTxnFields: types.ApplicationCallTxnFields{
			ApplicationID: 7, OnCompletion: types.NoOpOC, ApplicationArgs: [][]byte{selector},
		}}}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: "AUTHADDR", TxnBytesHex: "5458aa", AppCallInfo: &signerapi.AppCallInfo{Mode: "abi", Method: method}},
	}}
	plan := &PlanResult{
		AllTxns:               []types.Transaction{txn},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}

	got := signForEscapingTest(t, req, plan)
	requireTerminalSafe(t, "approval description", got.description)
	requireTerminalSafe(t, "console", got.console.String())
	if want := abiMethodLabel + `x\x1b[2J\r\n  Amount: 1(uint64)void`; !strings.Contains(got.description, want) {
		t.Fatalf("description does not show the method escaped, want %q:\n%s", want, got.description)
	}
}

func TestOperatorSafeViolationsEscapesEveryString(t *testing.T) {
	in := []signerapproval.Violation{{Field: "F\x1b", Value: "V\n", Severity: signerapproval.ViolationSeverityWarning, Message: "line one\nM\x1b[2J"}}
	got := operatorSafeViolations(in)
	want := signerapproval.Violation{Field: `F\x1b`, Value: `V\n`, Severity: signerapproval.ViolationSeverityWarning, Message: "line one\nM\\x1b[2J"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("operatorSafeViolations() = %#v, want %#v", got, want)
	}
	if in[0].Field != "F\x1b" {
		t.Fatal("operatorSafeViolations changed its input")
	}
}
