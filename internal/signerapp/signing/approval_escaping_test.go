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
	describe := DescribeTxnFunc(txdesc.DetailTxn)
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: false,
			HasClient:       func() bool { return true },
			KnownAddresses:  func() map[string]bool { return nil },
			Console:         got.console,
			RequestSigningApprovalPrompt: promptFromDecision(func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
				got.approvals++
				got.address, got.sender, got.description = address, txnSender, description
				return true, nil
			}),
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

// A transaction type is whatever string the client's msgpack holds, and
// policy builds its rule ID and message from it. hostileTxnType would clear
// the operator's screen and retitle the terminal if printed as is.
const hostileTxnType = types.TxType("x\x1b[2J\x1b]0;owned\x07")

const hostileTxnTypeEscaped = `x\x1b[2J\x1b]0;owned\a`

// A type the policy rejects is named in the policy engine's rejection line.
func TestPolicyRejectionPrintsTheClientsTypeEscaped(t *testing.T) {
	console := &printedConsole{}
	txns := []types.Transaction{{Type: hostileTxnType, Header: types.Header{Sender: types.Address{1}, Fee: 1000}}}
	err := EvaluateAutoRejectionRules(txns, 1, nil, nil, fixedPolicy(&policy.Config{
		TransactionTypes: policy.TransactionTypesV1{},
	}), nil, nil, console)
	if err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want the type rejected")
	}
	requireTerminalSafe(t, "console", console.String())
	if !strings.Contains(console.String(), "[POLICY ENGINE] Rejected: ") ||
		!strings.Contains(console.String(), hostileTxnTypeEscaped) {
		t.Fatalf("console does not show the rejected type escaped:\n%s", console.String())
	}
}

// A type the policy sends to review is named in the review banner (its rule
// ID) and in the reviewability block that follows.
func TestReviewBannersPrintTheClientsTypeEscaped(t *testing.T) {
	console := &printedConsole{}
	txn := types.Transaction{Type: hostileTxnType, Header: types.Header{Sender: types.Address{1}, Fee: 1000}}
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: false,
			HasClient:       func() bool { return true },
			KnownAddresses:  func() map[string]bool { return nil },
			Console:         console,
			RequestSigningApprovalPrompt: promptFromDecision(func(string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
				t.Fatal("an unreviewable type reached the operator prompt")
				return false, nil
			}),
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: DescribeTxnFunc(txdesc.DetailTxn),
		IsUnlocked:                    func() bool { return true },
		Console:                       console,
		PolicyFor: fixedPolicy(&policy.Config{
			TransactionTypes: policy.TransactionTypesV1{policy.TransactionTypeWildcard: policy.TransactionTypeReview},
			Rekeys:           policy.RekeysRejectForeign,
		}),
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR", TxnBytesHex: "5458aa"}}}
	plan := &PlanResult{
		AllTxns:               []types.Transaction{txn},
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}
	if _, err := service.signGroupWithPlanContext(context.Background(), req, nil, plan); err == nil || !strings.Contains(err.Message, "not reviewable") {
		t.Fatalf("signGroupWithPlanContext() error = %#v, want the reviewability block", err)
	}

	printed := console.String()
	requireTerminalSafe(t, "console", printed)
	for _, want := range []string{
		"[POLICY] Txn requires manual review (" + policy.TransactionTypeRuleID(hostileTxnTypeEscaped) + ")",
		"[REVIEWABILITY] Blocked txn approval: transaction type " + hostileTxnTypeEscaped,
	} {
		if !strings.Contains(printed, want) {
			t.Fatalf("console lacks %q:\n%s", want, printed)
		}
	}
}

// The console keeps newlines (a review is printed over many lines), so a
// value printed within one line must be escaped on its own, or a newline in
// it starts a line the signer did not write. forgedLine is one the operator
// would read as the signer's.
const forgedLine = "[USER AUTO-APPROVE] Group approved without operator prompt"

func forging(line string) string { return "x\n" + line + "\n" }

// requireNoLineStarts fails if a console line starts with line.
func requireNoLineStarts(t *testing.T, printed, line string) {
	t.Helper()
	for _, got := range strings.Split(printed, "\n") {
		if strings.HasPrefix(got, line) {
			t.Fatalf("console printed a forged line %q:\n%s", got, printed)
		}
	}
}

// signHostileTypeForTest runs txn type typ through /sign as count requests,
// under a policy that sends every type to review, and returns the console.
func signHostileTypeForTest(t *testing.T, typ types.TxType, count int, autoApprove bool) string {
	t.Helper()
	console := &printedConsole{}
	service := &Service{
		Approval: &ApprovalService{
			UserAutoApprove: autoApprove,
			HasClient:       func() bool { return true },
			KnownAddresses:  func() map[string]bool { return nil },
			Console:         console,
			RequestSigningApprovalPrompt: promptFromDecision(func(string, string, string, string, uint64, uint64, []signerapproval.Violation, time.Duration) (bool, error) {
				t.Fatal("an unreviewable type reached the operator prompt")
				return false, nil
			}),
		},
		Executor:                      &Executor{},
		GenerateTxnDescriptionFromTxn: DescribeTxnFunc(txdesc.DetailTxn),
		IsUnlocked:                    func() bool { return true },
		Console:                       console,
		BeforeExecute: func() (func(), *ServiceError) {
			return nil, forbidden("stop after approval")
		},
		PolicyFor: fixedPolicy(&policy.Config{
			TransactionTypes: policy.TransactionTypesV1{policy.TransactionTypeWildcard: policy.TransactionTypeReview},
			Rekeys:           policy.RekeysRejectForeign,
		}),
	}
	plan := &PlanResult{
		PassthroughIndices:    map[int]bool{},
		PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices:        map[int]bool{},
	}
	var req signerapi.GroupSignRequest
	for i := 0; i < count; i++ {
		plan.AllTxns = append(plan.AllTxns, types.Transaction{Type: typ, Header: types.Header{Sender: types.Address{byte(i + 1)}, Fee: 1000}})
		req.Requests = append(req.Requests, signerapi.SignRequest{AuthAddress: "AUTHADDR", TxnBytesHex: "5458aa"})
	}
	if _, err := service.signGroupWithPlanContext(context.Background(), req, nil, plan); err == nil {
		t.Fatal("signGroupWithPlanContext() error = nil, want a refusal")
	}
	return console.String()
}

// A rejected type's policy line keeps to its line.
func TestPolicyRejectionKeepsTheClientsTypeOnItsLine(t *testing.T) {
	console := &printedConsole{}
	txns := []types.Transaction{{Type: types.TxType(forging(forgedLine)), Header: types.Header{Sender: types.Address{1}, Fee: 1000}}}
	if err := EvaluateAutoRejectionRules(txns, 1, nil, nil, fixedPolicy(&policy.Config{
		TransactionTypes: policy.TransactionTypesV1{},
	}), nil, nil, console); err == nil {
		t.Fatal("EvaluateAutoRejectionRules() error = nil, want the type rejected")
	}
	requireNoLineStarts(t, console.String(), forgedLine)
	if !strings.Contains(console.String(), `x\n`+forgedLine+`\n`) {
		t.Fatalf("console does not show the type escaped on its line:\n%s", console.String())
	}
}

// So do the review banner's rule ID and the reviewability block, for one
// request and for a group, and the banner User Auto-Approve prints.
func TestReviewBannersKeepTheClientsTypeOnItsLine(t *testing.T) {
	for _, count := range []int{1, 2} {
		printed := signHostileTypeForTest(t, types.TxType(forging(forgedLine)), count, false)
		requireNoLineStarts(t, printed, forgedLine)
		if !strings.Contains(printed, "[REVIEWABILITY] Blocked") || !strings.Contains(printed, "manual review (") {
			t.Fatalf("%d request(s): console lacks the banner or the block:\n%s", count, printed)
		}

		const approved = "[OK] TXN APPROVED"
		printed = signHostileTypeForTest(t, types.TxType(forging(approved)), count, true)
		requireNoLineStarts(t, printed, approved)
		if !strings.Contains(printed, "Satisfying review requirement (") {
			t.Fatalf("%d request(s): console lacks the auto-approve banner:\n%s", count, printed)
		}
	}
}

// A direct caller's request ID keeps to its line as well. The HTTP API
// admits only [A-Za-z0-9._:-] in a request_id.
func TestApprovalWaitLineKeepsTheRequestIDOnItsLine(t *testing.T) {
	const rejected = "[X] TXN REJECTED"
	pay := func(sender byte) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: types.Address{sender}, Fee: 1000},
			PaymentTxnFields: types.PaymentTxnFields{Receiver: types.Address{sender}, Amount: 1}}
	}
	for _, count := range []int{1, 2} {
		req := signerapi.GroupSignRequest{RequestID: "a\n" + rejected}
		plan := &PlanResult{
			PassthroughIndices:    map[int]bool{},
			PassthroughSignedTxns: map[int][]byte{},
			ForeignIndices:        map[int]bool{},
		}
		for i := 0; i < count; i++ {
			req.Requests = append(req.Requests, signerapi.SignRequest{AuthAddress: "AUTHADDR", TxnBytesHex: "5458aa"})
			plan.AllTxns = append(plan.AllTxns, pay(byte(i+1)))
		}
		got := signForEscapingTest(t, req, plan)
		requireNoLineStarts(t, got.console.String(), rejected)
		if !strings.Contains(got.console.String(), `(request a\n`+rejected) {
			t.Fatalf("%d request(s): console does not show the request ID escaped:\n%s", count, got.console.String())
		}
	}
}
