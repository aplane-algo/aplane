// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/internal/transport"
)

func TestBuildApprovalResponseForSigning(t *testing.T) {
	req := approvalRequest{
		kind: approvalKindSign,
		signRequest: &protocol.SignRequestMessage{
			BaseMessage: protocol.BaseMessage{ID: "sign-1"},
		},
	}

	resp, err := buildApprovalResponse(req, true, "")
	if err != nil {
		t.Fatalf("buildApprovalResponse() error = %v", err)
	}
	signResp, ok := resp.(protocol.SignResponseMessage)
	if !ok {
		t.Fatalf("response type = %T, want protocol.SignResponseMessage", resp)
	}
	if signResp.Type != protocol.MsgTypeSignResponse {
		t.Fatalf("response type field = %q, want %q", signResp.Type, protocol.MsgTypeSignResponse)
	}
	if signResp.ID != "sign-1" || !signResp.Approved {
		t.Fatalf("unexpected signing response: %#v", signResp)
	}
}

func TestBuildApprovalResponseForClientEnrollment(t *testing.T) {
	req := approvalRequest{
		kind: approvalKindClientEnrollment,
		enrollmentRequest: &protocol.ClientEnrollmentRequestMessage{
			BaseMessage:    protocol.BaseMessage{ID: "enroll-1"},
			SSHFingerprint: "SHA256:abc",
		},
	}

	resp, err := buildApprovalResponse(req, false, "rejected by user")
	if err != nil {
		t.Fatalf("buildApprovalResponse() error = %v", err)
	}
	reject, ok := resp.(protocol.RejectEnrollmentMessage)
	if !ok {
		t.Fatalf("response type = %T, want protocol.RejectEnrollmentMessage", resp)
	}
	if reject.Type != protocol.MsgTypeRejectEnrollment || reject.ID != "enroll-1" || reject.Fingerprint != "SHA256:abc" {
		t.Fatalf("unexpected rejection: %#v", reject)
	}

	resp, err = buildApprovalResponse(req, true, "")
	if err != nil {
		t.Fatalf("buildApprovalResponse() error = %v", err)
	}
	approve, ok := resp.(protocol.ApproveEnrollmentMessage)
	if !ok {
		t.Fatalf("response type = %T, want protocol.ApproveEnrollmentMessage", resp)
	}
	if approve.Type != protocol.MsgTypeApproveEnrollment || approve.ID != "enroll-1" || approve.Fingerprint != "SHA256:abc" {
		t.Fatalf("unexpected approval: %#v", approve)
	}
}

func TestBuildApprovalResponseRejectsUnknownKind(t *testing.T) {
	_, err := buildApprovalResponse(approvalRequest{kind: approvalKind(99)}, true, "")
	if err == nil {
		t.Fatal("buildApprovalResponse() error = nil, want unknown-kind rejection")
	}
}

func TestDisplaySignRequestShowsViolations(t *testing.T) {
	req := &protocol.SignRequestMessage{
		Address:     "ADDR",
		Description: "test description",
		Violations: []protocol.PolicyViolation{{
			Field:    "RekeyTo",
			Value:    "SOMEADDR",
			Severity: "critical",
			Message:  "unexpected rekey",
		}},
	}

	rendered := captureStdout(t, func() { displaySignRequest(req, 1) })
	if !strings.Contains(rendered, "Policy warnings (1)") {
		t.Fatalf("displaySignRequest() output missing violations header:\n%s", rendered)
	}
	if !strings.Contains(rendered, "unexpected rekey") {
		t.Fatalf("displaySignRequest() output missing violation message:\n%s", rendered)
	}
}

// A notice is listed under its own heading after the warnings and is not
// counted among them.
func TestDisplaySignRequestListsNoticesApart(t *testing.T) {
	req := &protocol.SignRequestMessage{
		Address:     "ADDR",
		Description: "test description",
		Violations: []protocol.PolicyViolation{
			{Field: "CloseRemainderTo", Value: "OTHER", Severity: protocol.ViolationSeverityCritical, Message: "closes the account"},
			{Field: "RekeyTo", Value: "HELD", Severity: protocol.ViolationSeverityNotice, Message: "This signer holds the aplane key for the new address."},
		},
	}
	rendered := captureStdout(t, func() { displaySignRequest(req, 1) })
	warnings, notes := strings.Index(rendered, "Policy warnings (1):"), strings.Index(rendered, "Notes (1):")
	if warnings < 0 || notes < warnings || !strings.Contains(rendered, "[NOTICE] This signer holds the aplane key") {
		t.Fatalf("displaySignRequest() does not list the notice after the warnings:\n%s", rendered)
	}
}

// captureStdout returns what fn prints.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()
	fn()
	_ = w.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	return out.String()
}

// apapprover shows the rounds a request can be submitted in, as apadmin
// does, and nothing when the signer sent none.
func TestDisplaySignRequestShowsValidityWindow(t *testing.T) {
	rendered := captureStdout(t, func() {
		displaySignRequest(&protocol.SignRequestMessage{Address: "ADDR", Description: "desc", FirstValid: 100, LastValid: 1100}, 1)
	})
	if !strings.Contains(rendered, "Valid Rounds: 100 - 1100 (window: 1000 blocks)") {
		t.Fatalf("displaySignRequest() output missing the validity window:\n%s", rendered)
	}
	rendered = captureStdout(t, func() {
		displaySignRequest(&protocol.SignRequestMessage{Address: "ADDR", Description: "desc"}, 1)
	})
	if strings.Contains(rendered, "Valid Rounds") {
		t.Fatalf("displaySignRequest() shows a window the signer did not send:\n%s", rendered)
	}
}

func TestParseApprovalInput(t *testing.T) {
	tests := []struct {
		input        string
		wantApproved bool
		wantCode     string
		wantReason   string
		wantOK       bool
	}{
		{input: "y", wantApproved: true, wantOK: true},
		{input: "y 0427", wantApproved: true, wantCode: "0427", wantOK: true},
		{input: "YES 0427", wantApproved: true, wantCode: "0427", wantOK: true},
		{input: "y 0427 extra", wantOK: false},
		{input: "n", wantApproved: false, wantReason: "rejected by user", wantOK: true},
		{input: "no suspicious destination", wantApproved: false, wantReason: "suspicious destination", wantOK: true},
		{input: "n policy violation", wantApproved: false, wantReason: "policy violation", wantOK: true},
		{input: "maybe", wantOK: false},
	}
	for _, tt := range tests {
		gotApproved, gotCode, gotReason, gotOK := parseApprovalInput(tt.input)
		if gotApproved != tt.wantApproved || gotCode != tt.wantCode || gotReason != tt.wantReason || gotOK != tt.wantOK {
			t.Fatalf("parseApprovalInput(%q) = (%v, %q, %q, %v), want (%v, %q, %q, %v)",
				tt.input, gotApproved, gotCode, gotReason, gotOK, tt.wantApproved, tt.wantCode, tt.wantReason, tt.wantOK)
		}
	}
}

func TestDecodeNotificationSignRequest(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.SignRequestMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignRequest, ID: "sign-1"},
		Address:     "ADDR",
		TxnSender:   "SENDER",
		Description: "desc",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}

	decoded, handled, err := decodeNotification(transport.Notification{
		Base: protocol.BaseMessage{Type: protocol.MsgTypeSignRequest},
		Raw:  raw,
	})
	if err != nil {
		t.Fatalf("decodeNotification() error = %v", err)
	}
	if !handled {
		t.Fatal("decodeNotification() handled = false, want true")
	}
	if decoded.request == nil || decoded.request.kind != approvalKindSign || decoded.request.signRequest == nil {
		t.Fatalf("decoded.request = %#v, want sign approval request", decoded.request)
	}
	if decoded.request.signRequest.ID != "sign-1" || decoded.request.signRequest.Address != "ADDR" {
		t.Fatalf("decoded sign request = %#v", decoded.request.signRequest)
	}
}

// apapprover prints a request with fmt.Printf, so it escapes the request
// where it decodes it, even though the signer already did.
func TestDecodeNotificationSignRequestEscapesText(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.SignRequestMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignRequest, ID: "sign-1"},
		Address:     "ADDR\x1b[2J",
		Description: "Method: x\x1b[2J\r\n  To:   FRIEND",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	decoded, _, err := decodeNotification(transport.Notification{Base: protocol.BaseMessage{Type: protocol.MsgTypeSignRequest}, Raw: raw})
	if err != nil {
		t.Fatalf("decodeNotification() error = %v", err)
	}
	req := decoded.request.signRequest
	if req.Address != `ADDR\x1b[2J` || req.Description != "Method: x\\x1b[2J\\r\n  To:   FRIEND" {
		t.Fatalf("decoded sign request was not escaped: %#v", req)
	}
}

func TestDecodeNotificationSignRequestCanceled(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.SignRequestCanceledMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignRequestCanceled, ID: "sign-1"},
		Reason:      "client_canceled",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}

	decoded, handled, err := decodeNotification(transport.Notification{
		Base: protocol.BaseMessage{Type: protocol.MsgTypeSignRequestCanceled},
		Raw:  raw,
	})
	if err != nil {
		t.Fatalf("decodeNotification() error = %v", err)
	}
	if !handled {
		t.Fatal("decodeNotification() handled = false, want true")
	}
	if decoded.canceled == nil {
		t.Fatal("decoded.canceled = nil, want cancellation")
	}
	if decoded.canceled.ID != "sign-1" || decoded.canceled.Reason != "client_canceled" {
		t.Fatalf("decoded cancellation = %#v", decoded.canceled)
	}
}

func TestDecodeNotificationMalformedSignRequest(t *testing.T) {
	_, handled, err := decodeNotification(transport.Notification{
		Base: protocol.BaseMessage{Type: protocol.MsgTypeSignRequest},
		Raw:  []byte(`{"kind":"notification","type":"sign_request","address":`),
	})
	if !handled {
		t.Fatal("decodeNotification() handled = false, want true")
	}
	if err == nil || !strings.Contains(err.Error(), "malformed sign request") {
		t.Fatalf("decodeNotification() error = %v, want malformed sign request", err)
	}
}

func TestRemoveCanceledSignRequest(t *testing.T) {
	queue := []approvalRequest{
		{
			kind: approvalKindSign,
			signRequest: &protocol.SignRequestMessage{
				BaseMessage: protocol.BaseMessage{ID: "sign-1"},
			},
		},
		{
			kind: approvalKindClientEnrollment,
			enrollmentRequest: &protocol.ClientEnrollmentRequestMessage{
				BaseMessage: protocol.BaseMessage{ID: "token-1"},
			},
		},
		{
			kind: approvalKindSign,
			signRequest: &protocol.SignRequestMessage{
				BaseMessage: protocol.BaseMessage{ID: "sign-2"},
			},
		},
	}

	next, removed, active := removeCanceledRequest(queue, "sign-2")
	if !removed {
		t.Fatal("removed = false, want true")
	}
	if active {
		t.Fatal("active = true, want false for queued request")
	}
	if len(next) != 2 {
		t.Fatalf("queue length = %d, want 2", len(next))
	}
	if next[0].signRequest.ID != "sign-1" || next[1].enrollmentRequest.ID != "token-1" {
		t.Fatalf("queue after removal = %#v", next)
	}

	next, removed, active = removeCanceledRequest(next, "sign-1")
	if !removed || !active {
		t.Fatalf("removed, active = %v, %v; want true, true", removed, active)
	}
	if len(next) != 1 || next[0].enrollmentRequest.ID != "token-1" {
		t.Fatalf("queue after active removal = %#v", next)
	}

	unchanged, removed, active := removeCanceledRequest(next, "missing")
	if removed || active {
		t.Fatalf("removed, active = %v, %v; want false, false", removed, active)
	}
	if len(unchanged) != 1 || unchanged[0].enrollmentRequest.ID != "token-1" {
		t.Fatalf("queue after missing removal = %#v", unchanged)
	}
}

func TestDecodeNotificationClientEnrollmentRequest(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.ClientEnrollmentRequestMessage{
		BaseMessage:    protocol.BaseMessage{Type: protocol.MsgTypeClientEnrollmentRequest, ID: "token-1"},
		SSHFingerprint: "fp",
		RemoteAddr:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}

	decoded, handled, err := decodeNotification(transport.Notification{
		Base: protocol.BaseMessage{Type: protocol.MsgTypeClientEnrollmentRequest},
		Raw:  raw,
	})
	if err != nil {
		t.Fatalf("decodeNotification() error = %v", err)
	}
	if !handled {
		t.Fatal("decodeNotification() handled = false, want true")
	}
	if decoded.request == nil || decoded.request.kind != approvalKindClientEnrollment || decoded.request.enrollmentRequest == nil {
		t.Fatalf("decoded.request = %#v, want token provisioning request", decoded.request)
	}
	if decoded.request.enrollmentRequest.ID != "token-1" {
		t.Fatalf("decoded token request = %#v", decoded.request.enrollmentRequest)
	}
}

func TestDecodeNotificationErrorMessage(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError},
		Error:       "boom",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}

	decoded, handled, err := decodeNotification(transport.Notification{
		Base: protocol.BaseMessage{Type: protocol.MsgTypeError},
		Raw:  raw,
	})
	if err != nil {
		t.Fatalf("decodeNotification() error = %v", err)
	}
	if !handled {
		t.Fatal("decodeNotification() handled = false, want true")
	}
	if decoded.errMsg == nil || decoded.errMsg.Error != "boom" {
		t.Fatalf("decoded.errMsg = %#v, want error message boom", decoded.errMsg)
	}
}

func signApproval(id string) approvalRequest {
	return approvalRequest{kind: approvalKindSign, signRequest: &protocol.SignRequestMessage{BaseMessage: protocol.BaseMessage{ID: id}}}
}

func enrollmentApproval(id string) approvalRequest {
	return approvalRequest{kind: approvalKindClientEnrollment, enrollmentRequest: &protocol.ClientEnrollmentRequestMessage{BaseMessage: protocol.BaseMessage{ID: id}}}
}

// The operator answers the head of the queue; a failed send keeps the
// request so the operator can retry, and invalid input changes nothing.
// enrollmentReply answers enrollment requests the way the signer does, with
// a correlated result, recording what was asked.
func enrollmentReply(t *testing.T, sent *[]any, fail string) func(any) ([]byte, error) {
	t.Helper()
	return func(v any) ([]byte, error) {
		*sent = append(*sent, v)
		var reply any
		switch msg := v.(type) {
		case protocol.ApproveEnrollmentMessage:
			reply = protocol.ApproveEnrollmentResultMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApproveEnrollmentResult, ID: msg.ID}, Success: fail == "", Error: fail, Fingerprint: msg.Fingerprint, Label: "laptop"}
		case protocol.RejectEnrollmentMessage:
			reply = protocol.RejectEnrollmentResultMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRejectEnrollmentResult, ID: msg.ID}, Success: fail == "", Error: fail, Fingerprint: msg.Fingerprint}
		default:
			t.Fatalf("unexpected enrollment answer %T", v)
		}
		raw, err := protocol.MarshalAdminMessage(reply)
		if err != nil {
			t.Fatal(err)
		}
		return raw, nil
	}
}

func TestApproverAnswersHeadOfQueue(t *testing.T) {
	var sent []any
	sendErr := error(nil)
	a := &approver{send: func(v any) error {
		if sendErr != nil {
			return sendErr
		}
		sent = append(sent, v)
		return nil
	}}
	a.answer = enrollmentReply(t, &sent, "")
	a.enqueue(signApproval("sign-1"))
	a.enqueue(enrollmentApproval("token-1"))

	a.handleInput("maybe")
	if len(sent) != 0 || len(a.queue) != 2 {
		t.Fatalf("invalid input sent %d responses, queue %d; want none sent, 2 queued", len(sent), len(a.queue))
	}

	sendErr = os.ErrClosed
	a.handleInput("y " + a.headCode)
	if len(a.queue) != 2 {
		t.Fatalf("queue after failed send = %d, want the request kept", len(a.queue))
	}

	sendErr = nil
	a.handleInput("y " + a.headCode)
	if len(sent) != 1 || len(a.queue) != 1 || a.queue[0].id() != "token-1" {
		t.Fatalf("after approval: sent %d, queue %+v; want sign-1 answered and token-1 next", len(sent), a.queue)
	}
	resp, ok := sent[0].(protocol.SignResponseMessage)
	if !ok || resp.ID != "sign-1" || !resp.Approved {
		t.Fatalf("response = %#v, want approval of sign-1", sent[0])
	}

	a.handleInput("n not today")
	if len(sent) != 2 || len(a.queue) != 0 {
		t.Fatalf("after rejection: sent %d, queue %d; want token-1 answered and queue empty", len(sent), len(a.queue))
	}
}

// A withdrawal removes only the matching request; answering continues with
// the next one.
func TestApproverWithdrawnRequestLeavesQueue(t *testing.T) {
	var sent []any
	a := &approver{send: func(v any) error { sent = append(sent, v); return nil }}
	a.answer = enrollmentReply(t, &sent, "")
	a.enqueue(enrollmentApproval("enroll-1"))
	a.enqueue(signApproval("sign-1"))
	// An enrollment request announced again (as at login) is not queued twice.
	a.enqueue(enrollmentApproval("enroll-1"))
	if len(a.queue) != 2 {
		t.Fatalf("queue after a repeated announcement = %d, want 2", len(a.queue))
	}

	a.handleCanceled("enroll-1", "")
	if len(a.queue) != 2 {
		t.Fatalf("queue after a cancellation of another kind = %d, want 2", len(a.queue))
	}
	a.handleCanceled("sign-1", "")
	if len(a.queue) != 1 || a.queue[0].id() != "enroll-1" {
		t.Fatalf("queue after withdrawal = %+v, want only enroll-1", a.queue)
	}
	a.handleInput("y " + a.headCode)
	if len(sent) != 1 || len(a.queue) != 0 {
		t.Fatalf("after answering: sent %d, queue %d", len(sent), len(a.queue))
	}
	if _, ok := sent[0].(protocol.ApproveEnrollmentMessage); !ok {
		t.Fatalf("sent %T, want an enrollment approval", sent[0])
	}
}

// An enrollment answer is a correlated request: a refused result (the
// request was answered elsewhere, or the registry write failed) is final
// and the request leaves the queue, while a delivery failure keeps it so the
// operator can retry. The signer's verdict is what is printed, not the
// operator's intent.
func TestApproverEnrollmentAnswerFollowsTheSignersVerdict(t *testing.T) {
	var sent []any
	a := &approver{send: func(v any) error { t.Fatal("signing send used for an enrollment answer"); return nil }}
	a.answer = func(any) ([]byte, error) { return nil, os.ErrClosed }
	a.enqueue(enrollmentApproval("enroll-1"))
	a.handleInput("y " + a.headCode)
	if len(a.queue) != 1 {
		t.Fatalf("queue after a failed delivery = %d, want the request kept", len(a.queue))
	}

	a.answer = enrollmentReply(t, &sent, "no enrollment request is waiting for key SHA256:one")
	a.handleInput("y " + a.headCode)
	if len(sent) != 1 || len(a.queue) != 0 {
		t.Fatalf("after a refused approval: sent %d, queue %d; want the answer delivered and the request settled", len(sent), len(a.queue))
	}
	outcome, err := decodeEnrollmentOutcome(mustMarshal(t, protocol.ApproveEnrollmentResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeApproveEnrollmentResult, ID: "enroll-1"},
		Error:       "registry not durable",
		Fingerprint: "SHA256:one",
	}), "SHA256:one", true)
	if err != nil || outcome.success || !strings.Contains(outcome.String(), "Approval of SHA256:one failed: registry not durable") {
		t.Fatalf("refused approval outcome = %q, %v", outcome, err)
	}
	outcome, err = decodeEnrollmentOutcome(mustMarshal(t, protocol.RejectEnrollmentResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRejectEnrollmentResult, ID: "enroll-1"},
		Success:     true,
		Fingerprint: "SHA256:one",
	}), "SHA256:one", false)
	if err != nil || !outcome.success || !strings.Contains(outcome.String(), "Enrollment request for SHA256:one rejected") {
		t.Fatalf("rejection outcome = %q, %v", outcome, err)
	}
	outcome, err = decodeEnrollmentOutcome(mustMarshal(t, protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError, ID: "enroll-1"},
		Error:       "not permitted",
	}), "SHA256:one", true)
	if err != nil || outcome.success || !strings.Contains(outcome.String(), "not permitted") {
		t.Fatalf("protocol error outcome = %q, %v", outcome, err)
	}
	if _, err := decodeEnrollmentOutcome(mustMarshal(t, protocol.StatusMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeStatus}}), "SHA256:one", true); err == nil {
		t.Fatal("an unrelated reply must be rejected")
	}
}

func mustMarshal(t *testing.T, msg any) []byte {
	t.Helper()
	raw, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// An approval must carry the code of the request on screen. A "y" typed for a
// request the requester withdrew, and sent once its replacement is shown,
// cannot approve the replacement. Rejection needs no code.
func TestApproverApprovalNamesTheRequestShown(t *testing.T) {
	var sent []any
	codes := []string{"1111", "1111", "2222", "3333"}
	a := &approver{
		send: func(v any) error { sent = append(sent, v); return nil },
		newCode: func() string {
			c := codes[0]
			codes = codes[1:]
			return c
		},
	}
	a.enqueue(signApproval("prompt-a"))
	codeA := a.headCode

	// The operator types the approval for A; before Enter, the requester
	// withdraws A and sends B.
	a.handleCanceled("prompt-a", "client_canceled")
	a.enqueue(signApproval("prompt-b"))
	if a.headCode == codeA {
		t.Fatalf("replacement reused code %s", codeA)
	}
	a.handleInput("y " + codeA)
	if len(sent) != 0 || len(a.queue) != 1 {
		t.Fatalf("approval with the withdrawn request's code: sent %d, queue %d; want nothing sent", len(sent), len(a.queue))
	}
	a.handleInput("y")
	if len(sent) != 0 {
		t.Fatal("approval without a code was accepted")
	}

	a.handleInput("y " + a.headCode)
	if len(sent) != 1 || len(a.queue) != 0 {
		t.Fatalf("approval with the shown code: sent %d, queue %d", len(sent), len(a.queue))
	}
	if resp := sent[0].(protocol.SignResponseMessage); resp.ID != "prompt-b" || !resp.Approved {
		t.Fatalf("response = %#v, want approval of prompt-b", resp)
	}

	a.enqueue(signApproval("prompt-c"))
	a.handleInput("n")
	if len(sent) != 2 || sent[1].(protocol.SignResponseMessage).Approved {
		t.Fatalf("rejection needed a code or became an approval: %#v", sent)
	}
}

// A warning about a value names it; one about the request as a whole, such as
// lookalike accounts, is its message alone, with no dangling "=".
func TestViolationLineNamesOnlyAValue(t *testing.T) {
	for _, tc := range []struct {
		v    protocol.PolicyViolation
		want string
	}{
		{protocol.PolicyViolation{Severity: "critical", Field: "RekeyTo", Value: "ADDR", Message: "control moves"}, "  - [CRITICAL] control moves (RekeyTo=ADDR)"},
		{protocol.PolicyViolation{Severity: "warning", Field: "Lookalike accounts", Message: "two accounts look alike"}, "  - [WARNING] two accounts look alike"},
		{protocol.PolicyViolation{Severity: "warning", Value: "9", Message: "odd"}, "  - [WARNING] odd (9)"},
	} {
		if got := violationLine(tc.v); got != tc.want {
			t.Errorf("violationLine(%+v) = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// A request's text longer than the terminal is wide is cut into pieces each
// marked as a continuation, so no value from the request can wrap onto a
// line it starts, and read like a field of its own.
func TestConfinedLinesMarkEveryContinuation(t *testing.T) {
	line := "  URL: " + strings.Repeat("a", 70) + "To:      EVILADDRESS"
	pieces := confinedLines(line, 80)
	if len(pieces) != 2 || pieces[1] != continuationMark+"      EVILADDRESS" {
		t.Fatalf("confinedLines = %q", pieces)
	}
	wide := strings.Repeat("漢字", 50)
	pieces = confinedLines(wide, 21)
	var joined strings.Builder
	for i, piece := range pieces {
		if ansi.StringWidth(piece) > 21 {
			t.Errorf("piece %q is %d columns", piece, ansi.StringWidth(piece))
		}
		if i > 0 && !strings.HasPrefix(piece, continuationMark) {
			t.Errorf("piece %d %q is not marked", i, piece)
		}
		joined.WriteString(strings.TrimPrefix(piece, continuationMark))
	}
	if joined.String() != wide {
		t.Errorf("the pieces do not make up the line")
	}
}

// A client's label is shown quoted in ASCII on its own field's row, and
// each field is one row at every width: no label can drive the terminal or
// draw a line that reads like the key's fingerprint or address.
func TestEnrollmentRequestLabelCannotImitateAField(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	for _, label := range []string{
		"laptop-of-ops SHA256:FakeFakeFakeFakeFakeFakeFakeFakeFakeFake123",
		"x Remote Addr: 10.0.0.5:22",
		"bidi \u202e and C1 \u0085 and \xff",
		strings.Repeat(`\`, 33) + " SHA256:FakeFakeFake",
		"a SHA256:ExpectedLaptopKeyA\\\u2e3bpKeyAbCdEfGhIjKlMnOpQrStUvWxYz012",
		"\u7530\u4e2d\u306e\u30ce\u30fc\u30c8PC",
	} {
		for _, width := range []int{80, 81, 120, 200} {
			rendered := captureStdout(t, func() {
				displayClientEnrollmentRequest(&protocol.ClientEnrollmentRequestMessage{
					SSHFingerprint: fingerprint, Label: label, RemoteAddr: "203.0.113.9:51234",
				}, 1, width)
			})
			name := fmt.Sprintf("label %q width %d", label, width)
			labelRows := 0
			for _, line := range strings.Split(rendered, "\n") {
				if len(line) > width && !strings.HasPrefix(line, "\U0001f511") {
					t.Errorf("%s: line wider than the terminal: %q", name, line)
				}
				switch {
				case strings.HasPrefix(line, `Label:       "`):
					labelRows++
					if !strings.HasSuffix(line, `"`) || strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
						t.Errorf("%s: the label row is not one ASCII quoted row: %q", name, line)
					}
				case strings.Contains(line, "SHA256:") && line != "SSH Key:     "+fingerprint,
					strings.Contains(line, "Remote Addr:") && line != "Remote Addr: 203.0.113.9:51234":
					t.Errorf("%s: a line that reads like a field: %q", name, line)
				}
			}
			if labelRows != 1 {
				t.Errorf("%s: %d label rows:\n%s", name, labelRows, rendered)
			}
			if fits := len(strconv.QuoteToASCII(label)) <= width-13; fits && !strings.Contains(rendered, "Label:       "+strconv.QuoteToASCII(label)+"\n") {
				t.Errorf("%s: the label is not quoted in ASCII:\n%s", name, rendered)
			}
		}
	}
}

// useTerminalWidth makes the terminal width columns for the test.
func useTerminalWidth(t *testing.T, columns *int) {
	t.Helper()
	saved := terminalWidth
	terminalWidth = func() int { return *columns }
	t.Cleanup(func() { terminalWidth = saved })
}

// On a terminal narrower than 80 columns apapprover shows which request
// waits, its identity whole, and takes no answer, approval or rejection,
// since a field row would be cut short of what the operator must check. A
// request shown that way is shown whole, with a fresh code, once the
// terminal is wide enough, before any answer is taken.
func TestApproverTakesNoAnswerOnANarrowTerminal(t *testing.T) {
	const fingerprint = "SHA256:RealRealRealRealRealRealRealRealRealReal123"
	requests := map[string]approvalRequest{
		"enrollment": {kind: approvalKindClientEnrollment, enrollmentRequest: &protocol.ClientEnrollmentRequestMessage{
			BaseMessage: protocol.BaseMessage{ID: "token-1"}, SSHFingerprint: fingerprint, Label: "laptop", RemoteAddr: "[2001:db8::1]:51234"}},
		"signing": {kind: approvalKindSign, signRequest: &protocol.SignRequestMessage{
			BaseMessage: protocol.BaseMessage{ID: "sign-1"}, Address: "SGCU7MLRXQ4H227YCRTTT6MHL2N64WGJPHH3OTPID2CK4JNGJU6DITLIUQ", Description: "Payment"}},
	}
	for name, req := range requests {
		for _, width := range []int{20, 60, 79, 80} {
			columns := width
			useTerminalWidth(t, &columns)
			var sent []any
			a := &approver{send: func(v any) error { sent = append(sent, v); return nil }}
			a.answer = enrollmentReply(t, &sent, "")
			shown := captureStdout(t, func() { a.enqueue(req) })
			code := a.headCode
			out := captureStdout(t, func() {
				a.handleInput("y " + code)
				a.handleInput("n")
			})
			if width < minReviewWidth {
				identity := fingerprint
				if req.signRequest != nil {
					identity = req.signRequest.Address
				}
				if !strings.Contains(shown, identity+"\n") || !strings.Contains(shown, terminalTooNarrow) || strings.Contains(shown, "Approve current request?") {
					t.Errorf("%s at %d columns: shown as:\n%s", name, width, shown)
				}
				if len(sent) != 0 || len(a.queue) != 1 || strings.Count(out, terminalTooNarrow) != 2 {
					t.Errorf("%s at %d columns: an answer was taken: sent %v, output:\n%s", name, width, sent, out)
				}
				// Widened, the first line shows the request whole with a
				// fresh code; only then is an answer taken.
				columns = minReviewWidth
				reshown := captureStdout(t, func() { a.handleInput("y " + code) })
				if len(sent) != 0 || a.headCode == code || !strings.Contains(reshown, "Approve current request?") {
					t.Errorf("%s widened: answered or not shown whole: sent %v:\n%s", name, sent, reshown)
				}
				code = a.headCode
				_ = captureStdout(t, func() { a.handleInput("y " + code) })
			}
			if len(sent) != 1 || len(a.queue) != 0 {
				t.Errorf("%s at %d columns: the approval was not taken once wide enough: sent %v", name, width, sent)
			}
		}
	}
}

// The line reporting an enrollment names the label quoted in ASCII and cut
// to 32 columns: whole, it runs on past 80 columns and could start a line
// reading like the next request's key, and a label queued before labels were
// ASCII could reach the terminal with its controls.
func TestEnrollmentOutcomeQuotesAndCutsTheLabel(t *testing.T) {
	for _, label := range []string{
		"x SSH Key:     SHA256:ExpectedLaptopKeyAbCdEfGhIjKlMnOpQrStUv",
		"laptop\u202e\u0085\u7530",
	} {
		line := enrollmentOutcome{approved: true, success: true, fingerprint: "SHA256:one", label: label}.String()
		if want := "✓ Client key SHA256:one enrolled (" + termsafe.ResultLabel(label) + ")"; line != want {
			t.Errorf("outcome for %+q = %q, want %q", label, line, want)
		}
	}
}
