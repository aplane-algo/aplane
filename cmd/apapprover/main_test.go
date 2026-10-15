// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
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

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	displaySignRequest(req, 1)

	_ = w.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "Policy warnings (1)") {
		t.Fatalf("displaySignRequest() output missing violations header:\n%s", rendered)
	}
	if !strings.Contains(rendered, "unexpected rekey") {
		t.Fatalf("displaySignRequest() output missing violation message:\n%s", rendered)
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

	next, removed, active := removeCanceledRequest(queue, approvalKindSign, "sign-2")
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

	next, removed, active = removeCanceledRequest(next, approvalKindSign, "sign-1")
	if !removed || !active {
		t.Fatalf("removed, active = %v, %v; want true, true", removed, active)
	}
	if len(next) != 1 || next[0].enrollmentRequest.ID != "token-1" {
		t.Fatalf("queue after active removal = %#v", next)
	}

	unchanged, removed, active := removeCanceledRequest(next, approvalKindSign, "missing")
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

	a.handleCanceled(approvalKindSign, "Signing request", "enroll-1", "")
	if len(a.queue) != 2 {
		t.Fatalf("queue after a cancellation of another kind = %d, want 2", len(a.queue))
	}
	a.handleCanceled(approvalKindSign, "Signing request", "sign-1", "")
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
	a.handleCanceled(approvalKindSign, "Signing request", "prompt-a", "client_canceled")
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
