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

func TestBuildApprovalResponseForTokenProvisioning(t *testing.T) {
	req := approvalRequest{
		kind: approvalKindTokenProvisioning,
		tokenRequest: &protocol.TokenProvisioningRequestMessage{
			BaseMessage: protocol.BaseMessage{ID: "token-1"},
		},
	}

	resp, err := buildApprovalResponse(req, false, "rejected by user")
	if err != nil {
		t.Fatalf("buildApprovalResponse() error = %v", err)
	}
	tokenResp, ok := resp.(protocol.TokenProvisioningResponseMessage)
	if !ok {
		t.Fatalf("response type = %T, want protocol.TokenProvisioningResponseMessage", resp)
	}
	if tokenResp.Type != protocol.MsgTypeTokenProvisioningResponse {
		t.Fatalf("response type field = %q, want %q", tokenResp.Type, protocol.MsgTypeTokenProvisioningResponse)
	}
	if tokenResp.ID != "token-1" || tokenResp.Approved {
		t.Fatalf("unexpected token provisioning response: %#v", tokenResp)
	}
	if tokenResp.Reason != "rejected by user" {
		t.Fatalf("response reason = %q, want rejected by user", tokenResp.Reason)
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
		wantReason   string
		wantOK       bool
	}{
		{input: "y", wantApproved: true, wantOK: true},
		{input: "yes", wantApproved: true, wantOK: true},
		{input: "n", wantApproved: false, wantReason: "rejected by user", wantOK: true},
		{input: "no suspicious destination", wantApproved: false, wantReason: "suspicious destination", wantOK: true},
		{input: "n policy violation", wantApproved: false, wantReason: "policy violation", wantOK: true},
		{input: "maybe", wantOK: false},
	}
	for _, tt := range tests {
		gotApproved, gotReason, gotOK := parseApprovalInput(tt.input)
		if gotApproved != tt.wantApproved || gotReason != tt.wantReason || gotOK != tt.wantOK {
			t.Fatalf("parseApprovalInput(%q) = (%v, %q, %v), want (%v, %q, %v)",
				tt.input, gotApproved, gotReason, gotOK, tt.wantApproved, tt.wantReason, tt.wantOK)
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
			kind: approvalKindTokenProvisioning,
			tokenRequest: &protocol.TokenProvisioningRequestMessage{
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

	next, removed, active := removeCanceledSignRequest(queue, "sign-2")
	if !removed {
		t.Fatal("removed = false, want true")
	}
	if active {
		t.Fatal("active = true, want false for queued request")
	}
	if len(next) != 2 {
		t.Fatalf("queue length = %d, want 2", len(next))
	}
	if next[0].signRequest.ID != "sign-1" || next[1].tokenRequest.ID != "token-1" {
		t.Fatalf("queue after removal = %#v", next)
	}

	next, removed, active = removeCanceledSignRequest(next, "sign-1")
	if !removed || !active {
		t.Fatalf("removed, active = %v, %v; want true, true", removed, active)
	}
	if len(next) != 1 || next[0].tokenRequest.ID != "token-1" {
		t.Fatalf("queue after active removal = %#v", next)
	}

	unchanged, removed, active := removeCanceledSignRequest(next, "missing")
	if removed || active {
		t.Fatalf("removed, active = %v, %v; want false, false", removed, active)
	}
	if len(unchanged) != 1 || unchanged[0].tokenRequest.ID != "token-1" {
		t.Fatalf("queue after missing removal = %#v", unchanged)
	}
}

func TestDecodeNotificationTokenProvisioningRequest(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.TokenProvisioningRequestMessage{
		BaseMessage:    protocol.BaseMessage{Type: protocol.MsgTypeTokenProvisioningRequest, ID: "token-1"},
		SSHFingerprint: "fp",
		RemoteAddr:     "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}

	decoded, handled, err := decodeNotification(transport.Notification{
		Base: protocol.BaseMessage{Type: protocol.MsgTypeTokenProvisioningRequest},
		Raw:  raw,
	})
	if err != nil {
		t.Fatalf("decodeNotification() error = %v", err)
	}
	if !handled {
		t.Fatal("decodeNotification() handled = false, want true")
	}
	if decoded.request == nil || decoded.request.kind != approvalKindTokenProvisioning || decoded.request.tokenRequest == nil {
		t.Fatalf("decoded.request = %#v, want token provisioning request", decoded.request)
	}
	if decoded.request.tokenRequest.ID != "token-1" {
		t.Fatalf("decoded token request = %#v", decoded.request.tokenRequest)
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
