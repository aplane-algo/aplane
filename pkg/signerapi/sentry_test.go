// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"strings"
	"testing"
)

func TestComponentSignRequestValidate(t *testing.T) {
	valid := ComponentSignRequest{
		RequestID:     "cli.abc_123:test",
		Role:          ComponentSignRoleSentry,
		ComponentKey:  "I5T6BSFAT7TXWGKF4TQLDR6U6PTAZJDLN54XTY7JLFSQETEJW3JA",
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	}

	tests := []struct {
		name    string
		request ComponentSignRequest
		wantErr string
	}{
		{name: "valid sentry", request: valid},
		{name: "valid user", request: ComponentSignRequest{Role: ComponentSignRoleUser, ComponentKey: "ADDR", GroupBytesHex: []string{"5458aa"}, TargetIndices: []int{0}}},
		{name: "sentry may omit Sentry Key ID", request: ComponentSignRequest{Role: ComponentSignRoleSentry, GroupBytesHex: []string{"5458aa"}, TargetIndices: []int{0}}},
		{name: "invalid request ID", request: withComponentRequest(valid, func(r *ComponentSignRequest) { r.RequestID = "bad id" }), wantErr: "request_id contains invalid character"},
		{name: "missing role", request: withComponentRequest(valid, func(r *ComponentSignRequest) { r.Role = "" }), wantErr: "role must be"},
		{name: "user missing key", request: ComponentSignRequest{Role: ComponentSignRoleUser, GroupBytesHex: []string{"5458aa"}, TargetIndices: []int{0}}, wantErr: "component_key is required"},
		{name: "empty group", request: withComponentRequest(valid, func(r *ComponentSignRequest) { r.GroupBytesHex = nil }), wantErr: "group_bytes_hex is empty"},
		{name: "empty targets", request: withComponentRequest(valid, func(r *ComponentSignRequest) { r.TargetIndices = nil }), wantErr: "target_indices is empty"},
		{name: "duplicate target", request: withComponentRequest(valid, func(r *ComponentSignRequest) { r.TargetIndices = []int{0, 0} }), wantErr: "duplicate"},
		{name: "out of range target", request: withComponentRequest(valid, func(r *ComponentSignRequest) { r.TargetIndices = []int{1} }), wantErr: "out of range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestGuardedAssemblyRequestValidate(t *testing.T) {
	valid := GuardedAssemblyRequest{
		RequestID:     "asm-001",
		GroupBytesHex: []string{"5458aa", "5458bb"},
		Targets: []GuardedAssemblyTarget{{
			TargetIndex:     0,
			GuardedAccount:  "ADDR",
			UserSignature:   "aa",
			SentrySignature: "bb",
		}},
		Passthrough: []GuardedPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: "cc",
		}},
	}

	tests := []struct {
		name    string
		request GuardedAssemblyRequest
		wantErr string
	}{
		{name: "valid", request: valid},
		{name: "invalid request ID", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.RequestID = "bad id" }), wantErr: "request_id contains invalid character"},
		{name: "missing coverage", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.Passthrough = nil }), wantErr: "not covered"},
		{name: "duplicate coverage", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.Passthrough[0].TargetIndex = 0 }), wantErr: "duplicate"},
		{name: "missing target account", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.Targets[0].GuardedAccount = "" }), wantErr: "guarded_account is required"},
		{name: "missing user signature", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.Targets[0].UserSignature = "" }), wantErr: "user_signature is required"},
		{name: "missing sentry signature", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.Targets[0].SentrySignature = "" }), wantErr: "sentry_signature is required"},
		{name: "bad claimed source ID", request: withAssemblyRequest(valid, func(r *GuardedAssemblyRequest) { r.Targets[0].UserSourceRequestID = "bad id" }), wantErr: "user_source_request_id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestGuardedSimulateRequestValidate(t *testing.T) {
	valid := GuardedSimulateRequest{
		RequestID: "gsim-001",
		Requests: []SignRequest{
			{TxnBytesHex: "5458aa"},
			{TxnBytesHex: "5458bb"},
			{TxnBytesHex: "5458cc", AuthAddress: "LOCAL"},
		},
		Targets: []GuardedSimulateTarget{{
			TargetIndex:     0,
			GuardedAccount:  "ADDR",
			SentrySignature: "bb",
		}},
		Passthrough: []GuardedPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: "cc",
		}},
	}

	tests := []struct {
		name    string
		request GuardedSimulateRequest
		wantErr string
	}{
		{name: "valid", request: valid},
		{name: "invalid request ID", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.RequestID = "bad id" }), wantErr: "request_id contains invalid character"},
		{name: "no targets", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Targets = nil }), wantErr: "targets is required"},
		{name: "missing txn bytes", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Requests[0].TxnBytesHex = "" }), wantErr: "txn_bytes_hex is required"},
		{name: "signed txn hex in request", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Requests[1].SignedTxnHex = "dd" }), wantErr: "use passthrough"},
		{name: "missing coverage", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Passthrough = nil }), wantErr: "not covered"},
		{name: "duplicate coverage", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Passthrough[0].TargetIndex = 0 }), wantErr: "duplicate"},
		{name: "missing target account", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Targets[0].GuardedAccount = "" }), wantErr: "guarded_account is required"},
		{name: "missing sentry signature", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Targets[0].SentrySignature = "" }), wantErr: "sentry_signature is required"},
		{name: "target overlaps sign mode", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Requests[0].AuthAddress = "X" }), wantErr: "must not also be a sign-mode request"},
		{name: "passthrough overlaps sign mode", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Requests[1].AuthAddress = "X" }), wantErr: "must not also be a sign-mode request"},
		{name: "bad sentry source ID", request: withSimulateRequest(valid, func(r *GuardedSimulateRequest) { r.Targets[0].SentrySourceRequestID = "bad id" }), wantErr: "sentry_source_request_id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func withSimulateRequest(base GuardedSimulateRequest, mutate func(*GuardedSimulateRequest)) GuardedSimulateRequest {
	cp := base
	cp.Requests = append([]SignRequest(nil), base.Requests...)
	cp.Targets = append([]GuardedSimulateTarget(nil), base.Targets...)
	cp.Passthrough = append([]GuardedPassthroughItem(nil), base.Passthrough...)
	mutate(&cp)
	return cp
}

func withComponentRequest(base ComponentSignRequest, mutate func(*ComponentSignRequest)) ComponentSignRequest {
	cp := base
	cp.GroupBytesHex = append([]string(nil), base.GroupBytesHex...)
	cp.TargetIndices = append([]int(nil), base.TargetIndices...)
	mutate(&cp)
	return cp
}

func withAssemblyRequest(base GuardedAssemblyRequest, mutate func(*GuardedAssemblyRequest)) GuardedAssemblyRequest {
	cp := base
	cp.GroupBytesHex = append([]string(nil), base.GroupBytesHex...)
	cp.Targets = append([]GuardedAssemblyTarget(nil), base.Targets...)
	cp.Passthrough = append([]GuardedPassthroughItem(nil), base.Passthrough...)
	mutate(&cp)
	return cp
}
