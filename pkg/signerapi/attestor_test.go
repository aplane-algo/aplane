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
		Role:          ComponentSignRoleAttestor,
		ComponentKey:  "attkey_abc",
		GroupBytesHex: []string{"5458aa"},
		TargetIndices: []int{0},
	}

	tests := []struct {
		name    string
		request ComponentSignRequest
		wantErr string
	}{
		{name: "valid attestor", request: valid},
		{name: "valid user", request: ComponentSignRequest{Role: ComponentSignRoleUser, ComponentKey: "ADDR", GroupBytesHex: []string{"5458aa"}, TargetIndices: []int{0}}},
		{name: "attestor may omit component key", request: ComponentSignRequest{Role: ComponentSignRoleAttestor, GroupBytesHex: []string{"5458aa"}, TargetIndices: []int{0}}},
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

func TestAttestedAssemblyRequestValidate(t *testing.T) {
	valid := AttestedAssemblyRequest{
		RequestID:     "asm-001",
		GroupBytesHex: []string{"5458aa", "5458bb"},
		Targets: []AttestedAssemblyTarget{{
			TargetIndex:       0,
			AttestedAccount:   "ADDR",
			UserSignature:     "aa",
			AttestorSignature: "bb",
		}},
		Passthrough: []AttestedPassthroughItem{{
			TargetIndex:  1,
			SignedTxnHex: "cc",
		}},
	}

	tests := []struct {
		name    string
		request AttestedAssemblyRequest
		wantErr string
	}{
		{name: "valid", request: valid},
		{name: "invalid request ID", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.RequestID = "bad id" }), wantErr: "request_id contains invalid character"},
		{name: "missing coverage", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.Passthrough = nil }), wantErr: "not covered"},
		{name: "duplicate coverage", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.Passthrough[0].TargetIndex = 0 }), wantErr: "duplicate"},
		{name: "missing target account", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.Targets[0].AttestedAccount = "" }), wantErr: "attested_account is required"},
		{name: "missing user signature", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.Targets[0].UserSignature = "" }), wantErr: "user_signature is required"},
		{name: "missing attestor signature", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.Targets[0].AttestorSignature = "" }), wantErr: "attestor_signature is required"},
		{name: "bad claimed source ID", request: withAssemblyRequest(valid, func(r *AttestedAssemblyRequest) { r.Targets[0].UserSourceRequestID = "bad id" }), wantErr: "user_source_request_id"},
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

func withComponentRequest(base ComponentSignRequest, mutate func(*ComponentSignRequest)) ComponentSignRequest {
	cp := base
	cp.GroupBytesHex = append([]string(nil), base.GroupBytesHex...)
	cp.TargetIndices = append([]int(nil), base.TargetIndices...)
	mutate(&cp)
	return cp
}

func withAssemblyRequest(base AttestedAssemblyRequest, mutate func(*AttestedAssemblyRequest)) AttestedAssemblyRequest {
	cp := base
	cp.GroupBytesHex = append([]string(nil), base.GroupBytesHex...)
	cp.Targets = append([]AttestedAssemblyTarget(nil), base.Targets...)
	cp.Passthrough = append([]AttestedPassthroughItem(nil), base.Passthrough...)
	mutate(&cp)
	return cp
}
