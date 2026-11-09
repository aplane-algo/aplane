// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"strings"
	"testing"
)

func TestAssemblyRequestValidatesDiscriminatedTargetsAndCoverage(t *testing.T) {
	valid := AssemblyRequest{
		RequestID: "asm-1", GroupBytesHex: []string{"5458aa", "5458bb", "5458cc"},
		Targets: []AssemblyTarget{
			{TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "PLAIN", BaseSignatures: []string{"aa"}, AssemblyReceipt: "bb", CosignerSignature: "bb"},
			{TargetIndex: 1, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED", BaseSignatures: []string{"cc"}, AssemblyReceipt: "dd", CosignerSignature: "ee"},
		},
		Passthrough: []AssemblyPassthroughItem{{TargetIndex: 2, SignedTxnHex: "ff"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	tests := []struct {
		name string
		edit func(*AssemblyRequest)
		want string
	}{
		{"duplicate index", func(r *AssemblyRequest) { r.Passthrough[0].TargetIndex = 1 }, "duplicate"},
		{"coverage gap", func(r *AssemblyRequest) { r.Passthrough = nil }, "not covered"},
		{"no base signatures", func(r *AssemblyRequest) { r.Targets[0].BaseSignatures = nil }, "base_signatures and assembly_receipt are required"},
		{"no receipt", func(r *AssemblyRequest) { r.Targets[1].AssemblyReceipt = "" }, "base_signatures and assembly_receipt are required"},
		{"unknown kind", func(r *AssemblyRequest) { r.Targets[0].Kind = "future" }, "kind must be"},
		{"the retired guarded kind", func(r *AssemblyRequest) { r.Targets[0].Kind = "guarded" }, "kind must be"},
		{"a cosigner request ID without its signature", func(r *AssemblyRequest) {
			r.Targets[1].CosignerSignature, r.Targets[1].CosignerSourceRequestID = "", "cosigner-1"
		}, "cosigner_source_request_id needs a cosigner_signature"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			request.Targets = append([]AssemblyTarget(nil), valid.Targets...)
			request.Passthrough = append([]AssemblyPassthroughItem(nil), valid.Passthrough...)
			test.edit(&request)
			if err := request.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want %q", err, test.want)
			}
		})
	}
}

// A listed rekey on a cosigned account carries no cosigner signature; whether a
// bounded target needs one is assembly's to decide from the transaction.
func TestAssemblyRequestLeavesTheCosignerToBoundedAssembly(t *testing.T) {
	req := AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []AssemblyTarget{{TargetIndex: 0, Kind: AssemblyTargetKindBoundedCosigner, AuthAddress: "BOUNDED", BaseSignatures: []string{"cc"}, AssemblyReceipt: "dd"}},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestAssemblyRequestAllowsPassthroughOnly(t *testing.T) {
	req := AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Passthrough:   []AssemblyPassthroughItem{{TargetIndex: 0, SignedTxnHex: "aa"}},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
