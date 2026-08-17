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
			{TargetIndex: 0, Kind: AssemblyTargetKindGuarded, AuthAddress: "GUARDED", UserSignature: "aa", SentrySignature: "bb"},
			{TargetIndex: 1, Kind: AssemblyTargetKindBoundedSentry, AuthAddress: "BOUNDED", BaseSignatures: []string{"cc"}, AssemblyReceipt: "dd", SentrySignature: "ee"},
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
		{"guarded carries bounded material", func(r *AssemblyRequest) { r.Targets[0].AssemblyReceipt = "wrong" }, "bounded authorization material is forbidden"},
		{"bounded carries guarded material", func(r *AssemblyRequest) { r.Targets[1].UserSignature = "wrong" }, "guarded authorization material is forbidden"},
		{"unknown kind", func(r *AssemblyRequest) { r.Targets[0].Kind = "future" }, "kind must be"},
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

func TestAssemblyRequestAllowsPassthroughOnly(t *testing.T) {
	req := AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Passthrough:   []AssemblyPassthroughItem{{TargetIndex: 0, SignedTxnHex: "aa"}},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
