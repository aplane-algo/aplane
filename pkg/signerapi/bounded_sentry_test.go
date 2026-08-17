// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "testing"

func TestBoundedAssemblyRequestValidate(t *testing.T) {
	valid := BoundedAssemblyRequest{
		RequestID: "basm-1", GroupBytesHex: []string{"5458aa", "5458bb"},
		Targets: []BoundedAssemblyTarget{{
			TargetIndex: 0, BoundedAccount: "ACCOUNT", BaseSignatures: []string{"aa"},
			AssemblyReceipt: "bb", SentrySignature: "cc",
		}},
		Passthrough: []GuardedPassthroughItem{{TargetIndex: 1, SignedTxnHex: "dd"}},
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	tests := []struct {
		name string
		edit func(*BoundedAssemblyRequest)
	}{
		{"empty coverage", func(r *BoundedAssemblyRequest) { r.Targets = nil; r.Passthrough = nil }},
		{"missing receipt", func(r *BoundedAssemblyRequest) { r.Targets[0].AssemblyReceipt = "" }},
		{"duplicate coverage", func(r *BoundedAssemblyRequest) { r.Passthrough[0].TargetIndex = 0 }},
		{"uncovered", func(r *BoundedAssemblyRequest) { r.Passthrough = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			request.Targets = append([]BoundedAssemblyTarget(nil), valid.Targets...)
			request.Passthrough = append([]GuardedPassthroughItem(nil), valid.Passthrough...)
			test.edit(&request)
			if err := request.Validate(); err == nil {
				t.Fatal("Validate() error = nil")
			}
		})
	}
}
