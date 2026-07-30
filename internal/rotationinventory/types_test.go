// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotationinventory

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto"
)

func TestValidateEntriesCanonicalContract(t *testing.T) {
	valid := []Entry{
		{
			Path:           "identities/default/generations/gen-1-0badc0de/keys/A.key",
			Kind:           KindAccountKey,
			Size:           1,
			SHA256:         strings.Repeat("a", 64),
			Term:           1,
			ObjectClass:    crypto.ClassAccountKey,
			ObjectSelector: "A",
		},
		{
			Path:   "identities/default/policy.yaml",
			Kind:   KindPolicyDocument,
			Size:   1,
			SHA256: strings.Repeat("b", 64),
		},
		{
			Path:   "identities/default/policy.yaml.hmac",
			Kind:   KindPolicySidecar,
			Size:   1,
			SHA256: strings.Repeat("c", 64),
			Term:   1,
		},
	}
	if err := ValidateEntries(valid); err != nil {
		t.Fatalf("ValidateEntries(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]Entry) []Entry
	}{
		{
			name: "unsorted",
			mutate: func(entries []Entry) []Entry {
				entries[0], entries[1] = entries[1], entries[0]
				return entries
			},
		},
		{
			name: "duplicate",
			mutate: func(entries []Entry) []Entry {
				entries[1].Path = entries[0].Path
				return entries
			},
		},
		{
			name: "noncanonical path",
			mutate: func(entries []Entry) []Entry {
				entries[0].Path = "identities/default/../escape"
				return entries
			},
		},
		{
			name: "uppercase digest",
			mutate: func(entries []Entry) []Entry {
				entries[0].SHA256 = strings.Repeat("A", 64)
				return entries
			},
		},
		{
			name: "missing envelope term",
			mutate: func(entries []Entry) []Entry {
				entries[0].Term = 0
				return entries
			},
		},
		{
			name: "wrong envelope class",
			mutate: func(entries []Entry) []Entry {
				entries[0].ObjectClass = crypto.ClassSentryCredential
				return entries
			},
		},
		{
			name: "plaintext with term",
			mutate: func(entries []Entry) []Entry {
				entries[1].Term = 1
				return entries
			},
		},
		{
			name: "sidecar with context",
			mutate: func(entries []Entry) []Entry {
				entries[2].ObjectClass = crypto.ClassAccountKey
				entries[2].ObjectSelector = "A"
				return entries
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries := append([]Entry(nil), valid...)
			if err := ValidateEntries(tt.mutate(entries)); err == nil {
				t.Fatal("ValidateEntries() error = nil, want rejection")
			}
		})
	}
}
