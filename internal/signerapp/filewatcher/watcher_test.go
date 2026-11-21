// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package filewatcher

import "testing"

func TestIsReloadCandidate(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"account.key", true},
		{"cosigner.cos", true},
		{"policy.template", true},
		{"cosigner.cos.json", false},
		{"notes.json", false},
		{"store-root.enc", true},
		// Source token files are the daemon's own writes, never a reason to
		// reload.
		{"source_tokens/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.enc", false},
		{"source_tokens/default.enc", false},
		{"deleted/source_tokens/MYJZE3UF7G4JXR5STMQK5TSL5FNE7PE224BSKLZ2H4AJWJIPBEBQ.enc", false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := isReloadCandidate(test.path); got != test.want {
				t.Fatalf("isReloadCandidate(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}
