// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypefmt

import "testing"

func TestPublisher(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{name: "ed25519", keyType: "ed25519", want: ""},
		{name: "aplane falcon", keyType: "aplane.falcon1024.v1", want: "aplane"},
		{name: "other publisher", keyType: "custom.allowlist.v2", want: "custom"},
		{name: "filename unchanged", keyType: "test.generic-policy.v1.yaml", want: ""},
		{name: "missing publisher", keyType: "allowlist.v1", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Publisher(tt.keyType); got != tt.want {
				t.Fatalf("Publisher(%q) = %q, want %q", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestValidSegment(t *testing.T) {
	tests := []struct {
		segment string
		want    bool
	}{
		{segment: "aplane", want: true},
		{segment: "falcon1024-allowlist", want: true},
		{segment: "falcon1024_allowlist", want: true},
		{segment: "", want: false},
		{segment: "white.list", want: false},
		{segment: "white list", want: false},
		{segment: "Allowlist", want: false},
	}
	for _, tt := range tests {
		if got := ValidSegment(tt.segment); got != tt.want {
			t.Fatalf("ValidSegment(%q) = %v, want %v", tt.segment, got, tt.want)
		}
	}
}
