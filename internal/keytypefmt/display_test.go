// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypefmt

import "testing"

func TestDisplay(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{name: "ed25519", keyType: "ed25519", want: "ed25519"},
		{name: "aplane falcon unchanged", keyType: "aplane.falcon1024.v1", want: "aplane.falcon1024.v1"},
		{name: "aplane template unchanged", keyType: "aplane.falcon1024-whitelist.v1", want: "aplane.falcon1024-whitelist.v1"},
		{name: "other publisher unchanged", keyType: "custom.whitelist.v2", want: "custom.whitelist.v2"},
		{name: "filename unchanged", keyType: "aplane.whitelist.v1.yaml", want: "aplane.whitelist.v1.yaml"},
		{name: "extra family dot unchanged", keyType: "aplane.white.list.v1", want: "aplane.white.list.v1"},
		{name: "unsafe family unchanged", keyType: "aplane.white list.v1", want: "aplane.white list.v1"},
		{name: "legacy unchanged", keyType: "whitelist-v1", want: "whitelist-v1"},
		{name: "unqualified versioned unchanged", keyType: "whitelist.v1", want: "whitelist.v1"},
		{name: "invalid version unchanged", keyType: "aplane.whitelist.version1", want: "aplane.whitelist.version1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Display(tt.keyType); got != tt.want {
				t.Fatalf("Display(%q) = %q, want %q", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{name: "ed25519 unchanged", keyType: "ed25519", want: "ed25519"},
		{name: "unqualified falcon unchanged", keyType: "falcon1024.v1", want: "falcon1024.v1"},
		{name: "unqualified template unchanged", keyType: "falcon1024-whitelist.v1", want: "falcon1024-whitelist.v1"},
		{name: "bare unqualified unchanged", keyType: "whitelist.v1", want: "whitelist.v1"},
		{name: "trims and lowers unqualified", keyType: " Whitelist.V1 ", want: "whitelist.v1"},
		{name: "already aplane idempotent", keyType: "aplane.falcon1024.v1", want: "aplane.falcon1024.v1"},
		{name: "trims and lowers canonical", keyType: " APLANE.FALCON1024.V1 ", want: "aplane.falcon1024.v1"},
		{name: "other publisher unchanged", keyType: "custom.whitelist.v2", want: "custom.whitelist.v2"},
		{name: "legacy unchanged", keyType: "whitelist-v1", want: "whitelist-v1"},
		{name: "filename unchanged", keyType: "aplane.whitelist.v1.yaml", want: "aplane.whitelist.v1.yaml"},
		{name: "extra family dot unchanged", keyType: "aplane.white.list.v1", want: "aplane.white.list.v1"},
		{name: "unsafe family unchanged", keyType: "white list.v1", want: "white list.v1"},
		{name: "invalid version unchanged", keyType: "whitelist.version1", want: "whitelist.version1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Canonicalize(tt.keyType); got != tt.want {
				t.Fatalf("Canonicalize(%q) = %q, want %q", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestDisplayCanonicalizeRoundTrip(t *testing.T) {
	canonical := []string{
		"aplane.falcon1024.v1",
		"aplane.falcon1024-whitelist.v1",
		"aplane.falcon1024-timelock.v1",
	}
	for _, kt := range canonical {
		if got := Canonicalize(Display(kt)); got != kt {
			t.Fatalf("Canonicalize(Display(%q)) = %q, want %q", kt, got, kt)
		}
	}
}

func TestPublisher(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{name: "ed25519", keyType: "ed25519", want: ""},
		{name: "aplane falcon", keyType: "aplane.falcon1024.v1", want: "aplane"},
		{name: "other publisher", keyType: "custom.whitelist.v2", want: "custom"},
		{name: "filename unchanged", keyType: "aplane.whitelist.v1.yaml", want: ""},
		{name: "missing publisher", keyType: "whitelist.v1", want: ""},
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
		{segment: "falcon1024-whitelist", want: true},
		{segment: "falcon1024_whitelist", want: true},
		{segment: "", want: false},
		{segment: "white.list", want: false},
		{segment: "white list", want: false},
		{segment: "Whitelist", want: false},
	}
	for _, tt := range tests {
		if got := ValidSegment(tt.segment); got != tt.want {
			t.Fatalf("ValidSegment(%q) = %v, want %v", tt.segment, got, tt.want)
		}
	}
}
