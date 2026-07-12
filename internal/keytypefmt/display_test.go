// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypefmt

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keytypecatalog"
)

func TestDisplay(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		want    string
	}{
		{name: "ed25519", keyType: "ed25519", want: "ed25519"},
		{name: "aplane falcon unchanged", keyType: "aplane.falcon1024.v1", want: "aplane.falcon1024.v1"},
		{name: "aplane template unchanged", keyType: "aplane.falcon1024-allowlist.v1", want: "aplane.falcon1024-allowlist.v1"},
		{name: "other publisher unchanged", keyType: "custom.allowlist.v2", want: "custom.allowlist.v2"},
		{name: "filename unchanged", keyType: "aplane.allowlist.v1.yaml", want: "aplane.allowlist.v1.yaml"},
		{name: "extra family dot unchanged", keyType: "aplane.white.list.v1", want: "aplane.white.list.v1"},
		{name: "unsafe family unchanged", keyType: "aplane.white list.v1", want: "aplane.white list.v1"},
		{name: "legacy unchanged", keyType: "allowlist-v1", want: "allowlist-v1"},
		{name: "unqualified versioned unchanged", keyType: "allowlist.v1", want: "allowlist.v1"},
		{name: "invalid version unchanged", keyType: "aplane.allowlist.version1", want: "aplane.allowlist.version1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Display(tt.keyType); got != tt.want {
				t.Fatalf("Display(%q) = %q, want %q", tt.keyType, got, tt.want)
			}
		})
	}
}

func TestDisplayCanonicalizeRoundTrip(t *testing.T) {
	canonical := []string{
		"aplane.falcon1024.v1",
		"aplane.falcon1024-allowlist.v1",
		"aplane.falcon1024-timelock.v1",
	}
	for _, kt := range canonical {
		if got := keytypecatalog.Canonicalize(Display(kt)); got != kt {
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
		{name: "other publisher", keyType: "custom.allowlist.v2", want: "custom"},
		{name: "filename unchanged", keyType: "aplane.allowlist.v1.yaml", want: ""},
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
