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
		{name: "aplane falcon", keyType: "aplane.falcon1024.v1", want: "aplane.falcon1024.v1"},
		{name: "aplane template", keyType: "aplane.falcon1024-whitelist.v1", want: "aplane.falcon1024-whitelist.v1"},
		{name: "other publisher", keyType: "custom.whitelist.v2", want: "custom.whitelist.v2"},
		{name: "filename unchanged", keyType: "aplane.whitelist.v1.yaml", want: "aplane.whitelist.v1.yaml"},
		{name: "legacy unchanged", keyType: "whitelist-v1", want: "whitelist-v1"},
		{name: "missing publisher unchanged", keyType: "whitelist.v1", want: "whitelist.v1"},
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
