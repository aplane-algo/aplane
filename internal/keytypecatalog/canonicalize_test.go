// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypecatalog

import "testing"

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
