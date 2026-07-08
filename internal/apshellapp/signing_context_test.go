// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import "testing"

func TestDisplaySigningKeyType(t *testing.T) {
	tests := []struct {
		name       string
		keyType    string
		isLogicSig bool
		want       string
	}{
		{"ed25519", "ed25519", false, "Ed25519 key"},
		{"falcon lsig", "aplane.falcon1024.v1", true, "aplane.falcon1024.v1 lsig"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := displaySigningKeyType(tc.keyType, tc.isLogicSig)
			if got != tc.want {
				t.Errorf("displaySigningKeyType(%q, %v) = %q, want %q", tc.keyType, tc.isLogicSig, got, tc.want)
			}
		})
	}
}
