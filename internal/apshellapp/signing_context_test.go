// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
)

func TestDisplaySigningKeyType(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		kind    algorithm.AuthorizationKind
		want    string
	}{
		{"ed25519", "ed25519", algorithm.AuthorizationEd25519, "Ed25519 key"},
		{"native falcon", "falcon1024", algorithm.AuthorizationNativePQ, "falcon1024"},
		{"falcon lsig", "aplane.falcon1024.v1", algorithm.AuthorizationLogicSig, "aplane.falcon1024.v1 lsig"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := displaySigningKeyType(tc.keyType, tc.kind)
			if got != tc.want {
				t.Errorf("displaySigningKeyType(%q, %q) = %q, want %q", tc.keyType, tc.kind, got, tc.want)
			}
		})
	}
}
