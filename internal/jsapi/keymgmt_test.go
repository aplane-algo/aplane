// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsapi

import (
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/engine"
)

// generateKey() hands a script the signer's warnings. The signer creates the
// account either way, so a script that didn't get them would have no sign that,
// say, the cosigner is a key the signer holds. warnings is an array even when
// there are none, so a script can test its length.
func TestGenerateKeyReturnsTheSignersWarnings(t *testing.T) {
	for _, test := range []struct {
		name     string
		warnings []string
	}{
		{"none", nil},
		{"one", []string{"The cosigner is a key this signer holds."}},
		{"two", []string{"Fee limit 0 is too low to pay alone.", "The cosigner is a key this signer holds."}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := generatedKeyValue(&engine.GenerateKeyResult{Address: "ADDR", KeyType: "aplane.bounded.v1", Warnings: test.warnings})
			if value["address"] != "ADDR" || value["keyType"] != "aplane.bounded.v1" {
				t.Fatalf("value = %#v", value)
			}
			got, ok := value["warnings"].([]string)
			if !ok || got == nil {
				t.Fatalf("warnings = %#v, want an array", value["warnings"])
			}
			if !slices.Equal(got, test.warnings) {
				t.Fatalf("warnings = %q, want %q", got, test.warnings)
			}
		})
	}
}
