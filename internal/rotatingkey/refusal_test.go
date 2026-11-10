// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import "testing"

// One rule decides a rekey target for the signing gate and for account
// generation: a held rotating account, or a stage address of one, is refused.
// The rule has no exception of its own.
func TestRefuseRekeyTarget(t *testing.T) {
	const (
		rotating = "ROTATING"
		lower    = "AROTATING"
		plain    = "PLAIN"
		unknown  = "UNKNOWN"
	)
	keyTypes := map[string]string{rotating: RotatingTripleWotscV1, lower: RotatingTripleWotscV1, plain: "ed25519"}
	owners := map[string][]string{
		"STAGE":      {rotating},
		"SHARED":     {rotating, "GONE", lower},
		"ORPHAN":     {"GONE"},
		"MIXED":      {"GONE", plain, rotating},
		"PLAINSTAGE": {plain},
		"NONE":       {},
	}
	stages := func(address string) []string { return owners[address] }
	for _, test := range []struct {
		name   string
		target string
		stages StageOwners
		want   string
	}{
		{"a held rotating account", rotating, stages, RekeyTargetRefusal(rotating)},
		{"a held rotating account, no stage lookup", rotating, nil, RekeyTargetRefusal(rotating)},
		{"a stage of a held rotating account", "STAGE", stages, StageRekeyTargetRefusal("STAGE", rotating)},
		// Every table that holds the address is considered, and the lowest held
		// rotating account is named.
		{"a stage two held rotating accounts' tables hold", "SHARED", stages, StageRekeyTargetRefusal("SHARED", lower)},
		{"a stage whose first owners aren't held rotating accounts", "MIXED", stages, StageRekeyTargetRefusal("MIXED", rotating)},
		{"a stage, no stage lookup", "STAGE", nil, ""},
		// A table whose account is no longer a held rotating account refuses
		// nothing.
		{"a stage whose account isn't held", "ORPHAN", stages, ""},
		{"a stage whose account isn't rotating", "PLAINSTAGE", stages, ""},
		{"an address with an empty owner list", "NONE", stages, ""},
		{"a held account that isn't rotating", plain, stages, ""},
		{"an address the signer doesn't know", unknown, stages, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			reason, refused := RefuseRekeyTarget(test.target, keyTypes, test.stages)
			if refused != (test.want != "") || reason != test.want {
				t.Fatalf("RefuseRekeyTarget = %q, %v; want %q", reason, refused, test.want)
			}
		})
	}
}
