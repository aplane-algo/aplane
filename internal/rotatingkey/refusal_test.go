// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import "testing"

// One rule decides a rekey target for the signing gate and for account
// generation: a held rotating account, or a stage address of one, is refused,
// and a rotating account's rekey to its own stage is the rotation and passes.
func TestRefuseRekeyTarget(t *testing.T) {
	const (
		rotating = "ROTATING"
		plain    = "PLAIN"
		stage    = "STAGE"
		orphan   = "ORPHAN"
		unknown  = "UNKNOWN"
	)
	keyTypes := map[string]string{rotating: RotatingTripleWotscV1, plain: "ed25519"}
	owners := map[string]string{stage: rotating, orphan: "GONE", "PLAINSTAGE": plain}
	stages := func(address string) (string, bool) {
		account, ok := owners[address]
		return account, ok
	}
	for _, test := range []struct {
		name           string
		sender, target string
		stages         StageOwner
		want           string
	}{
		{"a held rotating account", plain, rotating, stages, RekeyTargetRefusal(rotating)},
		{"a held rotating account, no stage lookup", plain, rotating, nil, RekeyTargetRefusal(rotating)},
		{"a stage of a held rotating account", plain, stage, stages, StageRekeyTargetRefusal(stage, rotating)},
		{"a stage, at generation, with no sender", "", stage, stages, StageRekeyTargetRefusal(stage, rotating)},
		{"the rotation: the account to its own stage", rotating, stage, stages, ""},
		{"a stage, no stage lookup", plain, stage, nil, ""},
		// A table entry whose account is no longer a held rotating account
		// refuses nothing.
		{"a stage whose account isn't held", plain, orphan, stages, ""},
		{"a stage whose account isn't rotating", unknown, "PLAINSTAGE", stages, ""},
		{"a held account that isn't rotating", unknown, plain, stages, ""},
		{"an address the signer doesn't know", plain, unknown, stages, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			reason, refused := RefuseRekeyTarget(test.sender, test.target, keyTypes, test.stages)
			if refused != (test.want != "") || reason != test.want {
				t.Fatalf("RefuseRekeyTarget = %q, %v; want %q", reason, refused, test.want)
			}
		})
	}
}
