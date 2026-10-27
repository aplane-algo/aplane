// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/lsig/rotatingtripleslhdsa/stage"
	"testing"
)

func TestClassificationMatchesImplementation(t *testing.T) {
	p, ok := rotatingkey.Lookup(rotatingkey.RotatingTripleSlhdsaV1)
	if !ok || !p.StatelessHash || p.OneTimeStage || p.LeavesPerStage != 0 || p.StagesPerTree != 0 {
		t.Fatalf("profile %+v", p)
	}
	if p.StagePublicKeySize != packedSize || p.MaxProgramBytes != stage.SaltedProgramSize || p.MaxArgumentBytes != stage.MaxArgumentBytes || p.MaxOpcodeCost != stage.MaxOpcodeCost {
		t.Fatalf("profile differs from implementation: %+v", p)
	}
}
