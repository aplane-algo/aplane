// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/wotsc"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/lsig/rotatingtriplewotsc/stage"
)

func TestClassificationMatchesImplementation(t *testing.T) {
	p, ok := rotatingkey.Lookup(rotatingkey.RotatingTripleWotscV1)
	if !ok || p.StatelessHash || !p.OneTimeStage || p.LeavesPerStage != wotsc.Leaves || p.StagesPerTree != 0 {
		t.Fatalf("profile %+v", p)
	}
	if p.StagePublicKeySize != packedSize || p.MaxProgramBytes != stage.SaltedProgramSize || p.MaxArgumentBytes != stage.MaxArgumentBytes || p.MaxOpcodeCost != stage.MaxOpcodeCost {
		t.Fatalf("profile differs from implementation: %+v", p)
	}
	if lo, hi := p.LeafRange(7); lo != 0 || hi != wotsc.Leaves {
		t.Fatalf("stage 7 has leaves [%d, %d)", lo, hi)
	}
}
