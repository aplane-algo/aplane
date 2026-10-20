// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wots"
	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	triplestage "github.com/aplane-algo/aplane/lsig/rotatingtriple/stage"
	xmssstage "github.com/aplane-algo/aplane/lsig/rotatingxmsstriple/stage"
)

func TestClassifiers(t *testing.T) {
	if !IsRotatingKeyType(RotatingTripleHybridV1) {
		t.Fatal("the rotating key type was not classified as rotating")
	}
	if !IsRotatingKeyType(RotatingXmssTripleV1) {
		t.Fatal("the XMSS rotating key type was not classified as rotating")
	}
	if got := KeyTypes(); len(got) != 2 || got[0] != RotatingTripleHybridV1 || got[1] != RotatingXmssTripleV1 {
		t.Fatalf("KeyTypes() = %v", got)
	}
	// The retired Falcon and WOTS hybrids are ordinary unknown key types.
	for _, keyType := range []string{"", "ed25519", "falcon1024", "aplane.falcon1024.v1", "aplane.rotating-triple-hybrid.v2", " aplane.rotating-triple-hybrid.v1", "aplane.rotating-hybrid.v1", "aplane.rotating-wots-hybrid.v1"} {
		if IsRotatingKeyType(keyType) {
			t.Fatalf("%q classified as rotating", keyType)
		}
	}
}

func TestRoutingFamily(t *testing.T) {
	if family, ok := RoutingFamily(RotatingTripleHybridV1); !ok || family != RotatingTripleHybridFamily {
		t.Fatalf("RoutingFamily(%q) = %q, %v", RotatingTripleHybridV1, family, ok)
	}
	for _, keyType := range KeyTypes() {
		p, ok := Lookup(keyType)
		if !ok || p.KeyType != keyType || p.DisplayName == "" || p.StagePublicKeySize == 0 || p.MaxOpcodeCost == 0 {
			t.Fatalf("Lookup(%q) = %+v, %v", keyType, p, ok)
		}
	}
	if family, ok := RoutingFamily("aplane.falcon1024.v1"); ok || family != "" {
		t.Fatalf("RoutingFamily of a non-rotating key type = %q, %v", family, ok)
	}
}

// TestFrozenSizesMatchImplementation pins the leaf literals to the packages
// that define them.
func TestFrozenSizesMatchImplementation(t *testing.T) {
	checks := []struct {
		name      string
		got, want int
	}{
		{"seed", RotatingSeedSize, rotatinghybrid.SeedSize},
		{"genesis hash", RotatingGenesisHashSize, rotatinghybrid.GenesisHashSize},
		{"wots max steps", 990, wots.MaxVerifySteps},
		{"triple stage public key", RotatingTripleStagePublicKeySize, 32 + triplestage.FalconPublicKeySize + 2*triplestage.ConstantSize},
		{"triple program bytes", RotatingTripleMaxProgramBytes, triplestage.SaltedProgramSize},
		{"triple argument bytes", RotatingTripleMaxArgumentBytes, triplestage.MaxArgumentBytes},
		{"triple opcode cost", RotatingTripleMaxOpcodeCost, triplestage.MaxOpcodeCost},
		{"triple validity window", RotatingMaxValidityWindow, triplestage.MaxValidityWindow},
		{"xmss max steps", 990, xmss.MaxVerifySteps},
		{"xmss stage public key", RotatingXmssStagePublicKeySize, 32 + xmssstage.FalconPublicKeySize + 3*xmssstage.ConstantSize},
		{"xmss program bytes", RotatingXmssMaxProgramBytes, xmssstage.SaltedProgramSize},
		{"xmss argument bytes", RotatingXmssMaxArgumentBytes, xmssstage.MaxArgumentBytes},
		{"xmss opcode cost", RotatingXmssMaxOpcodeCost, xmssstage.MaxOpcodeCost},
		{"xmss validity window", RotatingMaxValidityWindow, xmssstage.MaxValidityWindow},
		{"xmss leaves per stage", RotatingXmssLeavesPerStage, xmssstage.IndicesPerStage},
		{"xmss stages per tree", RotatingXmssStagesPerTree, xmssstage.StagesPerTree},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: leaf has %d, implementation has %d", c.name, c.got, c.want)
		}
	}
}

func TestLeafRange(t *testing.T) {
	triple, _ := Lookup(RotatingTripleHybridV1)
	if lo, hi := triple.LeafRange(5); lo != 0 || hi != 1 {
		t.Fatalf("triple LeafRange = [%d, %d)", lo, hi)
	}
	if triple.TreeOf(5) != 0 {
		t.Fatal("triple TreeOf != 0")
	}
	x, _ := Lookup(RotatingXmssTripleV1)
	for _, tc := range []struct{ stage, tree, lo, hi uint64 }{
		{0, 0, 0, 64}, {1, 0, 64, 128}, {1023, 0, 65472, 65536}, {1024, 1, 0, 64}, {2048, 2, 0, 64},
	} {
		lo, hi := x.LeafRange(tc.stage)
		if lo != tc.lo || hi != tc.hi || x.TreeOf(tc.stage) != tc.tree {
			t.Fatalf("stage %d: range [%d, %d) tree %d", tc.stage, lo, hi, x.TreeOf(tc.stage))
		}
		slo, shi := func() (uint64, uint64) { _, a, b := xmssstage.RangeFor(tc.stage); return a, b }()
		if slo != lo || shi != hi {
			t.Fatalf("stage %d: profile range [%d, %d) differs from stage.RangeFor [%d, %d)", tc.stage, lo, hi, slo, shi)
		}
	}
}
