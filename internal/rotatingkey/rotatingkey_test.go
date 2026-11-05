// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/xmss"
	xmssstage "github.com/aplane-algo/aplane/lsig/rotatingtriplexmss/stage"
)

func TestClassifiers(t *testing.T) {
	if !IsRotatingKeyType(RotatingTripleXmssV1) {
		t.Fatal("the XMSS rotating key type was not classified as rotating")
	}
	if got := KeyTypes(); len(got) != 3 || got[0] != RotatingTripleXmssV1 || got[1] != RotatingTripleSlhdsaV1 || got[2] != RotatingTripleWotscV1 {
		t.Fatalf("KeyTypes() = %v", got)
	}
	// The retired Falcon and WOTS hybrids, the removed WOTS triple, and the
	// pre-rename identifiers are ordinary unknown key types.
	for _, keyType := range []string{"", "ed25519", "falcon1024", "aplane.falcon1024.v1", "aplane.rotating-triple-wots.v1", "aplane.rotating-triple-wots.v2", " aplane.rotating-triple-wots.v1", "aplane.rotating-triple-hybrid.v1", "aplane.rotating-xmss-triple.v1", "aplane.rotating-hybrid.v1", "aplane.rotating-wots-hybrid.v1"} {
		if IsRotatingKeyType(keyType) {
			t.Fatalf("%q classified as rotating", keyType)
		}
	}
}

func TestRoutingFamily(t *testing.T) {
	if family, ok := RoutingFamily(RotatingTripleWotscV1); !ok || family != RotatingTripleWotscFamily {
		t.Fatalf("RoutingFamily(%q) = %q, %v", RotatingTripleWotscV1, family, ok)
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
		{"validity window", RotatingMaxValidityWindow, xmssstage.MaxValidityWindow},
		{"xmss max steps", 990, xmss.MaxVerifySteps},
		{"xmss accepted steps", 525, xmssstage.MaxAcceptedSteps},
		{"xmss checksum cap", 511, xmssstage.MaxChecksum},
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

// A family with several leaves and no shared tree must get all of them at
// every stage. Reading StagesPerTree == 0 as one leaf would quietly make every
// retry reuse a key.
func TestLeafRangeOfOwnTreePerStage(t *testing.T) {
	p := Profile{LeavesPerStage: 64}
	for _, stage := range []uint64{0, 1, 63, 64, 1 << 40} {
		if lo, hi := p.LeafRange(stage); lo != 0 || hi != 64 {
			t.Fatalf("stage %d: LeafRange = [%d, %d)", stage, lo, hi)
		}
		if tree := p.TreeOf(stage); tree != 0 {
			t.Fatalf("stage %d: TreeOf = %d", stage, tree)
		}
	}
}

func TestLeafRangeWithoutLeaves(t *testing.T) {
	slh, _ := Lookup(RotatingTripleSlhdsaV1)
	if lo, hi := slh.LeafRange(5); lo != 0 || hi != 1 {
		t.Fatalf("LeafRange = [%d, %d)", lo, hi)
	}
	if slh.TreeOf(5) != 0 {
		t.Fatal("TreeOf != 0")
	}
}

func TestLeafRange(t *testing.T) {
	x, _ := Lookup(RotatingTripleXmssV1)
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
