// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/internal/crypto/wots"
	triplestage "github.com/aplane-algo/aplane/lsig/rotatingtriple/stage"
)

func TestClassifiers(t *testing.T) {
	if !IsRotatingKeyType(RotatingTripleHybridV1) {
		t.Fatal("the rotating key type was not classified as rotating")
	}
	if got := KeyTypes(); len(got) != 1 || got[0] != RotatingTripleHybridV1 {
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
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: leaf has %d, implementation has %d", c.name, c.got, c.want)
		}
	}
}
