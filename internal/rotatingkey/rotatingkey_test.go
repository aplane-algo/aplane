// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/rotatinghybrid"
	"github.com/aplane-algo/aplane/lsig/rotatinghybrid/stage"
)

func TestClassifiers(t *testing.T) {
	if !IsRotatingKeyType(RotatingHybridV1) {
		t.Fatal("rotating hybrid key type was not classified as rotating")
	}
	for _, keyType := range []string{"", "ed25519", "falcon1024", "aplane.falcon1024.v1", "aplane.rotating-hybrid.v2", " aplane.rotating-hybrid.v1"} {
		if IsRotatingKeyType(keyType) {
			t.Fatalf("%q classified as rotating", keyType)
		}
	}
}

func TestRoutingFamily(t *testing.T) {
	if family, ok := RoutingFamily(RotatingHybridV1); !ok || family != RotatingHybridFamily {
		t.Fatalf("RoutingFamily(%q) = %q, %v", RotatingHybridV1, family, ok)
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
		{"stage public key", RotatingStagePublicKeySize, stage.FalconPublicKeySize + stage.Ed25519PublicKeySize},
		{"program bytes", RotatingMaxProgramBytes, stage.SaltedProgramSize},
		{"argument bytes", RotatingMaxArgumentBytes, stage.MaxArgumentBytes},
		{"opcode cost", RotatingMaxOpcodeCost, stage.SaltedOpcodeCost},
		{"validity window", RotatingMaxValidityWindow, stage.MaxValidityWindow},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: leaf has %d, implementation has %d", c.name, c.got, c.want)
		}
	}
}
