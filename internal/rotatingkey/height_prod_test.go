//go:build !testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package rotatingkey

import "testing"

// TestRotatingSlhdsaShippedHeightIs22 pins ordinary builds (including CI) to
// the shipped hypertree height of aplane.rotating-triple-slhdsa.v1 so a
// height-63 review change cannot be committed and shipped by accident.
func TestRotatingSlhdsaShippedHeightIs22(t *testing.T) {
	if RotatingSlhdsaShippedHeight != 22 {
		t.Fatalf("RotatingSlhdsaShippedHeight = %d, want 22", RotatingSlhdsaShippedHeight)
	}
	if RotatingSlhdsaHeight != RotatingSlhdsaShippedHeight {
		t.Fatalf("RotatingSlhdsaHeight = %d in an ordinary build, want shipped height %d (non-shipped review builds require -tags testmode)",
			RotatingSlhdsaHeight, RotatingSlhdsaShippedHeight)
	}
}
