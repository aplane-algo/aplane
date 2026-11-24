//go:build !testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
)

func TestCheckGenerationHeightInOrdinaryBuild(t *testing.T) {
	if rotatingkey.RotatingSlhdsaHeight != 22 {
		t.Fatalf("RotatingSlhdsaHeight = %d in an ordinary build, want 22", rotatingkey.RotatingSlhdsaHeight)
	}
	if err := checkGenerationHeight(22); err != nil {
		t.Fatalf("checkGenerationHeight(22) = %v, want nil", err)
	}
	for _, height := range []int{63, 0, 20, 21, 64} {
		err := checkGenerationHeight(height)
		if !errors.Is(err, ErrUnsupportedGenerationHeight) {
			t.Fatalf("checkGenerationHeight(%d) = %v, want ErrUnsupportedGenerationHeight", height, err)
		}
	}
}
