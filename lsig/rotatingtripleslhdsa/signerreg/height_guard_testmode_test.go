//go:build testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import "testing"

func TestCheckGenerationHeightInTestmodeBuild(t *testing.T) {
	for _, height := range []int{22, 63} {
		if err := checkGenerationHeight(height); err != nil {
			t.Fatalf("checkGenerationHeight(%d) in testmode build = %v, want nil", height, err)
		}
	}
}
