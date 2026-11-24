// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
)

// ErrUnsupportedGenerationHeight reports an attempt to generate a rotating
// SLH-DSA key at a non-shipped hypertree height outside a testmode build.
var ErrUnsupportedGenerationHeight = errors.New("rotating SLH-DSA key generation at a non-shipped height requires a testmode build")

// checkGenerationHeight refuses rotating SLH-DSA key generation at any
// hypertree height other than the shipped height (22) unless the binary was
// built with the testmode tag.
func checkGenerationHeight(height int) error {
	if height == rotatingkey.RotatingSlhdsaShippedHeight || isTestModeBuild() {
		return nil
	}
	return fmt.Errorf("%w: height %d (shipped %s height is %d)",
		ErrUnsupportedGenerationHeight, height, rotatingkey.RotatingTripleSlhdsaV1, rotatingkey.RotatingSlhdsaShippedHeight)
}
