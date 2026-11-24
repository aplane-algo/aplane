//go:build testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

// isTestModeBuild reports that this binary was built with -tags testmode,
// permitting non-shipped rotating SLH-DSA heights (such as the height-63
// review build) to generate keys inside test stores.
func isTestModeBuild() bool { return true }
