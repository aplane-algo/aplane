//go:build !testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg

// isTestModeBuild reports that this is an ordinary (non-testmode) build,
// keeping non-shipped rotating SLH-DSA heights out of key generation.
func isTestModeBuild() bool { return false }
