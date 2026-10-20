// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package racetest lets tests tell whether the race detector is on, so work
// the detector makes prohibitively slow can be skipped in the race job and
// left to the ordinary unit suite.
package racetest

import "testing"

// SkipFullTree skips the test when the race detector is on: building a full
// 65,536-leaf XMSS tree takes seconds normally and minutes under the
// detector, which times out CI's race job. The ordinary unit suite, the
// pre-commit hook and the LocalNet suite still run every such test.
func SkipFullTree(t testing.TB) {
	t.Helper()
	if Enabled {
		t.Skip("full XMSS tree build skipped under the race detector")
	}
}
