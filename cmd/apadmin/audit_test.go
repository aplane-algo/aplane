// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import "testing"

func init() {
	// Register providers for tests
	RegisterProviders()
}

func TestEnsureProviders(t *testing.T) {
	if err := ensureProviders(); err != nil {
		t.Fatalf("provider audit failed: %v", err)
	}
}
