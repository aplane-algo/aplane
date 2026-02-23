// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

func init() {
	// Register providers for tests
	RegisterProviders()
}

func TestProvidersAreRegistered(t *testing.T) {
	// Verify LogicSig DSAs are registered
	dsas := logicsigdsa.GetAll()
	if len(dsas) == 0 {
		t.Fatal("no LogicSig DSAs registered")
	}
}
