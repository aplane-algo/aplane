// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/signing"
)

func init() {
	// Register providers for tests
	RegisterProviders()
}

func TestSigningProvidersAreRegistered(t *testing.T) {
	// Verify signing providers are registered
	families := signing.GetRegisteredFamilies()
	if len(families) == 0 {
		t.Fatal("no signing providers registered")
	}
}
