// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

func init() {
	// Register providers for tests
	RegisterProviders()
}

func TestEnsureProviders(t *testing.T) {
	if err := ensureProviders(); err != nil {
		t.Fatalf("provider audit failed: %v", err)
	}
}

func TestNativeFalconAdminWorkflowsAreRegistered(t *testing.T) {
	if _, err := keygen.GetGenerator(nativefalcon.KeyType); err != nil {
		t.Fatalf("native Falcon generator is unavailable to apadmin: %v", err)
	}
	handler, err := mnemonic.GetHandler(nativefalcon.KeyType)
	if err != nil {
		t.Fatalf("native Falcon mnemonic handler is unavailable to apadmin: %v", err)
	}
	if got := handler.WordCount(); got != nativefalcon.MnemonicWordCount {
		t.Fatalf("native Falcon mnemonic word count = %d, want %d", got, nativefalcon.MnemonicWordCount)
	}
}
