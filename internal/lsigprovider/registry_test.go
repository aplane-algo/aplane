// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider_test

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/genericlsig"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	v1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
)

func init() {
	// Register Falcon explicitly before querying the unified registry.
	v1.RegisterLogicSigDSA()
}

func TestFalcon1024V1Registration(t *testing.T) {
	p := lsigprovider.Get("aplane.falcon1024.v1")
	if p == nil {
		t.Fatalf("aplane.falcon1024.v1 not registered")
	}

	if p.KeyType() != "aplane.falcon1024.v1" {
		t.Errorf("KeyType = %q, want %q", p.KeyType(), "aplane.falcon1024.v1")
	}

	if p.RoutingFamily() != "aplane.falcon1024" {
		t.Errorf("Family = %q, want %q", p.RoutingFamily(), "aplane.falcon1024")
	}

	if p.Version() != 1 {
		t.Errorf("Version = %d, want %d", p.Version(), 1)
	}

	if p.Category() != lsigprovider.CategoryDSALsig {
		t.Errorf("Category = %q, want %q", p.Category(), lsigprovider.CategoryDSALsig)
	}

	if p.DisplayName() != "Falcon-1024" {
		t.Errorf("DisplayName = %q, want %q", p.DisplayName(), "Falcon-1024")
	}
}

func TestFalcon1024V1DSAMetadata(t *testing.T) {
	p := lsigprovider.Get("aplane.falcon1024.v1")
	if p == nil {
		t.Fatal("aplane.falcon1024.v1 not registered")
	}
	dsa := logicsigdsa.Get("aplane.falcon1024.v1")
	if dsa == nil {
		t.Fatal("aplane.falcon1024.v1 not registered")
	}

	if dsa.CryptoSignatureSize() != family.MaxSignatureSize {
		t.Errorf("CryptoSignatureSize = %d, want %d", dsa.CryptoSignatureSize(), family.MaxSignatureSize)
	}
	sp, ok := p.(lsigprovider.SigningProvider)
	if !ok {
		t.Fatal("aplane.falcon1024.v1 should implement SigningProvider metadata")
	}

	// Verify CreationParams is empty for pure Falcon
	params := sp.CreationParams()
	if len(params) != 0 {
		t.Errorf("CreationParams should be empty for pure Falcon, got %d", len(params))
	}
}

func TestFalcon1024V1MnemonicMetadata(t *testing.T) {
	dsa := logicsigdsa.Get("aplane.falcon1024.v1")
	if dsa == nil {
		t.Fatal("aplane.falcon1024.v1 not registered")
	}

	if dsa.MnemonicScheme() != "bip39" {
		t.Errorf("MnemonicScheme = %q, want %q", dsa.MnemonicScheme(), "bip39")
	}

	if dsa.MnemonicWordCount() != 24 {
		t.Errorf("MnemonicWordCount = %d, want %d", dsa.MnemonicWordCount(), 24)
	}
}

func TestCapabilityDetection(t *testing.T) {
	p := lsigprovider.Get("aplane.falcon1024.v1")
	if p == nil {
		t.Fatal("aplane.falcon1024.v1 not registered")
	}

	// Falcon should be a DSA LSig
	if p.Category() != lsigprovider.CategoryDSALsig {
		t.Errorf("Category = %q, want %q", p.Category(), lsigprovider.CategoryDSALsig)
	}

	// Falcon should expose signer metadata, but not private-key operations.
	if _, ok := p.(lsigprovider.SigningProvider); !ok {
		t.Error("aplane.falcon1024.v1 should implement SigningProvider metadata")
	}

	if _, ok := p.(lsigprovider.MnemonicProvider); !ok {
		t.Error("aplane.falcon1024.v1 should implement MnemonicProvider metadata")
	}
}

func TestUnregisteredKeyType(t *testing.T) {
	p := lsigprovider.Get("nonexistent-v1")
	if p != nil {
		t.Error("Get should return nil for unregistered key type")
	}

	_, err := lsigprovider.GetOrError("nonexistent-v1")
	if err == nil {
		t.Error("GetOrError should return error for unregistered key type")
	}
}

func TestHas(t *testing.T) {
	if !lsigprovider.Has("aplane.falcon1024.v1") {
		t.Error("Has should return true for registered key type")
	}

	if lsigprovider.Has("nonexistent-v1") {
		t.Error("Has should return false for unregistered key type")
	}
}

func TestGetAll(t *testing.T) {
	all := lsigprovider.GetAll()
	if len(all) == 0 {
		t.Fatal("GetAll should return at least one provider")
	}

	found := false
	for _, p := range all {
		if p.KeyType() == "aplane.falcon1024.v1" {
			found = true
			break
		}
	}

	if !found {
		t.Error("aplane.falcon1024.v1 should be in GetAll()")
	}
}

// TestNoKeyTypeCollisionBetweenRegistries ensures that no keyType exists in both
// the unified lsigprovider registry. Generic and DSA-specific helpers provide filtered views,
// and collisions would cause ambiguous resolution.
func TestNoKeyTypeCollisionBetweenRegistries(t *testing.T) {
	// Build set of generic LSig keyTypes
	genericKeyTypes := make(map[string]bool)
	for _, template := range genericlsig.GetAll() {
		genericKeyTypes[template.KeyType()] = true
	}

	// Check each DSA keyType for collision
	for _, keyType := range logicsigdsa.GetKeyTypes() {
		if genericKeyTypes[keyType] {
			t.Errorf("keyType collision: %q exists in both genericlsig and logicsigdsa registries", keyType)
		}
	}
}
