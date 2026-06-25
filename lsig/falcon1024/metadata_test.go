// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package falcon

import (
	"testing"

	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

func TestFalconMetadata(t *testing.T) {
	m := &FalconMetadata{}

	t.Run("Family", func(t *testing.T) {
		if m.RoutingFamily() != "aplane.falcon1024" {
			t.Errorf("RoutingFamily() = %v, want aplane.falcon1024", m.RoutingFamily())
		}
	})

	t.Run("CryptoSignatureSize", func(t *testing.T) {
		// Max Falcon-1024 signature size (matches LogicSigDSA)
		expectedSize := 1280
		if m.CryptoSignatureSize() != expectedSize {
			t.Errorf("CryptoSignatureSize() = %v, want %d", m.CryptoSignatureSize(), expectedSize)
		}
	})

	t.Run("MnemonicWordCount", func(t *testing.T) {
		if m.MnemonicWordCount() != 24 {
			t.Errorf("MnemonicWordCount() = %v, want 24", m.MnemonicWordCount())
		}
	})

	t.Run("MnemonicScheme", func(t *testing.T) {
		if m.MnemonicScheme() != "bip39" {
			t.Errorf("MnemonicScheme() = %v, want bip39", m.MnemonicScheme())
		}
	})

	t.Run("RequiresLogicSig", func(t *testing.T) {
		if !m.RequiresLogicSig() {
			t.Error("RequiresLogicSig() should be true for Falcon")
		}
	})

	t.Run("DefaultDerivation", func(t *testing.T) {
		if m.DefaultDerivation() != "bip39-standard" {
			t.Errorf("DefaultDerivation() = %v, want bip39-standard", m.DefaultDerivation())
		}
	})

	t.Run("DisplayColor", func(t *testing.T) {
		if m.DisplayColor() != "33" {
			t.Errorf("DisplayColor() = %v, want 33 (yellow)", m.DisplayColor())
		}
	})
}

func TestRegisterClientRegistersComposableBase(t *testing.T) {
	RegisterClient()

	reg, ok := composeddsa.LookupBase("aplane.falcon1024.v1")
	if !ok {
		t.Fatal("aplane.falcon1024.v1 was not registered as a composable base")
	}
	if reg.FamilyName != "aplane.falcon1024" {
		t.Fatalf("FamilyName = %q, want aplane.falcon1024", reg.FamilyName)
	}
	if reg.Version != 1 {
		t.Fatalf("Version = %d, want 1", reg.Version)
	}
	if reg.Ops == nil {
		t.Fatal("Ops is nil")
	}
	if reg.NewAddressDeriver == nil {
		t.Fatal("NewAddressDeriver is nil")
	}
}
