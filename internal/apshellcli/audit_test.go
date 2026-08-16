// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/manifest"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
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

func TestRegisterProvidersIsClientOnly(t *testing.T) {
	metadata, err := algorithm.GetMetadata(nativefalcon.KeyType)
	if err != nil {
		t.Fatalf("apshell has no client-safe native Falcon metadata: %v", err)
	}
	if metadata.AuthorizationKind() != algorithm.AuthorizationNativePQ {
		t.Fatalf("native Falcon authorization kind = %q", metadata.AuthorizationKind())
	}
	if got := signing.GetRegisteredFamilies(); len(got) != 0 {
		t.Fatalf("apshell registered signer-side signing providers: %v", got)
	}
	if got := keygen.GetRegisteredFamilies(); len(got) != 0 {
		t.Fatalf("apshell registered signer-side keygen providers: %v", got)
	}
	if got := mnemonic.GetRegisteredFamilies(); len(got) != 0 {
		t.Fatalf("apshell registered signer-side mnemonic handlers: %v", got)
	}

	m := manifest.Generate()
	if len(m.LogicSigDSAs) == 0 {
		t.Fatal("apshell manifest has no LogicSig metadata")
	}
	if len(m.SigningProviders) != 0 {
		t.Fatalf("apshell manifest should not expose signer-side providers: %v", m.SigningProviders)
	}
	foundNativeFalcon := false
	for _, info := range m.AlgorithmMetadata {
		if info.Family == nativefalcon.KeyType {
			foundNativeFalcon = true
			if info.AuthorizationKind != string(algorithm.AuthorizationNativePQ) {
				t.Fatalf("native Falcon manifest authorization kind = %q", info.AuthorizationKind)
			}
		}
	}
	if !foundNativeFalcon {
		t.Fatal("apshell manifest omitted native Falcon metadata")
	}
}
