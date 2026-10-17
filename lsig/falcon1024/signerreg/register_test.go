// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerreg_test

import (
	"testing"

	cosignerverify "github.com/aplane-algo/aplane/internal/cosigner/verify"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerreg"
)

const falconKeyType = "aplane.falcon1024.v1"

// TestRegisterSignerInstallsSigningProvider covers production Falcon
// registration through the entry point production uses: after
// RegisterSigner, the versioned key type resolves to a signing provider that
// loads a real key and produces a signature the Falcon verifier accepts.
func TestRegisterSignerInstallsSigningProvider(t *testing.T) {
	signerreg.RegisterSigner()
	signerreg.RegisterSigner() // idempotent

	provider := signing.GetProvider(falconKeyType)
	if provider == nil {
		t.Fatalf("no signing provider registered for %s", falconKeyType)
	}
	if got := provider.RoutingFamily(); got != family.Name {
		t.Fatalf("RoutingFamily() = %q, want %q", got, family.Name)
	}

	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, priv, err := signerops.New(nil).GenerateKeypair(seed)
	if err != nil {
		t.Fatalf("GenerateKeypair() error = %v", err)
	}

	km, err := provider.LoadKeyMaterial(signing.ProviderKey{Type: falconKeyType, PrivateKey: priv})
	if err != nil {
		t.Fatalf("LoadKeyMaterial() error = %v", err)
	}
	defer provider.ZeroKey(km)

	message := []byte("falcon registration round trip")
	sig, err := provider.SignMessage(km, message)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	if len(sig) == 0 || len(sig) > family.MaxSignatureSize {
		t.Fatalf("SignMessage() signature length = %d, want 1..%d", len(sig), family.MaxSignatureSize)
	}
	if err := cosignerverify.VerifyFalcon1024(pub, message, sig); err != nil {
		t.Fatalf("signature does not verify under the generated public key: %v", err)
	}
}
