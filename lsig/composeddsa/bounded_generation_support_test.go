// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

// unsupportedAdminTemplate is structurally valid, but its external-admin rekey
// can never complete: the admin ceremony requires a Falcon-1024 spending key.
const unsupportedAdminTemplate = `
schema_version: 2
template_type: composed
base_key_type: aplane.ed25519.v1
template_mode: strict
publisher: test
family: unsupported-admin-fixture
version: 1
display_name: Unsupported Admin Fixture
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none
teal: |
  int 1
  assert
`

func unsupportedAdminProvider(t *testing.T) *composeddsa.ComposedDSA {
	t.Helper()
	ed25519lsig.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(unsupportedAdminTemplate))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := composeddsa.ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("ValidateTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	return provider
}

// Installed templates must keep their exact fingerprint: a change reads as an
// external edit, and that takes the whole store out of service.
func TestUnsupportedAdminTemplateKeepsStructuralBehavior(t *testing.T) {
	const pinnedFingerprint = "1:3397306526ef0ad18780c4c45c729920b332d5ebd4e5fd2a4c335e8dccbd8167"
	provider := unsupportedAdminProvider(t)
	if got := provider.CompatibilityFingerprint(); got != pinnedFingerprint {
		t.Fatalf("CompatibilityFingerprint() = %s, want %s", got, pinnedFingerprint)
	}
	if provider.BoundedAuthorizationMetadata() == nil {
		t.Fatal("BoundedAuthorizationMetadata() = nil, want the inventory projection")
	}
	if got := provider.BoundedAuthorizationProfile(); got == nil {
		t.Fatal("BoundedAuthorizationProfile() = nil")
	}
	// An existing account of this shape still assembles its spending arguments.
	if args, err := provider.BuildArgs(make([]byte, 64), nil); err != nil || len(args) != 1 {
		t.Fatalf("BuildArgs() = %d args, %v", len(args), err)
	}
}

func generationParameters() map[string]string {
	return map[string]string{
		composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)),
	}
}

func TestGenerationRefusesExternalAdminOnUnsupportedBase(t *testing.T) {
	provider := unsupportedAdminProvider(t)
	spendingKey := bytes.Repeat([]byte{0x22}, 32)

	t.Run("template route", func(t *testing.T) {
		_, err := provider.GenerateTEAL(spendingKey, generationParameters())
		if err == nil || !strings.Contains(err.Error(), "requires a Falcon-1024 spending key") {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})

	// Account creation derives through this, and it is refused before any compile.
	t.Run("derivation", func(t *testing.T) {
		client, err := algod.MakeClient("http://127.0.0.1:1", "")
		if err != nil {
			t.Fatal(err)
		}
		provider.SetAlgodClient(client)
		_, err = provider.DeriveLsigWithSalt(context.Background(), spendingKey, generationParameters())
		if err == nil || !strings.Contains(err.Error(), "requires a Falcon-1024 spending key") {
			t.Fatalf("DeriveLsigWithSalt() error = %v", err)
		}
	})

	t.Run("direct construction", func(t *testing.T) {
		direct := composeddsa.NewComposedDSA(composeddsa.Config{
			KeyType: "test.direct-unsupported-admin.v1", BaseKeyType: "aplane.ed25519.v1", FamilyName: "aplane.ed25519",
			Version: 1, Ops: ed25519v1.NewOps(), TEALSuffix: "int 1\nassert",
			Bounded: provider.BoundedAuthorizationProfile(),
		})
		_, err := direct.GenerateTEAL(spendingKey, generationParameters())
		if err == nil || !strings.Contains(err.Error(), "requires a Falcon-1024 spending key") {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})
}

// Template validation refuses this shape, so direct construction is the only way
// to reach the generation check.
func TestGenerationRefusesCosignerOnUnsupportedBase(t *testing.T) {
	profile := *unsupportedAdminProvider(t).BoundedAuthorizationProfile()
	profile.AdminOperations = nil
	profile.Cosigner = &boundedmeta.CosignerAuthorization{}
	direct := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: "test.direct-unsupported-cosigner.v1", BaseKeyType: "aplane.ed25519.v1", FamilyName: "aplane.ed25519",
		Version: 1, Ops: ed25519v1.NewOps(), TEALSuffix: "int 1\nassert", Bounded: &profile,
	})
	_, err := direct.GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), nil)
	if err == nil || !strings.Contains(err.Error(), "does not support a cosigner") {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
}

func TestGenerationRefusesUnknownBoundedBase(t *testing.T) {
	profile := unsupportedAdminProvider(t).BoundedAuthorizationProfile()
	direct := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: "test.direct-unknown-base.v1", BaseKeyType: "test.unknown-base.v1", FamilyName: "unknown",
		Version: 1, Ops: ed25519v1.NewOps(), TEALSuffix: "int 1\nassert", Bounded: profile,
	})
	_, err := direct.GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), generationParameters())
	if err == nil || !strings.Contains(err.Error(), "cannot be generated on base key type") {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
}

func TestGenerationAllowsSupportedProfiles(t *testing.T) {
	ed25519lsig.RegisterClient()
	falcon.RegisterClient()

	t.Run("Ed25519 with spending-key rekey", func(t *testing.T) {
		yaml := strings.Replace(unsupportedAdminTemplate, "authorization: admin_key", "authorization: spending_key", 1)
		spec, err := composeddsa.ParseTemplateSpec([]byte(yaml))
		if err != nil {
			t.Fatal(err)
		}
		provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), nil); err != nil {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})

	t.Run("Falcon with external admin", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "..", "library", "retired", "aplane.falcon1024-allowlist-lock.v1.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		spec, err := composeddsa.ParseTemplateSpec(data)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		params := generationParameters()
		params["recipients"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
		if _, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x22}, 1793), params); err != nil {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})

	t.Run("Falcon with a cosigner", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join("..", "..", "library", "retired", "aplane.corridor.v1.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		spec, err := composeddsa.ParseTemplateSpec(data)
		if err != nil {
			t.Fatal(err)
		}
		provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		params := generationParameters()
		params["recipients"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
		params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
		if _, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x22}, 1793), params); err != nil {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})

	t.Run("plain Ed25519 LogicSig", func(t *testing.T) {
		if _, err := ed25519v1.NewProvider().GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), nil); err != nil {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})
}
