// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

// ed25519BoundedTemplate is a bounded program on the Ed25519 base. That base
// supports ordinary spending and spending-key rekey, but not a cosigner.
const ed25519BoundedTemplate = `
schema_version: 2
template_type: composed
base_key_type: aplane.ed25519.v1
template_mode: strict
publisher: test
family: ed25519-bounded-fixture
version: 1
display_name: Ed25519 Bounded Fixture
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: spending_key
teal: |
  int 1
  assert
`

// falconCosignerTemplate is a bounded program with a cosigner on the Falcon base,
// the one base the cosigner workflow supports.
const falconCosignerTemplate = `
schema_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: falcon-cosigner-fixture
version: 1
display_name: Falcon Cosigner Fixture
max_opcode_cost: 20000
bounded:
  contract: bounded2
  spend_effects: [pay]
  max_fee: 10000
  rekey: refused
  cosigner:
    contract: cosigner1
    required_on: [spend]
teal: |
  int 1
  assert
`

func ed25519BoundedProvider(t *testing.T) *composeddsa.ComposedDSA {
	t.Helper()
	ed25519lsig.RegisterClient()
	spec, err := composeddsa.ParseTemplateSpec([]byte(ed25519BoundedTemplate))
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

// A policy that stops supporting a cosigner on a base refuses new accounts with
// one at generation. Every production base supports a cosigner, so the policy is
// narrowed for this composer alone.
func TestGenerationRefusesCosignerOnUnsupportedBase(t *testing.T) {
	profile := *ed25519BoundedProvider(t).BoundedAuthorizationProfile()
	profile.Rekey = boundedmeta.RekeyRefused
	profile.Cosigner = &boundedmeta.CosignerAuthorization{}
	direct := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: "test.direct-unsupported-cosigner.v1", BaseKeyType: "aplane.ed25519.v1", FamilyName: "aplane.ed25519",
		Version: 1, Ops: ed25519v1.NewOps(), TEALSuffix: "int 1\nassert", Bounded: &profile,
	})
	composeddsa.NarrowCosignerSupport(direct)
	spendingKey := bytes.Repeat([]byte{0x22}, 32)

	t.Run("template route", func(t *testing.T) {
		_, err := direct.GenerateTEAL(spendingKey, nil)
		if err == nil || !strings.Contains(err.Error(), "does not support a cosigner") {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})

	// Account creation derives through this, and it is refused before any compile.
	t.Run("derivation", func(t *testing.T) {
		client, err := algod.MakeClient("http://127.0.0.1:1", "")
		if err != nil {
			t.Fatal(err)
		}
		direct.SetAlgodClient(client)
		_, err = direct.DeriveLsigWithSalt(context.Background(), spendingKey, nil)
		if err == nil || !strings.Contains(err.Error(), "does not support a cosigner") {
			t.Fatalf("DeriveLsigWithSalt() error = %v", err)
		}
	})
}

func TestGenerationRefusesUnknownBoundedBase(t *testing.T) {
	profile := ed25519BoundedProvider(t).BoundedAuthorizationProfile()
	direct := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: "test.direct-unknown-base.v1", BaseKeyType: "test.unknown-base.v1", FamilyName: "unknown",
		Version: 1, Ops: ed25519v1.NewOps(), TEALSuffix: "int 1\nassert", Bounded: profile,
	})
	_, err := direct.GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), nil)
	if err == nil || !strings.Contains(err.Error(), "cannot be generated on base key type") {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
}

// A direct NewComposedDSA call bypasses RegisterBase. Naming the Falcon base while
// passing Ed25519 ops would get Falcon's support while the program verified an
// Ed25519 signature, and signing would later check the account against Falcon.
func TestGenerationRefusesOpsThatDisagreeWithTheBaseName(t *testing.T) {
	profile := *ed25519BoundedProvider(t).BoundedAuthorizationProfile()
	profile.Rekey = boundedmeta.RekeyRefused
	direct := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType: "test.direct-mismatched-ops.v1", BaseKeyType: "aplane.falcon1024.v1", FamilyName: "aplane.falcon1024",
		Version: 1, Ops: ed25519v1.NewOps(), TEALSuffix: "int 1\nassert", Bounded: &profile,
	})
	_, err := direct.GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), nil)
	if err == nil || !strings.Contains(err.Error(), `names construction "falcon1024", but its ops render "ed25519"`) {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
}

func TestGenerationAllowsSupportedProfiles(t *testing.T) {
	ed25519lsig.RegisterClient()
	falcon.RegisterClient()

	t.Run("Ed25519 with spending-key rekey", func(t *testing.T) {
		if _, err := ed25519BoundedProvider(t).GenerateTEAL(bytes.Repeat([]byte{0x22}, 32), nil); err != nil {
			t.Fatalf("GenerateTEAL() error = %v", err)
		}
	})

	t.Run("Falcon with a cosigner", func(t *testing.T) {
		spec, err := composeddsa.ParseTemplateSpec([]byte(falconCosignerTemplate))
		if err != nil {
			t.Fatal(err)
		}
		provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		params := map[string]string{
			composeddsa.BoundedCosignerPublicKeyParameter: hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1)),
		}
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
