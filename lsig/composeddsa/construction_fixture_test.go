// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package composeddsa_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/sigconstruction"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

// fixtureBaseKeyType is a synthetic all-of base. It exists only in these tests:
// no production path can register it, and it is not a product key type.
const fixtureBaseKeyType = "example.construction-allof.v1"

// compositeOps adapts a test construction to the composer. Production constructions
// of several components have no signature encoding, so this encoding is the
// fixture's own: each component's signature with a two-byte length prefix.
type compositeOps struct {
	construction sigconstruction.Construction
}

func (o compositeOps) PublicKeySize() int { return o.construction.PublicKeySize() }
func (o compositeOps) CryptoSignatureSize() int {
	total := 0
	for _, size := range o.construction.Layout().MaxSizes() {
		total += 2 + size
	}
	return total
}
func (o compositeOps) MnemonicScheme() string { return "" }
func (o compositeOps) MnemonicWordCount() int { return 0 }
func (o compositeOps) DisplayColor() string   { return "" }
func (o compositeOps) TEALVersion() int       { return 13 }
func (o compositeOps) BuildVerifyTEAL(publicKey []byte) (string, error) {
	return o.construction.VerifyTEAL(publicKey, "txn TxID", 0)
}
func (o compositeOps) SignatureArgLayout() composeddsa.SignatureArgLayout {
	layout := o.construction.Layout()
	return composeddsa.SignatureArgLayout{Count: layout.Count(), MaxSizes: layout.MaxSizes()}
}
func (o compositeOps) BuildSignatureArgs(signature []byte) ([][]byte, error) {
	var args [][]byte
	for len(signature) > 0 {
		if len(signature) < 2 {
			return nil, fmt.Errorf("truncated fixture signature")
		}
		size := int(binary.BigEndian.Uint16(signature))
		if len(signature) < 2+size {
			return nil, fmt.Errorf("truncated fixture signature")
		}
		args = append(args, signature[2:2+size])
		signature = signature[2+size:]
	}
	return args, nil
}

func encodeCompositeSignature(parts ...[]byte) []byte {
	var encoded []byte
	for _, part := range parts {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(part)))
		encoded = append(encoded, part...)
	}
	return encoded
}

func compositeConstruction(t *testing.T, primitives ...sigconstruction.PrimitiveID) sigconstruction.Construction {
	t.Helper()
	specs := make([]sigconstruction.ComponentSpec, len(primitives))
	for i, primitive := range primitives {
		specs[i] = sigconstruction.ComponentSpec{Name: fmt.Sprintf("part%d", i), Primitive: primitive}
	}
	construction, err := sigconstruction.New(sigconstruction.Definition{ID: "example-allof", Components: specs})
	if err != nil {
		t.Fatalf("sigconstruction.New() error = %v", err)
	}
	return construction
}

func compositeBase(construction sigconstruction.Construction) composeddsa.BaseRegistration {
	return composeddsa.BaseRegistration{
		BaseKeyType: fixtureBaseKeyType,
		FamilyName:  "example.construction-allof",
		Version:     1,
		Ops:         compositeOps{construction: construction},
	}
}

// compositeTemplate returns a bounded template on the fixture base. An extra block
// such as an admin operation or a cosigner goes inside bounded.
func compositeTemplate(extra string) string {
	return `
schema_version: 2
template_type: composed
base_key_type: ` + fixtureBaseKeyType + `
template_mode: strict
publisher: test
family: construction-fixture
version: 1
display_name: Construction Fixture
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay]
  max_fee: 10000
` + extra + `
teal: |
  int 1
  assert
`
}

const (
	spendingKeyRekeyYAML = `  admin_operations:
    - kind: rekey
      authorization: spending_key
      policy_gate: none`
	adminKeyRekeyYAML = `  admin_operations:
    - kind: rekey
      authorization: admin_key
      policy_gate: none`
	cosignerYAML = `  cosigner:
    contract: cosigner1
    required_on: [spend]`
)

func parseCompositeTemplate(t *testing.T, extra string) *composeddsa.TemplateSpec {
	t.Helper()
	spec, err := composeddsa.ParseTemplateSpec([]byte(compositeTemplate(extra)))
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	return spec
}

func compositeProvider(t *testing.T, construction sigconstruction.Construction, extra string, support composeddsa.FixtureSupport) *composeddsa.ComposedDSA {
	t.Helper()
	provider, err := composeddsa.NewFixtureProvider(parseCompositeTemplate(t, extra), compositeBase(construction), support)
	if err != nil {
		t.Fatalf("NewFixtureProvider() error = %v", err)
	}
	return provider
}

// syntheticKey returns a distinct public key for each component. Rendering never
// interprets a key, so these need no private half.
func syntheticKey(construction sigconstruction.Construction) ([]byte, [][]byte) {
	key := make([]byte, construction.PublicKeySize())
	for i := range key {
		key[i] = byte(i%251 + 1)
	}
	parts, err := construction.SplitPublicKey(key)
	if err != nil {
		panic(err)
	}
	return key, parts
}

func compositeFixtures(t *testing.T) map[string]sigconstruction.Construction {
	t.Helper()
	const falconPrimitive, edPrimitive = sigconstruction.PrimitiveFalcon1024, sigconstruction.PrimitiveEd25519
	return map[string]sigconstruction.Construction{
		"Falcon then Ed25519": compositeConstruction(t, falconPrimitive, edPrimitive),
		"Ed25519 then Falcon": compositeConstruction(t, edPrimitive, falconPrimitive),
		"three components":    compositeConstruction(t, edPrimitive, falconPrimitive, edPrimitive),
	}
}

func TestCompositeBaseRequiresEveryComponentInOrder(t *testing.T) {
	for name, construction := range compositeFixtures(t) {
		t.Run(name, func(t *testing.T) {
			provider := compositeProvider(t, construction, spendingKeyRekeyYAML, composeddsa.FixtureSupport{})
			key, parts := syntheticKey(construction)
			teal, err := provider.GenerateTEAL(key, nil)
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			offset := 0
			for i, part := range parts {
				want := fmt.Sprintf("arg %d\npushbytes 0x%s\n", i, hex.EncodeToString(part))
				found := strings.Index(teal[offset:], want)
				if found < 0 {
					t.Fatalf("component %d is missing or out of order:\n%s", i, teal)
				}
				offset += found + len(want)
			}
			metadata, err := provider.BuildBoundedAuthorizationMetadata(key, nil, []byte{1})
			if err != nil {
				t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
			}
			if metadata.BaseSignatureArgLayout.Count != len(parts) {
				t.Fatalf("base layout count = %d, want %d", metadata.BaseSignatureArgLayout.Count, len(parts))
			}
			base := 0
			for _, slot := range metadata.ArgumentLayout {
				if slot.Source == boundedmeta.ArgSourceBaseSignature {
					if slot.Index != base {
						t.Fatalf("base slot %q index = %d, want %d", slot.Name, slot.Index, base)
					}
					base++
				}
			}
			if base != len(parts) {
				t.Fatalf("metadata has %d base slots, want %d", base, len(parts))
			}
		})
	}
}

func TestCompositeArgumentsAreAssembledFromEverySlot(t *testing.T) {
	construction := compositeConstruction(t, sigconstruction.PrimitiveEd25519, sigconstruction.PrimitiveFalcon1024)
	provider := compositeProvider(t, construction, spendingKeyRekeyYAML, composeddsa.FixtureSupport{})
	first, second := bytes.Repeat([]byte{1}, 64), bytes.Repeat([]byte{2}, 1000)
	args, err := provider.BuildArgs(encodeCompositeSignature(first, second), nil)
	if err != nil {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	if len(args) != 2 || !bytes.Equal(args[0], first) || !bytes.Equal(args[1], second) {
		t.Fatalf("BuildArgs() returned %d args", len(args))
	}
	if _, err := provider.BuildArgs(encodeCompositeSignature(first), nil); err == nil {
		t.Fatal("BuildArgs() accepted a missing component")
	}
	if _, err := provider.BuildArgs(encodeCompositeSignature(second, first), nil); err == nil {
		t.Fatal("BuildArgs() accepted oversized component arguments")
	}
}

// The gates read their slot from the layout, so a base of several slots has to
// move them. Their key and signature are still Falcon under bounded1.
func TestAuthorityGatesFollowEveryBaseSlot(t *testing.T) {
	construction := compositeConstruction(t, sigconstruction.PrimitiveFalcon1024, sigconstruction.PrimitiveEd25519)
	key, _ := syntheticKey(construction)
	falconKey := bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1)
	for name, test := range map[string]struct {
		extra     string
		parameter string
		source    string
		heading   string
	}{
		"cosigner": {cosignerYAML, composeddsa.BoundedCosignerPublicKeyParameter, boundedmeta.ArgSourceCosigner, "// Cosigner-authorized pure spend"},
		"admin":    {adminKeyRekeyYAML, composeddsa.BoundedAdminPublicKeyParameter, boundedmeta.ArgSourceAdmin, "// Contract-admin-authorized pure rekey"},
	} {
		t.Run(name, func(t *testing.T) {
			provider := compositeProvider(t, construction, test.extra, composeddsa.FixtureSupport{ExternalAdmin: true, Cosigner: true})
			params := map[string]string{test.parameter: hex.EncodeToString(falconKey)}
			teal, err := provider.GenerateTEAL(key, params)
			if err != nil {
				t.Fatalf("GenerateTEAL() error = %v", err)
			}
			metadata, err := provider.BuildBoundedAuthorizationMetadata(key, params, []byte{1})
			if err != nil {
				t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
			}
			index := -1
			for _, slot := range metadata.ArgumentLayout {
				if string(slot.Source) == test.source {
					index = slot.Index
				}
			}
			if index < 2 {
				t.Fatalf("%s slot index = %d, want one after the base slots", name, index)
			}
			_, gate, found := strings.Cut(teal, test.heading)
			if !found {
				t.Fatalf("program has no %s gate:\n%s", name, teal)
			}
			want := fmt.Sprintf("arg %d\npushbytes 0x%s\nfalcon_verify\nassert\n", index, hex.EncodeToString(falconKey))
			if !strings.Contains(gate, want) {
				t.Fatalf("gate lacks %q", want)
			}
		})
	}
}

func TestProductionRefusesFixtureIdentities(t *testing.T) {
	falcon.RegisterClient()
	ed25519lsig.RegisterClient()
	construction := compositeConstruction(t, sigconstruction.PrimitiveFalcon1024, sigconstruction.PrimitiveEd25519)
	key, _ := syntheticKey(construction)

	if _, ok := sigconstruction.ForBaseKeyType(fixtureBaseKeyType); ok {
		t.Fatal("the production catalog resolved a fixture base")
	}
	if composeddsa.IsBaseRegistered(fixtureBaseKeyType) {
		t.Fatal("a fixture base reached the base registry")
	}
	spec := parseCompositeTemplate(t, spendingKeyRekeyYAML)
	if err := composeddsa.ValidateTemplateSpec(spec); err == nil || !strings.Contains(err.Error(), "not registered as composable") {
		t.Fatalf("ValidateTemplateSpec() error = %v", err)
	}
	if _, err := composeddsa.NewProviderFromTemplateSpec(spec); err == nil {
		t.Fatal("NewProviderFromTemplateSpec() accepted a fixture base")
	}

	// A composer built without the bridge has the production policy, whatever it
	// was given.
	fixture := compositeProvider(t, construction, spendingKeyRekeyYAML, composeddsa.FixtureSupport{})
	unprivileged := composeddsa.NewComposedDSA(composeddsa.Config{
		KeyType:     fixture.KeyType(),
		BaseKeyType: fixtureBaseKeyType,
		FamilyName:  "example.construction-allof",
		Version:     1,
		Ops:         compositeOps{construction: construction},
		Bounded:     fixture.BoundedAuthorizationProfile(),
	})
	if _, err := unprivileged.GenerateTEAL(key, nil); err == nil || !strings.Contains(err.Error(), "cannot be generated on base key type") {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
}

func TestFixturePolicyBelongsToOneComposer(t *testing.T) {
	construction := compositeConstruction(t, sigconstruction.PrimitiveFalcon1024, sigconstruction.PrimitiveEd25519)
	key, _ := syntheticKey(construction)
	params := map[string]string{composeddsa.BoundedAdminPublicKeyParameter: hex.EncodeToString(bytes.Repeat([]byte{0x41}, composeddsa.BoundedAdminPublicKeySize))}

	permitted := compositeProvider(t, construction, adminKeyRekeyYAML, composeddsa.FixtureSupport{ExternalAdmin: true})
	refused := compositeProvider(t, construction, adminKeyRekeyYAML, composeddsa.FixtureSupport{})
	if _, err := permitted.GenerateTEAL(key, params); err != nil {
		t.Fatalf("GenerateTEAL() with fixture support error = %v", err)
	}
	if _, err := refused.GenerateTEAL(key, params); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("GenerateTEAL() without fixture support error = %v", err)
	}
	if composeddsa.ProductionSupportsBase(composeddsa.BoundedContractV1, fixtureBaseKeyType) {
		t.Fatal("a fixture base reached the production policy")
	}
}

func TestEveryProductionBaseResolvesToASupportedConstruction(t *testing.T) {
	falcon.RegisterClient()
	ed25519lsig.RegisterClient()
	bases := composeddsa.RegisteredBaseKeyTypes()
	if len(bases) < 2 {
		t.Fatalf("registered bases = %v", bases)
	}
	for _, base := range bases {
		if !strings.HasPrefix(base, "aplane.") {
			continue // another test in this package registered a stand-in
		}
		construction, ok := sigconstruction.ForBaseKeyType(base)
		if !ok {
			t.Fatalf("registered base %q has no signature construction", base)
		}
		registration, _ := composeddsa.LookupBase(base)
		if got := registration.Ops.PublicKeySize(); got != construction.PublicKeySize() {
			t.Fatalf("%q public key size = %d, construction says %d", base, got, construction.PublicKeySize())
		}
		if !composeddsa.ProductionSupportsBase(composeddsa.BoundedContractV1, base) {
			t.Fatalf("registered base %q has no %s support policy", base, composeddsa.BoundedContractV1)
		}
		if composeddsa.ProductionSupportsBase("bounded-unknown", base) {
			t.Fatalf("base %q has support under a contract nothing reviewed", base)
		}
	}
}
