// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sigconstruction

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/falconparams"
	"github.com/aplane-algo/aplane/internal/witness"
)

const (
	falconKeySize  = falconparams.PublicKeySize
	ed25519KeySize = 32
)

func must(t *testing.T, definition Definition) Construction {
	t.Helper()
	construction, err := New(definition)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return construction
}

func components(primitives ...PrimitiveID) []ComponentSpec {
	specs := make([]ComponentSpec, len(primitives))
	for i, primitive := range primitives {
		specs[i] = ComponentSpec{Name: fmt.Sprintf("part%d", i), Primitive: primitive}
	}
	return specs
}

func TestNewRejectsInvalidDefinitions(t *testing.T) {
	for name, test := range map[string]struct {
		definition Definition
		want       string
	}{
		"no identifier":     {Definition{Components: components(PrimitiveEd25519)}, "identifier is required"},
		"no components":     {Definition{ID: "x"}, "no components"},
		"unnamed component": {Definition{ID: "x", Components: []ComponentSpec{{Primitive: PrimitiveEd25519}}}, "unnamed"},
		"repeated name": {Definition{ID: "x", Components: []ComponentSpec{
			{Name: "a", Primitive: PrimitiveEd25519}, {Name: "a", Primitive: PrimitiveFalcon1024},
		}}, "repeats component"},
		"unknown primitive": {Definition{ID: "x", Components: []ComponentSpec{{Name: "a", Primitive: "unknown"}}}, "unknown primitive"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(test.definition); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSamePrimitiveTwiceNeedsSeparateNames(t *testing.T) {
	construction := must(t, Definition{ID: "x", Components: []ComponentSpec{
		{Name: "first", Primitive: PrimitiveEd25519}, {Name: "second", Primitive: PrimitiveEd25519},
	}})
	if got := construction.Layout().Count(); got != 2 {
		t.Fatalf("Count() = %d", got)
	}
}

func TestDefinitionIsCopied(t *testing.T) {
	specs := components(PrimitiveEd25519, PrimitiveFalcon1024)
	construction := must(t, Definition{ID: "x", Components: specs})
	specs[0].Primitive = PrimitiveFalcon1024
	if got := construction.Layout().MaxSizes(); !slices.Equal(got, []int{64, falconparams.CompressedSignatureMaxSize}) {
		t.Fatalf("MaxSizes() = %v after changing the definition", got)
	}
}

func TestLayoutCannotBeChangedThroughItsViews(t *testing.T) {
	construction := must(t, Definition{ID: "x", Components: components(PrimitiveEd25519)})
	layout := construction.Layout()
	layout.MaxSizes()[0] = 1
	layout.Components()[0].maxSizes[0] = 1
	if got := layout.MaxSizes(); !slices.Equal(got, []int{64}) {
		t.Fatalf("MaxSizes() = %v", got)
	}
}

func TestLayoutConcatenatesComponents(t *testing.T) {
	first := must(t, Definition{ID: "a", Components: components(PrimitiveFalcon1024, PrimitiveEd25519)})
	second := must(t, Definition{ID: "b", Components: components(PrimitiveEd25519, PrimitiveFalcon1024)})
	maxFalcon := falconparams.CompressedSignatureMaxSize
	if got := first.Layout().MaxSizes(); !slices.Equal(got, []int{maxFalcon, 64}) {
		t.Fatalf("Falcon first: %v", got)
	}
	if got := second.Layout().MaxSizes(); !slices.Equal(got, []int{64, maxFalcon}) {
		t.Fatalf("Ed25519 first: %v", got)
	}
}

// No production primitive has several slots, so a local descriptor proves that one
// component is not assumed to be one argument. It is not in the production catalog.
func TestMultiSlotPrimitiveKeepsItsBoundaries(t *testing.T) {
	multi := &primitiveProfile{
		publicKeySize: 4,
		slots:         []argSlot{{maxSize: 32}, {maxSize: 32}},
		render: func(publicKey []byte, firstArg int) string {
			return fmt.Sprintf("arg %d\narg %d\npushbytes 0x%s\nmulti_verify\n", firstArg, firstArg+1, hex.EncodeToString(publicKey))
		},
	}
	profiles := map[PrimitiveID]*primitiveProfile{"multi": multi, PrimitiveEd25519: primitiveProfiles[PrimitiveEd25519]}
	construction, err := newConstruction(Definition{ID: "x", Components: components("multi", PrimitiveEd25519)}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	layout := construction.Layout()
	if layout.Count() != 3 || !slices.Equal(layout.MaxSizes(), []int{32, 32, 64}) {
		t.Fatalf("layout = %d %v", layout.Count(), layout.MaxSizes())
	}
	parts := layout.Components()
	if parts[0].Start != 0 || parts[0].Count() != 2 || parts[1].Start != 2 || parts[1].Count() != 1 {
		t.Fatalf("components = %+v", parts)
	}
	key := append(bytes.Repeat([]byte{1}, 4), bytes.Repeat([]byte{2}, ed25519KeySize)...)
	teal, err := construction.VerifyTEAL(key, "txn TxID", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"arg 1\narg 2\n", "arg 3\npushbytes"} {
		if !strings.Contains(teal, want) {
			t.Fatalf("VerifyTEAL() lacks %q:\n%s", want, teal)
		}
	}
	if _, err := New(Definition{ID: "x", Components: components("multi")}); err == nil {
		t.Fatal("the local descriptor reached the production catalog")
	}
}

func TestVerifyTEALMatchesTheSequencesInUse(t *testing.T) {
	falconKey := bytes.Repeat([]byte{0x11}, falconKeySize)
	edKey := bytes.Repeat([]byte{0x22}, ed25519KeySize)
	falcon, _ := ForBaseKeyType("aplane.falcon1024.v1")
	ed, _ := ForBaseKeyType("aplane.ed25519.v1")

	got, err := falcon.VerifyTEAL(falconKey, "txn TxID", 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "txn TxID\narg 0\npushbytes 0x" + hex.EncodeToString(falconKey) + "\nfalcon_verify\n"; got != want {
		t.Fatalf("Falcon = %q", got)
	}
	got, err = ed.VerifyTEAL(edKey, "txn TxID", 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := "txn TxID\narg 0\npushbytes 0x" + hex.EncodeToString(edKey) + "\ned25519verify_bare\n"; got != want {
		t.Fatalf("Ed25519 = %q", got)
	}
}

// Every component but the last asserts, and the last leaves the one boolean. The
// order is the proof of no primary component: each order renders both checks.
func TestVerifyTEALRequiresEveryComponentInOrder(t *testing.T) {
	falconKey := bytes.Repeat([]byte{0x11}, falconKeySize)
	edKey := bytes.Repeat([]byte{0x22}, ed25519KeySize)
	secondKey := bytes.Repeat([]byte{0x33}, ed25519KeySize)
	joined := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	for name, test := range map[string]struct {
		construction Construction
		key          []byte
		want         []string
	}{
		"Falcon first": {
			must(t, Definition{ID: "a", Components: components(PrimitiveFalcon1024, PrimitiveEd25519)}), joined(falconKey, edKey),
			[]string{"arg 0\npushbytes 0x" + hex.EncodeToString(falconKey) + "\nfalcon_verify\n", "arg 1\npushbytes 0x" + hex.EncodeToString(edKey) + "\ned25519verify_bare\n"},
		},
		"Ed25519 first": {
			must(t, Definition{ID: "b", Components: components(PrimitiveEd25519, PrimitiveFalcon1024)}), joined(edKey, falconKey),
			[]string{"arg 0\npushbytes 0x" + hex.EncodeToString(edKey) + "\ned25519verify_bare\n", "arg 1\npushbytes 0x" + hex.EncodeToString(falconKey) + "\nfalcon_verify\n"},
		},
		"three components": {
			must(t, Definition{ID: "c", Components: components(PrimitiveEd25519, PrimitiveFalcon1024, PrimitiveEd25519)}), joined(edKey, falconKey, secondKey),
			[]string{"arg 0\npushbytes 0x" + hex.EncodeToString(edKey) + "\ned25519verify_bare\n", "arg 1\npushbytes 0x" + hex.EncodeToString(falconKey) + "\nfalcon_verify\n", "arg 2\npushbytes 0x" + hex.EncodeToString(secondKey) + "\ned25519verify_bare\n"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := test.construction.VerifyTEAL(test.key, "txn TxID", 0)
			if err != nil {
				t.Fatal(err)
			}
			want := "txn TxID\n" + strings.Join(test.want, "assert\ntxn TxID\n")
			if got != want {
				t.Fatalf("VerifyTEAL() =\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestVerifyTEALRejectsAWrongKeySize(t *testing.T) {
	construction := must(t, Definition{ID: "x", Components: components(PrimitiveFalcon1024, PrimitiveEd25519)})
	if _, err := construction.VerifyTEAL(make([]byte, falconKeySize), "txn TxID", 0); err == nil {
		t.Fatal("VerifyTEAL() accepted a key missing a component")
	}
	if _, err := construction.VerifyTEAL(make([]byte, falconKeySize+ed25519KeySize+1), "txn TxID", 0); err == nil {
		t.Fatal("VerifyTEAL() accepted a key with trailing bytes")
	}
}

// A zero value never passed New, and rendering it must not report success with no
// signature checks in the program.
func TestZeroConstructionRendersNothing(t *testing.T) {
	var zero Construction
	if teal, err := zero.VerifyTEAL(nil, "txn TxID", 0); err == nil {
		t.Fatalf("VerifyTEAL() = %q, want an error", teal)
	}
	if _, err := zero.SplitPublicKey(nil); err == nil {
		t.Fatal("SplitPublicKey() accepted a zero construction")
	}
	if _, err := zero.PackSignature(make([]byte, 64)); err == nil {
		t.Fatal("PackSignature() accepted a zero construction")
	}
}

func TestPackSignatureKeepsRawSignatures(t *testing.T) {
	falcon, _ := ForBaseKeyType("aplane.falcon1024.v1")
	ed, _ := ForBaseKeyType("aplane.ed25519.v1")
	signature := bytes.Repeat([]byte{7}, 64)
	for name, construction := range map[string]Construction{"Falcon": falcon, "Ed25519": ed} {
		args, err := construction.PackSignature(signature)
		if err != nil || len(args) != 1 || !bytes.Equal(args[0], signature) {
			t.Fatalf("%s PackSignature() = %d args, %v", name, len(args), err)
		}
	}
	if _, err := falcon.PackSignature(nil); err == nil {
		t.Fatal("Falcon accepted an empty signature")
	}
	if _, err := falcon.PackSignature(make([]byte, falconparams.CompressedSignatureMaxSize+1)); err == nil {
		t.Fatal("Falcon accepted an oversized signature")
	}
	if _, err := ed.PackSignature(make([]byte, 63)); err == nil {
		t.Fatal("Ed25519 accepted a short signature")
	}
}

func TestPackSignatureRefusesAnUndefinedEncoding(t *testing.T) {
	construction := must(t, Definition{ID: "x", Components: components(PrimitiveFalcon1024, PrimitiveEd25519)})
	if _, err := construction.PackSignature(make([]byte, 64)); err == nil {
		t.Fatal("PackSignature() invented a multi-component encoding")
	}
}

// The bounded contract froze its Falcon authority sizes separately.
func TestCatalogMatchesTheFrozenAuthoritySizes(t *testing.T) {
	falcon, ok := ForWitnessKeyType(witness.Falcon1024V1)
	if !ok {
		t.Fatal("no construction for the Falcon witness")
	}
	maxSizes := falcon.Layout().MaxSizes()
	if falcon.PublicKeySize() != boundedmeta.CosignerPublicKeySizeV1 || falcon.PublicKeySize() != boundedmeta.FalconAdminPublicKeySize {
		t.Fatalf("PublicKeySize() = %d", falcon.PublicKeySize())
	}
	if !slices.Equal(maxSizes, []int{boundedmeta.CosignerSignatureMaxSizeV1}) || !slices.Equal(maxSizes, []int{boundedmeta.FalconAdminSignatureSize}) {
		t.Fatalf("MaxSizes() = %v", maxSizes)
	}
}

func TestSharesComponentKeyComparesCompatibleComponents(t *testing.T) {
	falconKey := bytes.Repeat([]byte{0x11}, falconKeySize)
	edKey := bytes.Repeat([]byte{0x22}, ed25519KeySize)
	otherFalcon := bytes.Repeat([]byte{0x33}, falconKeySize)
	first := must(t, Definition{ID: "a", Components: components(PrimitiveFalcon1024, PrimitiveEd25519)})
	second := must(t, Definition{ID: "b", Components: components(PrimitiveEd25519, PrimitiveFalcon1024)})
	joined := append(bytes.Clone(falconKey), edKey...)
	reversed := append(bytes.Clone(edKey), otherFalcon...)

	if !SharesComponentKey(first, joined, Falcon1024(), falconKey) {
		t.Fatal("missed a witness key inside a larger construction")
	}
	if !SharesComponentKey(Falcon1024(), falconKey, first, joined) {
		t.Fatal("the comparison depends on argument order")
	}
	if !SharesComponentKey(first, joined, second, reversed) {
		t.Fatal("missed a shared Ed25519 component at a different position")
	}
	if SharesComponentKey(first, joined, Falcon1024(), otherFalcon) {
		t.Fatal("reported a key the construction does not hold")
	}
	if SharesComponentKey(first, joined[1:], Falcon1024(), falconKey) {
		t.Fatal("compared a key that does not parse")
	}
	if SharesComponentKey(Construction{}, nil, Falcon1024(), falconKey) {
		t.Fatal("a zero construction shares a key")
	}
}

// Equal bytes under different primitives are not the same key.
func TestSharesComponentKeyIgnoresOtherPrimitives(t *testing.T) {
	profiles := map[PrimitiveID]*primitiveProfile{
		"other":          {publicKeySize: ed25519KeySize, slots: []argSlot{{maxSize: 64}}},
		PrimitiveEd25519: primitiveProfiles[PrimitiveEd25519],
	}
	other, err := newConstruction(Definition{ID: "x", Components: components("other")}, profiles)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x22}, ed25519KeySize)
	if SharesComponentKey(other, key, Ed25519(), key) {
		t.Fatal("compared components of different primitives")
	}
}

func TestCatalogResolvesProductionIdentifiersOnly(t *testing.T) {
	if construction, ok := ForBaseKeyType(" APLANE.FALCON1024.V1 "); !ok || construction.ID() != "falcon1024" {
		t.Fatalf("ForBaseKeyType() = %q, %v", construction.ID(), ok)
	}
	if construction, ok := ForWitnessKeyType(witness.Falcon1024V1); !ok || construction.ID() != "falcon1024" {
		t.Fatalf("ForWitnessKeyType() = %q, %v", construction.ID(), ok)
	}
	if _, ok := ForBaseKeyType("example.construction-allof.v1"); ok {
		t.Fatal("ForBaseKeyType() resolved a fixture identity")
	}
	if _, ok := ForBaseKeyType(witness.Falcon1024V1); ok {
		t.Fatal("a witness key type resolved as a spending base")
	}
	if _, ok := ForWitnessKeyType("aplane.falcon1024.v1"); ok {
		t.Fatal("a spending base resolved as a witness key type")
	}
}
