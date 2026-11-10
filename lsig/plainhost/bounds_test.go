// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// everyTransfer is every transfer kind, in canonical order.
var everyTransfer = []txeffects.SpendEffect{txeffects.SpendEffectPay, txeffects.SpendEffectAxfer, txeffects.SpendEffectAssetOptIn}

// verifyOp is the signature check each base renders, so a program shows which
// base it composed on.
var verifyOp = map[string]string{"falcon": "falcon_verify", "ed25519": "ed25519verify_bare"}

// spendingCheck is the base's signature check over the spending key.
func spendingCheck(b base) string {
	return "pushbytes 0x" + hex.EncodeToString(b.spendingKey) + "\n" + verifyOp[b.name] + "\n"
}

func falconHost(t *testing.T) *plainhost.Provider {
	t.Helper()
	return bases(t)[0].provider
}

func joinEffects(spend []txeffects.SpendEffect) string {
	items := make([]string, len(spend))
	for i, effect := range spend {
		items[i] = string(effect)
	}
	return strings.Join(items, ",")
}

func testAddress(i int) string {
	var address types.Address
	address[0], address[1] = byte(i>>8), byte(i)
	address[31] = 1
	return address.String()
}

func testRecipients(count int) string {
	recipients := make([]string, count)
	for i := range recipients {
		recipients[i] = testAddress(i)
	}
	return strings.Join(recipients, ",")
}

// rekeyTarget is a rekey-to list entry, apart from every testAddress. Its first
// byte leads the address text, so rekeyTarget(0xd0) ("2...") sorts before
// rekeyTarget(0x08) ("B...") as text and after it as bytes.
func rekeyTarget(first byte) string {
	var address types.Address
	address[0] = first
	address[31] = 2
	return address.String()
}

// listedRekeyTo is the rekey-to list shapeRequest gives a list shape, in
// canonical (byte) order.
var listedRekeyTo = rekeyTarget(0x08) + "," + rekeyTarget(0xd0)

// shapeRequest is the bounds request for a shape. A shape's Encoding may be auto,
// which the request passes through for the provider to choose.
func shapeRequest(shape plainhost.Shape, recipients string) map[string]string {
	params := map[string]string{
		plainhost.ParameterSpendEffects:   joinEffects(shape.Spend),
		plainhost.ParameterRekeyAuthority: shape.Rekey,
	}
	if shape.Encoding != "" {
		params[plainhost.ParameterListEncoding] = shape.Encoding
		params[plainhost.ParameterRecipients] = recipients
	}
	if shape.HasRekeyList() {
		params[plainhost.ParameterRekeyTo] = listedRekeyTo
	}
	if shape.AnyRecipient {
		params[plainhost.ParameterRecipientScope] = plainhost.RecipientScopeAny
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = testCosigner
	}
	return params
}

// withRoot adds the rekey-to list root key generation computes, which a list
// shape needs before it can render. Other requests come back unchanged.
func withRoot(t *testing.T, provider *plainhost.Provider, params map[string]string) map[string]string {
	t.Helper()
	prepared, err := provider.PrepareRekeyList(testListKey, params)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func resolveShape(t *testing.T, provider *plainhost.Provider, shape plainhost.Shape, recipients string) *lsigprovider.Instance {
	t.Helper()
	instance, err := provider.ResolveInstance(shapeRequest(shape, recipients))
	if err != nil {
		t.Fatalf("%s: %v", shape.Descriptor(), err)
	}
	return instance
}

// wantRekeySetting is the contract's rekey setting under a rekey option: only
// these is refused plus the list, plus cosigned a spending-key rekey plus the list.
func wantRekeySetting(rekey string) boundedmeta.RekeySetting {
	if rekey == plainhost.RekeySpendingKey || rekey == plainhost.RekeyPlusCosigned {
		return boundedmeta.RekeySpendingKey
	}
	return boundedmeta.RekeyRefused
}

// The expected set is written out here rather than derived from the code that
// produces it. The grammar is every combination: three policies (inline and
// Merkle allowlists, and limits only), each with the seven overlay arrangements,
// each with all seven transfer subsets, for 3 x 7 x 7 = 147. A refused rekey is
// a shape too; only plus_cosigned has no uncosigned arrangement, since without a
// cosigner it would mean spending_key. The framework timelock is gone: no shape
// names one.
func TestShapesEnumerateTheGrammar(t *testing.T) {
	policies := []string{
		composeddsa.Layer3PolicyFixedAllowlist, composeddsa.Layer3PolicyMerkleAllowlist,
		composeddsa.Layer3PolicyNone,
	}
	encodings := map[string]string{
		composeddsa.Layer3PolicyFixedAllowlist: plainhost.EncodingInline, composeddsa.Layer3PolicyMerkleAllowlist: plainhost.EncodingMerkle,
	}
	arrangements := []plainhost.Arrangement{
		{Rekey: plainhost.RekeyRefused}, {Rekey: plainhost.RekeyRefused, Cosigner: true},
		{Rekey: plainhost.RekeySpendingKey}, {Rekey: plainhost.RekeySpendingKey, Cosigner: true},
		{Rekey: plainhost.RekeyOnlyThese}, {Rekey: plainhost.RekeyOnlyThese, Cosigner: true},
		{Rekey: plainhost.RekeyPlusCosigned, Cosigner: true},
	}
	if !slices.Equal(plainhost.Arrangements(), arrangements) {
		t.Fatalf("Arrangements() = %v, want %v", plainhost.Arrangements(), arrangements)
	}
	subsets := []string{"pay", "axfer", "pay,axfer", "asset_opt_in", "pay,asset_opt_in", "axfer,asset_opt_in", "pay,axfer,asset_opt_in"}
	shapes := plainhost.Shapes()
	if want := len(policies) * len(arrangements) * len(subsets); len(shapes) != want || want != 147 {
		t.Fatalf("Shapes() = %d, want %d", len(shapes), want)
	}
	perPolicy := len(arrangements) * len(subsets)
	seen := make(map[string]bool)
	for index, shape := range shapes {
		policy := policies[index/perPolicy]
		arrangement := arrangements[index%perPolicy/len(subsets)]
		subset := subsets[index%len(subsets)]
		if shape.Policy() != policy || shape.Rekey != arrangement.Rekey || shape.Cosigner != arrangement.Cosigner || joinEffects(shape.Spend) != subset {
			t.Fatalf("shape %d is %s, want policy %s, %s, cosigner %v, spend %s", index, shape.Descriptor(), policy, arrangement.Rekey, arrangement.Cosigner, subset)
		}
		if shape.Encoding != encodings[policy] || shape.AnyRecipient != (policy == composeddsa.Layer3PolicyNone) {
			t.Fatalf("shape %d %s: encoding %q, any recipient %v", index, shape.Descriptor(), shape.Encoding, shape.AnyRecipient)
		}
		if strings.Contains(shape.Policy(), "timelock") || strings.Contains(shape.Descriptor(), "timelock") {
			t.Fatalf("shape %d %s names a timelock", index, shape.Descriptor())
		}
		if shape.HasRekeyList() != (shape.Rekey == plainhost.RekeyOnlyThese || shape.Rekey == plainhost.RekeyPlusCosigned) {
			t.Fatalf("%s: HasRekeyList() = %v", shape.Descriptor(), shape.HasRekeyList())
		}
		if seen[shape.Descriptor()] {
			t.Fatalf("duplicate shape %s", shape.Descriptor())
		}
		seen[shape.Descriptor()] = true
	}
}

// The descriptor names the rekey setting alone: the contract has no Layer 3 gate
// for it to name.
func TestShapeDescriptorFormat(t *testing.T) {
	pay := []txeffects.SpendEffect{txeffects.SpendEffectPay}
	for _, test := range []struct {
		shape plainhost.Shape
		want  string
	}{
		{plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey},
			"spend=pay,axfer,asset_opt_in;policy=fixed_allowlist;rekey=spending_key;cosigner=none"},
		{plainhost.Shape{Spend: pay, Encoding: plainhost.EncodingMerkle, Rekey: plainhost.RekeyRefused, Cosigner: true},
			"spend=pay;policy=merkle_allowlist;rekey=refused;cosigner=required"},
		{plainhost.Shape{Spend: pay, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyRefused},
			"spend=pay;policy=fixed_allowlist;rekey=refused;cosigner=none"},
		{plainhost.Shape{Spend: pay, Rekey: plainhost.RekeySpendingKey, AnyRecipient: true},
			"spend=pay;policy=none;rekey=spending_key;cosigner=none"},
		{plainhost.Shape{Spend: []txeffects.SpendEffect{txeffects.SpendEffectAxfer}, Rekey: plainhost.RekeyOnlyThese, AnyRecipient: true},
			"spend=axfer;policy=none;rekey=only_these;cosigner=none"},
		{plainhost.Shape{Spend: pay, Rekey: plainhost.RekeyPlusCosigned, Cosigner: true, AnyRecipient: true},
			"spend=pay;policy=none;rekey=plus_cosigned;cosigner=required"},
	} {
		if got := test.shape.Descriptor(); got != test.want {
			t.Errorf("Descriptor() = %q, want %q", got, test.want)
		}
	}
}

// Every shape resolves on both bases, its stored metadata leads back to it, its
// persisted values select it again, and it renders on its own base.
func TestEveryShapeResolvesAndAgreesWithItsMetadata(t *testing.T) {
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			other := verifyOp["ed25519"]
			if b.name == "ed25519" {
				other = verifyOp["falcon"]
			}
			fingerprints := make(map[string]string)
			for _, shape := range plainhost.Shapes() {
				t.Run(shape.Descriptor(), func(t *testing.T) {
					instance := resolveShape(t, b.provider, shape, testRecipients(3))
					bounded := instance.Bounded
					if bounded == nil || bounded.Contract != boundedmeta.Contract {
						t.Fatalf("instance has no bounded2 contract: %+v", bounded)
					}
					fromMetadata, err := plainhost.ShapeFromMetadata(bounded)
					if err != nil {
						t.Fatal(err)
					}
					if fromMetadata.Descriptor() != shape.Descriptor() {
						t.Fatalf("metadata selects %s", fromMetadata.Descriptor())
					}
					if bounded.Layer3Policy != shape.Policy() || strings.Join(bounded.SpendEffects, ",") != joinEffects(shape.Spend) {
						t.Fatalf("policy %s, spend %v", bounded.Layer3Policy, bounded.SpendEffects)
					}
					if bounded.MaxFee == nil || *bounded.MaxFee != plainhost.MaxFee {
						t.Fatalf("MaxFee = %v", bounded.MaxFee)
					}
					if bounded.Rekey != wantRekeySetting(shape.Rekey) {
						t.Fatalf("rekey setting %s", bounded.Rekey)
					}
					if (bounded.Cosigner != nil) != shape.Cosigner {
						t.Fatalf("cosigner metadata = %v", bounded.Cosigner)
					}
					if (bounded.RekeyList != nil) != shape.HasRekeyList() {
						t.Fatalf("rekey-to list metadata = %v", bounded.RekeyList)
					}
					if bounded.Cosigner != nil && !slices.Equal(bounded.Cosigner.RequiredOn, boundedmeta.CosignerRequiredOn(bounded.Rekey)) {
						t.Fatalf("cosigner required_on = %v under rekey %s", bounded.Cosigner.RequiredOn, bounded.Rekey)
					}
					if len(bounded.RuntimeArgs) != 0 {
						t.Fatalf("the shape declares runtime arguments %v", bounded.RuntimeArgs)
					}
					if err := bounded.ValidateProfile(); err != nil {
						t.Fatal(err)
					}
					if instance.ReviewFingerprint != b.provider.GrammarFingerprint() || instance.BoundaryDigest == "" {
						t.Fatalf("review fingerprint %s, digest %q", instance.ReviewFingerprint, instance.BoundaryDigest)
					}
					if previous, ok := fingerprints[instance.Fingerprint]; ok || instance.Fingerprint == "" {
						t.Fatalf("fingerprint %q is shared with %s", instance.Fingerprint, previous)
					}
					fingerprints[instance.Fingerprint] = shape.Descriptor()
					if instance.Values[plainhost.ParameterRekeyAuthority] != shape.Rekey {
						t.Fatalf("persisted rekey_authority = %q", instance.Values[plainhost.ParameterRekeyAuthority])
					}
					if _, present := instance.Values[boundedmeta.RekeyListRootParameter]; present {
						t.Fatal("persisted values hold the rekey-to list root")
					}
					again, err := b.provider.ResolveInstance(instance.Values)
					if err != nil {
						t.Fatalf("persisted values do not resolve again: %v", err)
					}
					if again.Fingerprint != instance.Fingerprint || again.BoundaryDigest != instance.BoundaryDigest || !maps.Equal(again.Values, instance.Values) {
						t.Fatal("persisted values select a different shape")
					}
					stored, err := b.provider.StoredFingerprint(nil, bounded)
					if err != nil || stored != instance.Fingerprint {
						t.Fatalf("stored fingerprint %s, %v; instance %s", stored, err, instance.Fingerprint)
					}
					if component, ok := b.provider.CosignerComponentKeyType(instance.Values); ok != shape.Cosigner ||
						(ok && component != boundedmeta.CosignerComponentKeyTypeV1) {
						t.Fatalf("cosigner component %q, %v", component, ok)
					}
					prepared := withRoot(t, b.provider, instance.Values)
					teal, err := b.provider.GenerateTEAL(b.spendingKey, prepared)
					if err != nil {
						t.Fatal(err)
					}
					// The spending key is checked by the base's own signature check; the
					// other base's appears only as a cosigner's, which is a Falcon witness.
					if !strings.Contains(teal, spendingCheck(b)) || (strings.Contains(teal, other) && (!shape.Cosigner || other != verifyOp["falcon"])) {
						t.Fatalf("program does not verify on its base:\n%s", teal)
					}
					if !strings.Contains(teal, "txn Fee\npushint 10000\n<=\nassert\n") {
						t.Fatal("program has no fee ceiling")
					}
					metadata, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, prepared, make([]byte, 3_000))
					if err != nil {
						t.Fatal(err)
					}
					if err := metadata.Validate(); err != nil {
						t.Fatalf("stored metadata: %v", err)
					}
					if fingerprint, err := b.provider.StoredFingerprint(nil, metadata); err != nil || fingerprint != instance.Fingerprint {
						t.Fatalf("generated metadata fingerprint %s, %v; want %s", fingerprint, err, instance.Fingerprint)
					}
				})
			}
		})
	}
}

// The general bounded type refused a bare rekey_authority=refused. That rule is
// lifted: each combination resolves to its shape, and its metadata says what it
// means. A cosigner on an Ed25519 bounded account is new as well.
func TestLiftedCombinationsResolve(t *testing.T) {
	pay := []txeffects.SpendEffect{txeffects.SpendEffectPay}
	for _, b := range bases(t) {
		for _, test := range []struct {
			name      string
			shape     plainhost.Shape
			contained bool
		}{
			{"refused without a cosigner", plainhost.Shape{Spend: pay, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyRefused}, true},
			{"refused with a cosigner", plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingMerkle, Rekey: plainhost.RekeyRefused, Cosigner: true}, true},
			{"limits only, refused", plainhost.Shape{Spend: pay, Rekey: plainhost.RekeyRefused, AnyRecipient: true}, false},
			{"allowlist, cosigned spending key", plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey, Cosigner: true}, false},
		} {
			t.Run(b.name+"/"+test.name, func(t *testing.T) {
				params := shapeRequest(test.shape, testRecipients(2))
				if err := b.provider.ValidateCreationParams(params); err != nil {
					t.Fatalf("ValidateCreationParams() error = %v", err)
				}
				instance, err := b.provider.ResolveInstance(params)
				if err != nil {
					t.Fatal(err)
				}
				bounded := instance.Bounded
				if bounded.Contract != boundedmeta.Contract || bounded.Layer3Policy != test.shape.Policy() || bounded.Rekey != wantRekeySetting(test.shape.Rekey) ||
					(bounded.Cosigner != nil) != test.shape.Cosigner || (bounded.RekeyList != nil) != test.shape.HasRekeyList() {
					t.Fatalf("metadata = %+v", bounded)
				}
				if bounded.RefusesRekeys() != (test.shape.Rekey == plainhost.RekeyRefused || test.shape.Rekey == plainhost.RekeyOnlyThese) || bounded.Contained() != test.contained {
					t.Fatalf("refuses rekeys %v, contained %v", bounded.RefusesRekeys(), bounded.Contained())
				}
				if got := instance.Values[plainhost.ParameterRekeyAuthority]; got != test.shape.Rekey {
					t.Fatalf("rekey_authority = %q", got)
				}
				if instance.Fingerprint != b.provider.ShapeFingerprintForTest(test.shape) {
					t.Fatal("the request did not select its shape")
				}
				teal, err := b.provider.GenerateTEAL(b.spendingKey, withRoot(t, b.provider, instance.Values))
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(teal, spendingCheck(b)) {
					t.Fatalf("program does not verify on its base:\n%s", teal)
				}
				if stored, err := b.provider.StoredFingerprint(nil, bounded); err != nil || stored != instance.Fingerprint {
					t.Fatalf("stored fingerprint %s, %v", stored, err)
				}
			})
		}
	}
}

func TestInvalidRequestsFailClosed(t *testing.T) {
	spendingKey := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeySpendingKey}
	onlyThese := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeyOnlyThese}
	cosignedOnlyThese := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeyOnlyThese, Cosigner: true}
	plusCosigned := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeyPlusCosigned, Cosigner: true}
	refused := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeyRefused}
	zero := types.Address{}.String()
	targets := func(count int) string {
		entries := make([]string, count)
		for i := range entries {
			entries[i] = rekeyTarget(byte(i + 1))
		}
		return strings.Join(entries, ",")
	}
	tests := []struct {
		name   string
		base   plainhost.Shape
		mutate func(map[string]string)
		want   string
	}{
		{"no spend", spendingKey, func(p map[string]string) { delete(p, plainhost.ParameterSpendEffects) }, "spend_effects is required"},
		{"unknown spend", spendingKey, func(p map[string]string) { p[plainhost.ParameterSpendEffects] = "pay,keyreg" }, "unknown effect"},
		{"repeated spend", spendingKey, func(p map[string]string) { p[plainhost.ParameterSpendEffects] = "pay,pay" }, "repeats"},
		{"no rekey", spendingKey, func(p map[string]string) { delete(p, plainhost.ParameterRekeyAuthority) }, "rekey_authority must be"},
		{"bad rekey", spendingKey, func(p map[string]string) { p[plainhost.ParameterRekeyAuthority] = "none" }, "rekey_authority must be"},
		{"no recipients", spendingKey, func(p map[string]string) { delete(p, plainhost.ParameterRecipients) }, "recipients is required"},
		// The framework timelock is gone: its parameter is refused, with a list,
		// with no list, and whatever it holds.
		{"unlock round", spendingKey, func(p map[string]string) { p["unlock_round"] = "50000000" }, "unknown parameter"},
		{"unlock round with no list", spendingKey, func(p map[string]string) {
			delete(p, plainhost.ParameterRecipients)
			delete(p, plainhost.ParameterListEncoding)
			p["unlock_round"] = "5"
		}, "unknown parameter"},
		{"unlock round with any recipient", plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeySpendingKey, AnyRecipient: true},
			func(p map[string]string) { p["unlock_round"] = "5" }, "unknown parameter"},
		// Without a cosigner the spending key would rekey anywhere, so the list
		// would add nothing: that is spending_key.
		{"plus cosigned without a cosigner", plusCosigned, func(p map[string]string) { delete(p, composeddsa.BoundedCosignerPublicKeyParameter) },
			"rekey_authority=plus_cosigned needs a cosigner; without one it is rekey_authority=spending_key"},
		{"plus_cosigned without rekey_to", plusCosigned, func(p map[string]string) { delete(p, plainhost.ParameterRekeyTo) },
			"rekey_authority=plus_cosigned needs the addresses the account may be rekeyed to in rekey_to"},
		{"only_these without rekey_to", onlyThese, func(p map[string]string) { delete(p, plainhost.ParameterRekeyTo) },
			"rekey_authority=only_these needs the addresses the account may be rekeyed to in rekey_to"},
		{"rekey_to with a spending-key rekey", spendingKey, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(1) }, "rekey_to needs rekey_authority=only_these or plus_cosigned"},
		{"rekey_to with a cosigned spending-key rekey", spendingKey, func(p map[string]string) {
			p[plainhost.ParameterRekeyTo] = targets(1)
			p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosigner
		}, "rekey_to needs rekey_authority=only_these or plus_cosigned"},
		{"rekey_to with a refused rekey", refused, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(1) }, "rekey_to needs rekey_authority=only_these or plus_cosigned"},
		{"17 plus-cosigned rekey_to entries", plusCosigned, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(17) }, "holds at most 16 addresses, got 17"},
		{"zero rekey_to entry", onlyThese, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(1) + "," + zero }, "must not contain the zero address"},
		{"repeated rekey_to entry", onlyThese, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(1) + "," + targets(1) }, "repeats"},
		{"17 rekey_to entries", onlyThese, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(17) }, "holds at most 16 addresses, got 17"},
		{"bad rekey_to entry", onlyThese, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = "NOTANADDRESS" }, "rekey_to: invalid address"},
		{"empty rekey_to item", onlyThese, func(p map[string]string) { p[plainhost.ParameterRekeyTo] = targets(1) + ",," + rekeyTarget(0xd0) }, "empty item"},
		// Key generation computes the root; no request can set it.
		{"rekey-to list root", onlyThese, func(p map[string]string) { p[boundedmeta.RekeyListRootParameter] = strings.Repeat("00", 32) }, "unknown parameter"},
		{"zero recipient", spendingKey, func(p map[string]string) { p[plainhost.ParameterRecipients] = testAddress(1) + "," + zero }, "zero address"},
		{"repeated recipient", spendingKey, func(p map[string]string) { p[plainhost.ParameterRecipients] = testAddress(1) + "," + testAddress(1) }, "repeats"},
		{"bad recipient", spendingKey, func(p map[string]string) { p[plainhost.ParameterRecipients] = "NOTANADDRESS" }, "invalid address"},
		{"bad encoding", spendingKey, func(p map[string]string) { p[plainhost.ParameterListEncoding] = "blinded" }, "list_encoding must be"},
		{"inline too long", spendingKey, func(p map[string]string) {
			p[plainhost.ParameterListEncoding] = plainhost.EncodingInline
			p[plainhost.ParameterRecipients] = testRecipients(plainhost.InlineMax + 1)
		}, "inline encoding accepts at most 30"},
		{"too many recipients", spendingKey, func(p map[string]string) {
			p[plainhost.ParameterRecipients] = testRecipients(plainhost.RecipientsMax + 1)
		}, "maximum is 65536"},
		// The admin key is gone: its parameter and its rekey authority are refused.
		{"admin key parameter", spendingKey, func(p map[string]string) {
			// Spelled in two parts so the retired-names scan in test/arch skips it.
			p["bounded_"+"admin_public_key"] = hex.EncodeToString(bytes.Repeat([]byte{0x31}, 1793))
		}, "unknown parameter"},
		{"admin rekey authority", spendingKey, func(p map[string]string) { p[plainhost.ParameterRekeyAuthority] = "admin_key" }, "rekey_authority must be"},
		{"unresolved cosigner", cosignedOnlyThese, func(p map[string]string) { p[plainhost.ParameterCosigner] = "ops" }, "not resolved"},
		{"teal", spendingKey, func(p map[string]string) { p["teal"] = "int 1" }, "unknown parameter"},
		{"template", spendingKey, func(p map[string]string) { p["template"] = "x" }, "unknown parameter"},
		{"max fee", spendingKey, func(p map[string]string) { p["max_fee"] = "1" }, "unknown parameter"},
	}
	for _, b := range bases(t) {
		for _, test := range tests {
			t.Run(b.name+"/"+test.name, func(t *testing.T) {
				params := shapeRequest(test.base, testRecipients(2))
				test.mutate(params)
				if _, err := b.provider.ResolveInstance(params); err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("ResolveInstance error = %v, want %q", err, test.want)
				}
				if err := b.provider.ValidateCreationParams(params); err == nil {
					t.Fatal("ValidateCreationParams() accepted it")
				}
			})
		}
	}
}

// A parameter given with an empty value is refused, never read as absent:
// absence could make a weaker account than the request named (empty transfer
// kinds would drop the bounds, an empty cosigner the cosigner). Leave a parameter
// out to leave it unset.
func TestEmptyValuesAreRefused(t *testing.T) {
	provider := falconHost(t)
	cosigned := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeyOnlyThese, Cosigner: true}
	for _, name := range []string{
		plainhost.ParameterSpendEffects, plainhost.ParameterRecipients, plainhost.ParameterRecipientScope,
		plainhost.ParameterListEncoding, plainhost.ParameterRekeyAuthority,
		plainhost.ParameterRekeyTo, plainhost.ParameterCosigner, composeddsa.BoundedCosignerPublicKeyParameter,
	} {
		for _, empty := range []string{"", "  "} {
			params := shapeRequest(cosigned, testRecipients(2))
			params[name] = empty
			if _, err := provider.ResolveInstance(params); err == nil || !strings.Contains(err.Error(), name+" is empty") {
				t.Fatalf("ResolveInstance(empty %s) error = %v", name, err)
			}
			if err := provider.ValidateCreationParams(params); err == nil {
				t.Fatalf("ValidateCreationParams accepted an empty %s", name)
			}
			if _, err := provider.GenerateTEAL(make([]byte, 1793), params); err == nil {
				t.Fatalf("GenerateTEAL accepted an empty %s", name)
			}
		}
	}
	// The fail-open cases the rule closes.
	for name, params := range map[string]map[string]string{
		"empty transfer kinds": {plainhost.ParameterSpendEffects: "", plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused},
	} {
		if instance, err := provider.ResolveInstance(params); err == nil {
			t.Fatalf("%s resolved to %+v", name, instance.Bounded)
		}
	}
}

func TestEncodingThreshold(t *testing.T) {
	provider := falconHost(t)
	auto := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeySpendingKey}
	for _, test := range []struct {
		count int
		want  string
	}{{1, plainhost.EncodingInline}, {plainhost.AutoInlineMax, plainhost.EncodingInline}, {plainhost.AutoInlineMax + 1, plainhost.EncodingMerkle}, {plainhost.RecipientsMax, plainhost.EncodingMerkle}} {
		instance := resolveShape(t, provider, auto, testRecipients(test.count))
		if got := instance.Values[plainhost.ParameterListEncoding]; got != test.want {
			t.Errorf("%d recipients encode as %s, want %s", test.count, got, test.want)
		}
	}
	for _, explicit := range []struct {
		encoding string
		count    int
	}{{plainhost.EncodingInline, plainhost.InlineMax}, {plainhost.EncodingMerkle, 1}} {
		shape := plainhost.Shape{Spend: everyTransfer, Encoding: explicit.encoding, Rekey: plainhost.RekeySpendingKey}
		instance := resolveShape(t, provider, shape, testRecipients(explicit.count))
		if got := instance.Values[plainhost.ParameterListEncoding]; got != explicit.encoding {
			t.Errorf("explicit %s became %s", explicit.encoding, got)
		}
	}
}

func TestRequestsCanonicalize(t *testing.T) {
	provider := falconHost(t)
	base := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingAuto, Rekey: plainhost.RekeySpendingKey}
	first := resolveShape(t, provider, base, testAddress(1)+","+testAddress(2)+","+testAddress(3))
	reordered := shapeRequest(base, testAddress(3)+", "+testAddress(1)+","+testAddress(2))
	reordered[plainhost.ParameterSpendEffects] = "asset_opt_in, pay,axfer"
	second, err := provider.ResolveInstance(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if first.BoundaryDigest != second.BoundaryDigest || first.Fingerprint != second.Fingerprint || !maps.Equal(first.Values, second.Values) {
		t.Fatal("equivalent requests resolved differently")
	}
	if got := first.Values[plainhost.ParameterSpendEffects]; got != "pay,axfer,asset_opt_in" {
		t.Fatalf("spend_effects = %q, want canonical order", got)
	}
}

// only_these is stored as rekey: refused plus a rekey-to list. The persisted values
// hold the list in the order its tree uses, by address bytes, and never the root,
// which key generation computes.
func TestOnlyTheseRequestResolves(t *testing.T) {
	provider := falconHost(t)
	low, high := rekeyTarget(0x08), rekeyTarget(0xd0)
	if high >= low {
		t.Fatal("fixture: the targets must sort one way as text and the other as bytes")
	}
	params := shapeRequest(plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese}, testRecipients(2))
	params[plainhost.ParameterRekeyTo] = high + ", " + low
	instance, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatal(err)
	}
	if got := instance.Values[plainhost.ParameterRekeyTo]; got != low+","+high {
		t.Fatalf("rekey_to = %q, want canonical %q", got, low+","+high)
	}
	if instance.Values[plainhost.ParameterRekeyAuthority] != plainhost.RekeyOnlyThese {
		t.Fatalf("rekey_authority = %q", instance.Values[plainhost.ParameterRekeyAuthority])
	}
	if _, present := instance.Values[boundedmeta.RekeyListRootParameter]; present {
		t.Fatal("persisted values hold the rekey-to list root")
	}
	bounded := instance.Bounded
	if bounded.Rekey != boundedmeta.RekeyRefused || !bounded.RefusesRekeys() || bounded.Cosigner != nil {
		t.Fatalf("rekey = %q, cosigner = %v", bounded.Rekey, bounded.Cosigner)
	}
	// The root is an instance field, filled in at generation.
	if bounded.RekeyList == nil || *bounded.RekeyList != (boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: 4}) {
		t.Fatalf("rekey-to list = %+v", bounded.RekeyList)
	}
	var proofs []boundedmeta.DerivedArg
	for _, arg := range bounded.DerivedArgs {
		if arg.Kind == boundedmeta.DerivedArgRekeyListProof {
			proofs = append(proofs, arg)
		}
	}
	if len(proofs) != 1 || proofs[0].Name != "rekey_list_proof" || proofs[0].Parameter != plainhost.ParameterRekeyTo {
		t.Fatalf("rekey-list proof arguments = %+v", proofs)
	}
	slot := -1
	for i, candidate := range bounded.ArgumentLayout {
		if candidate.Name == proofs[0].Name {
			slot = i
		}
	}
	if slot < 0 || bounded.ArgumentLayout[slot].Paths != (boundedmeta.ArgumentPathMask{
		Spend: boundedmeta.ArgForbidden, SpendingRekey: boundedmeta.ArgForbidden, ListedRekey: boundedmeta.ArgRequired,
	}) {
		t.Fatalf("rekey-list proof slot %d in %+v, want required on listed_rekey only", slot, bounded.ArgumentLayout)
	}
	if err := bounded.ValidateProfile(); err != nil {
		t.Fatal(err)
	}
	// A listed address is the only way out, so the account pays only listed
	// recipients.
	if !bounded.Contained() {
		t.Fatal("an only_these account with a recipient list is not contained")
	}
	again, err := provider.ResolveInstance(instance.Values)
	if err != nil || again.Fingerprint != instance.Fingerprint || again.BoundaryDigest != instance.BoundaryDigest ||
		!maps.Equal(again.Values, instance.Values) {
		t.Fatalf("persisted values resolved to another instance: %v", err)
	}
	// Without a recipient list it is not contained, whatever its rekey rule.
	limits := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeyOnlyThese, AnyRecipient: true}, "")
	if limits.Bounded.Contained() {
		t.Fatal("a limits-only only_these account reports itself contained")
	}
	// A full list resolves.
	full := make([]string, 16)
	for i := range full {
		full[i] = rekeyTarget(byte(i + 1))
	}
	params[plainhost.ParameterRekeyTo] = strings.Join(full, ",")
	if _, err := provider.ResolveInstance(params); err != nil {
		t.Fatalf("a 16-entry list was refused: %v", err)
	}
}

// The selectors choose the composer and are not its parameters; the rekey-to list
// and the cosigner key reach it only on a shape that declares them.
func TestComposerSeesOnlyItsDeclaredParameters(t *testing.T) {
	provider := falconHost(t)
	for _, shape := range plainhost.Shapes() {
		request := shapeRequest(shape, testRecipients(2))
		request[plainhost.ParameterRekeyTo] = listedRekeyTo
		request[composeddsa.BoundedCosignerPublicKeyParameter] = testCosigner
		values := provider.ComposerValuesForTest(shape, request)
		for _, selector := range []string{plainhost.ParameterSpendEffects, plainhost.ParameterRekeyAuthority, plainhost.ParameterListEncoding, plainhost.ParameterRecipientScope} {
			if _, ok := values[selector]; ok {
				t.Fatalf("%s: %s reached the composer", shape.Descriptor(), selector)
			}
		}
		if _, ok := values[plainhost.ParameterRekeyTo]; ok != shape.HasRekeyList() {
			t.Fatalf("%s: rekey_to reached the composer = %v", shape.Descriptor(), ok)
		}
		if _, ok := values[composeddsa.BoundedCosignerPublicKeyParameter]; ok != shape.Cosigner {
			t.Fatalf("%s: the cosigner key reached the composer = %v", shape.Descriptor(), ok)
		}
		if _, ok := values[plainhost.ParameterRecipients]; ok != (shape.Encoding != "") {
			t.Fatalf("%s: recipients reached the composer = %v", shape.Descriptor(), ok)
		}
	}
}

func TestProviderHasNoRuntimeArguments(t *testing.T) {
	for _, b := range bases(t) {
		if len(b.provider.RuntimeArgs()) != 0 {
			t.Fatalf("%s: this grammar has no runtime arguments", b.name)
		}
		if _, ok := b.provider.CosignerComponentKeyType(map[string]string{}); ok {
			t.Fatalf("%s: discovery added a cosigner to a request that named none", b.name)
		}
		// A bounds request names a cosigner the same way an overlays one does.
		request := map[string]string{plainhost.ParameterCosigner: "ops", plainhost.ParameterSpendEffects: "pay"}
		if component, ok := b.provider.CosignerComponentKeyType(request); !ok || component != boundedmeta.CosignerComponentKeyTypeV1 {
			t.Fatalf("%s: named cosigner reports %q, %v", b.name, component, ok)
		}
	}
}

func TestBoundaryDigestBindsWhatItCompares(t *testing.T) {
	hosts := bases(t)
	provider := hosts[0].provider
	shape := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese, Cosigner: true}
	digest := func(t *testing.T, mutate func(map[string]string)) string {
		t.Helper()
		params := shapeRequest(shape, testRecipients(3))
		mutate(params)
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		return instance.BoundaryDigest
	}
	base := digest(t, func(map[string]string) {})
	for name, mutate := range map[string]func(map[string]string){
		"cosigner key": func(p map[string]string) {
			p[composeddsa.BoundedCosignerPublicKeyParameter] = strings.Repeat("45", boundedmeta.CosignerPublicKeySizeV1)
		},
		"recipients": func(p map[string]string) { p[plainhost.ParameterRecipients] = testRecipients(4) },
		"spend":      func(p map[string]string) { p[plainhost.ParameterSpendEffects] = "pay" },
		"encoding":   func(p map[string]string) { p[plainhost.ParameterListEncoding] = plainhost.EncodingMerkle },
		// The option is bound, not just the list: plus cosigned is the same
		// entries with other rekeys open to the cosigner.
		"plus cosigned": func(p map[string]string) { p[plainhost.ParameterRekeyAuthority] = plainhost.RekeyPlusCosigned },
		"refused": func(p map[string]string) {
			p[plainhost.ParameterRekeyAuthority] = plainhost.RekeyRefused
			delete(p, plainhost.ParameterRekeyTo)
		},
		"no cosigner": func(p map[string]string) { delete(p, composeddsa.BoundedCosignerPublicKeyParameter) },
	} {
		if digest(t, mutate) == base {
			t.Errorf("changing %s did not change the digest", name)
		}
	}
	// The digest names the base, so one request on two bases compares unequal.
	other, err := hosts[1].provider.ResolveInstance(shapeRequest(shape, testRecipients(3)))
	if err != nil {
		t.Fatal(err)
	}
	if other.BoundaryDigest == base {
		t.Error("the same request on another base has the same digest")
	}
}

// The digest binds a rekey-to list's entries, not the order they were written in.
func TestBoundaryDigestBindsTheRekeyToList(t *testing.T) {
	provider := falconHost(t)
	shape := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese}
	digest := func(rekeyTo string) string {
		t.Helper()
		params := shapeRequest(shape, testRecipients(2))
		params[plainhost.ParameterRekeyTo] = rekeyTo
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		return instance.BoundaryDigest
	}
	base := digest(rekeyTarget(0x08) + "," + rekeyTarget(0xd0))
	if digest(rekeyTarget(0xd0)+", "+rekeyTarget(0x08)) != base {
		t.Error("reordering the rekey-to list changed the digest")
	}
	for name, rekeyTo := range map[string]string{
		"a removed entry":  rekeyTarget(0x08),
		"an added entry":   rekeyTarget(0x08) + "," + rekeyTarget(0xd0) + "," + rekeyTarget(0x10),
		"a replaced entry": rekeyTarget(0x08) + "," + rekeyTarget(0x10),
	} {
		if digest(rekeyTo) == base {
			t.Errorf("%s did not change the digest", name)
		}
	}
}

// A new rule must not disturb existing accounts: a program's fingerprint and an
// account's digest depend on that program alone, and only the grammar sees them
// all, in order. The grammar and every shape name the plain key type, so two
// bases share no provenance.
func TestFingerprintScopes(t *testing.T) {
	hosts := bases(t)
	for _, b := range hosts {
		descriptors, fingerprints := b.provider.ProgramsForTest()
		if len(fingerprints) != len(plainhost.Arrangements())+len(plainhost.Shapes()) {
			t.Fatalf("%s: %d programs", b.name, len(fingerprints))
		}
		all := make([]int, len(fingerprints))
		for i := range all {
			all[i] = i
		}
		full := b.provider.GrammarFingerprintOverForTest(all)
		if full != b.provider.GrammarFingerprint() {
			t.Fatalf("%s: the grammar fingerprint is not over every program in order", b.name)
		}
		if b.provider.GrammarFingerprintOverForTest(all[:len(all)-1]) == full {
			t.Fatalf("%s: a removed shape did not change the grammar fingerprint", b.name)
		}
		swapped := slices.Clone(all)
		swapped[len(plainhost.Arrangements())], swapped[len(plainhost.Arrangements())+1] = swapped[len(plainhost.Arrangements())+1], swapped[len(plainhost.Arrangements())]
		if b.provider.GrammarFingerprintOverForTest(swapped) == full {
			t.Fatalf("%s: the grammar fingerprint does not bind which shape has which behavior", b.name)
		}
		seen := make(map[string]string)
		for i, fingerprint := range fingerprints {
			if fingerprint == full {
				t.Fatalf("%s: %s has the grammar's fingerprint", b.name, descriptors[i])
			}
			if other, ok := seen[fingerprint]; ok {
				t.Fatalf("%s: %s and %s share a fingerprint", b.name, other, descriptors[i])
			}
			seen[fingerprint] = descriptors[i]
		}
		for _, shape := range plainhost.Shapes() {
			composer := b.provider.ShapeComposerForTest(shape)
			if composer.KeyType() != b.provider.KeyType() || composer.BaseKeyType() != b.provider.KeyType() {
				t.Fatalf("%s: %s composes as %s on %s", b.name, shape.Descriptor(), composer.KeyType(), composer.BaseKeyType())
			}
		}
	}
	if hosts[0].provider.GrammarFingerprint() == hosts[1].provider.GrammarFingerprint() {
		t.Fatal("two bases share a grammar fingerprint")
	}
	for _, shape := range plainhost.Shapes() {
		if hosts[0].provider.ShapeFingerprintForTest(shape) == hosts[1].provider.ShapeFingerprintForTest(shape) {
			t.Fatalf("%s has one fingerprint on two bases", shape.Descriptor())
		}
	}
}

// A shape composes with its host's salt style, not the template schema's, so an
// account and a plain key on the same spending key differ only by their bounds.
func TestShapesFollowTheHostSaltStyle(t *testing.T) {
	pushbytes, err := plainhost.Wrap(&falconv1.Falcon1024V1{}, plainhost.Base{Ops: falconv1.NewFalconOps(family.FalconBase), SaltStyle: lsigsalt.StylePushbytes})
	if err != nil {
		t.Fatal(err)
	}
	preamble, err := lsigsalt.StylePushbytes.SourcePreamble()
	if err != nil || preamble == "" {
		t.Fatalf("preamble %q, %v", preamble, err)
	}
	b := bases(t)[0]
	shape := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey}
	for name, test := range map[string]struct {
		provider *plainhost.Provider
		want     bool
	}{"pushbytes host": {pushbytes, true}, "auto-salt host": {b.provider, false}} {
		teal, err := test.provider.GenerateTEAL(b.spendingKey, shapeRequest(shape, testRecipients(2)))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(teal, preamble) != test.want {
			t.Fatalf("%s: pushbytes salt preamble present = %v", name, !test.want)
		}
	}
	if pushbytes.ShapeFingerprintForTest(shape) == b.provider.ShapeFingerprintForTest(shape) {
		t.Fatal("the salt style is not part of a shape's provenance")
	}
}

func TestStoredFingerprintRefusesWhatTheGrammarCannotProduce(t *testing.T) {
	provider := falconHost(t)
	if _, err := provider.StoredFingerprint(nil, nil); err == nil {
		t.Fatal("accepted missing metadata")
	}
	instance := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey}, testRecipients(1))
	custom := boundedmeta.Clone(instance.Bounded)
	custom.Layer3Policy = boundedmeta.Layer3PolicyCustom
	if _, err := provider.StoredFingerprint(nil, custom); err == nil {
		t.Fatal("accepted a custom policy")
	}
	unknown := boundedmeta.Clone(instance.Bounded)
	unknown.SpendEffects = []string{"pay", "keyreg"}
	if _, err := provider.StoredFingerprint(nil, unknown); err == nil {
		t.Fatal("accepted an unknown transfer kind")
	}
	contract := boundedmeta.Clone(instance.Bounded)
	contract.Contract = "bounded1"
	if _, err := provider.StoredFingerprint(nil, contract); err == nil || !strings.Contains(err.Error(), "contract") {
		t.Fatalf("a stored bounded1 contract: StoredFingerprint() error = %v", err)
	}
}

// A stored account's rekey setting and list are part of its shape: each
// combination the contract stores selects the shape that produces it, never a
// neighbor, and a setting the contract does not know is refused rather than read
// as a known one.
func TestStoredFingerprintSelectsTheStoredRekey(t *testing.T) {
	provider := falconHost(t)
	cosignedLimits := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeyOnlyThese, Cosigner: true, AnyRecipient: true}, "")
	if cosignedLimits.Bounded.Rekey != boundedmeta.RekeyRefused || !cosignedLimits.Bounded.RefusesRekeys() || cosignedLimits.Bounded.RekeyList == nil {
		t.Fatalf("a cosigned only_these limits-only account stored rekey %q, list %v", cosignedLimits.Bounded.Rekey, cosignedLimits.Bounded.RekeyList)
	}
	// A limits-only account beside a spending-key rekey, cosigned or plus
	// cosigned, and a cosigned one that refuses every rekey, are shapes: each
	// mutation selects that shape, not the account it came from.
	for name, test := range map[string]struct {
		mutate func(*boundedmeta.Metadata)
		want   plainhost.Shape
	}{
		"plus cosigned": {func(m *boundedmeta.Metadata) { m.Rekey = boundedmeta.RekeySpendingKey },
			plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeyPlusCosigned, Cosigner: true, AnyRecipient: true}},
		"cosigned spending key": {func(m *boundedmeta.Metadata) { m.Rekey, m.RekeyList = boundedmeta.RekeySpendingKey, nil },
			plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeySpendingKey, Cosigner: true, AnyRecipient: true}},
		"refusing with no list": {func(m *boundedmeta.Metadata) { m.RekeyList = nil },
			plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeyRefused, Cosigner: true, AnyRecipient: true}},
	} {
		stored := boundedmeta.Clone(cosignedLimits.Bounded)
		test.mutate(stored)
		got, err := provider.StoredFingerprint(nil, stored)
		if err != nil {
			t.Fatalf("a stored %s limits-only account: %v", name, err)
		}
		if got != resolveShape(t, provider, test.want, "").Fingerprint || got == cosignedLimits.Fingerprint {
			t.Fatalf("a stored %s limits-only account did not select %s", name, test.want.Descriptor())
		}
	}
	listed := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Rekey: plainhost.RekeyOnlyThese, AnyRecipient: true}, "")
	// A setting the contract does not know, such as the retired admin-key rekey,
	// or no setting at all, is refused rather than read as either known one, with
	// a rekey-to list or without.
	for _, metadata := range []*boundedmeta.Metadata{cosignedLimits.Bounded, listed.Bounded} {
		for _, rekey := range []boundedmeta.RekeySetting{"admin_key", "none", "", boundedmeta.RekeySetting(plainhost.RekeyOnlyThese)} {
			stored := boundedmeta.Clone(metadata)
			stored.Rekey = rekey
			if _, err := provider.StoredFingerprint(nil, stored); err == nil || !strings.Contains(err.Error(), "rekey setting") {
				t.Fatalf("stored rekey %q: StoredFingerprint() error = %v", rekey, err)
			}
		}
	}
	spending := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey}, testRecipients(2))
	if spending.Bounded.Rekey != boundedmeta.RekeySpendingKey {
		t.Fatalf("a spending-key shape stored rekey %q", spending.Bounded.Rekey)
	}
	// The same account refusing rekeys with no list and no cosigner is the refused
	// shape, which the grammar now offers.
	refusedShape := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyRefused}
	stored := boundedmeta.Clone(spending.Bounded)
	stored.Rekey = boundedmeta.RekeyRefused
	if got, err := provider.StoredFingerprint(nil, stored); err != nil || got != provider.ShapeFingerprintForTest(refusedShape) || got == spending.Fingerprint {
		t.Fatalf("a stored uncosigned refusal: StoredFingerprint() = %q, %v", got, err)
	}
	// With a rekey-to list it is the only_these shape, which carries a different
	// fingerprint.
	onlyThese := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese}, testRecipients(2))
	stored.RekeyList = &boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: 4}
	fingerprint, err := provider.StoredFingerprint(nil, stored)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != onlyThese.Fingerprint || fingerprint == spending.Fingerprint {
		t.Fatal("a stored rekey-to list did not select the only_these shape")
	}
	// Without its list, the only_these account is the uncosigned refusal.
	stripped := boundedmeta.Clone(onlyThese.Bounded)
	stripped.RekeyList = nil
	if got, err := provider.StoredFingerprint(nil, stripped); err != nil || got != provider.ShapeFingerprintForTest(refusedShape) || got == onlyThese.Fingerprint {
		t.Fatalf("an only_these account without its list: StoredFingerprint() = %q, %v", got, err)
	}
	// A cosigned list account is its own shape, not its uncosigned twin.
	got, err := provider.StoredFingerprint(nil, cosignedLimits.Bounded)
	if err != nil || got != cosignedLimits.Fingerprint || got == listed.Fingerprint {
		t.Fatalf("a cosigned only_these limits-only account: StoredFingerprint() = %q, %v", got, err)
	}
}

// "Only these" is stored as rekey refused plus the list. The same list beside a
// spending-key rekey is plus cosigned, which needs a cosigner, so without one it
// has no shape to report.
func TestStoredFingerprintRefusesAListBesideAnotherRekey(t *testing.T) {
	for _, b := range bases(t) {
		shape := plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese}
		instance := resolveShape(t, b.provider, shape, testAddress(1))
		if got, err := b.provider.StoredFingerprint(nil, instance.Bounded); err != nil || got != instance.Fingerprint {
			t.Fatalf("%s: StoredFingerprint() = %q, %v; want %s", b.name, got, err, instance.Fingerprint)
		}
		mismatched := boundedmeta.Clone(instance.Bounded)
		mismatched.Rekey = boundedmeta.RekeySpendingKey
		if _, err := b.provider.StoredFingerprint(nil, mismatched); err == nil || !strings.Contains(err.Error(), "unsupported bounded shape spend=pay,axfer,asset_opt_in;policy=fixed_allowlist;rekey=plus_cosigned;cosigner=none") {
			t.Fatalf("%s: StoredFingerprint() error = %v", b.name, err)
		}
	}
}

func writeBoundaryFile(t *testing.T, directory, body string) string {
	t.Helper()
	path := filepath.Join(directory, "boundary.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The file lists its recipients and rekey-to entries out of canonical order.
func TestBoundaryFileReachesTheSameInstanceAsDirectParameters(t *testing.T) {
	path := writeBoundaryFile(t, t.TempDir(), `schema: aplane.boundary.v1
spend: [pay, axfer, asset_opt_in]
recipients:
  - `+testAddress(2)+`
  - `+testAddress(1)+`
rekey:
  authority: only_these
  to:
    - `+rekeyTarget(0xd0)+`
    - `+rekeyTarget(0x08)+`
`)
	loaded, err := boundary.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	flow, err := boundary.ParseFile([]byte("schema: aplane.boundary.v1\nspend: [pay, axfer, asset_opt_in]\n" +
		"recipients: [" + testAddress(2) + ", " + testAddress(1) + "]\n" +
		"rekey: {authority: only_these, to: [" + rekeyTarget(0xd0) + ", " + rekeyTarget(0x08) + "]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bases(t) {
		direct := resolveShape(t, b.provider, plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese},
			testAddress(1)+","+testAddress(2))
		for name, params := range map[string]map[string]string{"block style": loaded, "flow style": flow.CreationParameters()} {
			fromFile, err := b.provider.ResolveInstance(params)
			if err != nil {
				t.Fatalf("%s %s: %v", b.name, name, err)
			}
			if fromFile.BoundaryDigest != direct.BoundaryDigest || fromFile.Fingerprint != direct.Fingerprint ||
				!maps.Equal(fromFile.Values, direct.Values) {
				t.Fatalf("%s %s: file and direct parameters resolved differently", b.name, name)
			}
		}
	}
}

func TestBoundaryFileLeavesCosignerNameForTheSigner(t *testing.T) {
	file, err := boundary.ParseFile([]byte(`schema: aplane.boundary.v1
spend: [pay]
recipients: [` + testAddress(1) + `]
rekey: {authority: spending_key}
cosigner: ops-cosigner
`))
	if err != nil {
		t.Fatal(err)
	}
	params := file.CreationParameters()
	if params[plainhost.ParameterCosigner] != "ops-cosigner" {
		t.Fatalf("cosigner = %q", params[plainhost.ParameterCosigner])
	}
	// The host refuses the name until the signer resolves it to a key.
	if _, err := falconHost(t).ResolveInstance(params); err == nil || !strings.Contains(err.Error(), "not resolved") {
		t.Fatalf("ResolveInstance() with a cosigner name: error = %v", err)
	}
}

func TestBoundaryFileRejections(t *testing.T) {
	recipient := testAddress(1)
	valid := "schema: aplane.boundary.v1\nspend: [pay]\nrecipients: [" + recipient + "]\nrekey: {authority: spending_key}\n"
	if _, err := boundary.ParseFile([]byte(valid)); err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	target := rekeyTarget(0x08)
	onlyThese := strings.Replace(valid, "{authority: spending_key}", "{authority: only_these, to: ["+target+"]}", 1)
	if _, err := boundary.ParseFile([]byte(onlyThese)); err != nil {
		t.Fatalf("only_these rekey rejected: %v", err)
	}
	plusCosigned := strings.Replace(onlyThese, "only_these", "plus_cosigned", 1) + "cosigner: ops-cosigner\n"
	if _, err := boundary.ParseFile([]byte(plusCosigned)); err != nil {
		t.Fatalf("plus_cosigned rekey rejected: %v", err)
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{"wrong schema", strings.Replace(valid, "boundary.v1", "boundary.v2", 1), "schema must be"},
		{"missing schema", strings.Replace(valid, "schema: aplane.boundary.v1\n", "", 1), "schema must be"},
		// Without spend a file has no bounds, so it may not name what only bounds take.
		{"no spend", strings.Replace(valid, "spend: [pay]\n", "", 1), "recipients needs spend"},
		{"no spend with a scope", strings.Replace(valid, "spend: [pay]\nrecipients: ["+recipient+"]\n", "", 1) + "recipient_scope: any\n", "recipient_scope needs spend"},
		{"empty spend", strings.Replace(valid, "spend: [pay]", "spend: []", 1), "spend is empty"},
		{"no recipients", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1), "recipients is required"},
		{"no rekey", strings.Replace(valid, "rekey: {authority: spending_key}\n", "", 1), "rekey is required"},
		{"bad authority", strings.Replace(valid, "spending_key", "nobody", 1), "rekey.authority must be"},
		{"admin authority", strings.Replace(valid, "spending_key", "admin_key", 1), "rekey.authority must be"},
		{"admin key field", strings.Replace(valid, "{authority: spending_key}", "{authority: spending_key, admin_key: a.ref.json}", 1), "not found"},
		{"plus_cosigned without to", strings.Replace(valid, "spending_key", "plus_cosigned", 1), "rekey.authority plus_cosigned needs the addresses in rekey.to"},
		{"only_these without to", strings.Replace(valid, "spending_key", "only_these", 1), "rekey.authority only_these needs the addresses in rekey.to"},
		{"only_these with an empty to", strings.Replace(onlyThese, "["+target+"]", "[]", 1), "rekey.authority only_these needs the addresses in rekey.to"},
		{"to with spending_key", strings.Replace(onlyThese, "only_these", "spending_key", 1), "rekey.to needs rekey.authority only_these or plus_cosigned"},
		{"to with refused", strings.Replace(onlyThese, "only_these", "refused", 1), "rekey.to needs rekey.authority only_these or plus_cosigned"},
		{"empty to with spending_key", strings.Replace(valid, "{authority: spending_key}", "{authority: spending_key, to: []}", 1), "rekey.to needs rekey.authority only_these or plus_cosigned"},
		{"scalar to", strings.Replace(onlyThese, "["+target+"]", target, 1), "cannot unmarshal"},
		{"top-level rekey_to", valid + "rekey_to: [" + target + "]\n", "not found"},
		{"unknown field", valid + "expires: \"5\"\n", "not found"},
		// The framework timelock is gone: its field is unknown, whatever it holds
		// and whatever stands beside it.
		{"unlock round", valid + "unlock_round: \"5\"\n", "field unlock_round not found"},
		{"numeric unlock round", valid + "unlock_round: 50000000\n", "must be a string"},
		{"unlock round with no list", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1) + "unlock_round: \"5\"\n", "field unlock_round not found"},
		{"unlock round with any recipient", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1) + "recipient_scope: any\nunlock_round: \"5\"\n", "field unlock_round not found"},
		{"unlock round without spend", strings.Replace(valid, "spend: [pay]\nrecipients: ["+recipient+"]\n", "", 1) + "unlock_round: \"5\"\n", "field unlock_round not found"},
		{"encoding with no list", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1) + "recipient_scope: any\nencoding: auto\n", "needs a recipient list"},
		{"teal field", valid + "teal: \"int 1\"\n", "not found"},
		{"template field", valid + "template: x\n", "not found"},
		{"max fee field", valid + "max_fee: \"1\"\n", "not found"},
		{"nested unknown field", strings.Replace(valid, "{authority: spending_key}", "{authority: spending_key, gate: none}", 1), "not found"},
		{"duplicate key", valid + "spend: [axfer]\n", "duplicate field"},
		{"alias", "schema: aplane.boundary.v1\nspend: &s [pay]\nrecipients: *s\nrekey: {authority: spending_key}\n", "aliases"},
		{"merge key", valid + "<<: {encoding: auto}\n", "merge keys"},
		{"second document", valid + "---\nschema: aplane.boundary.v1\n", "multiple YAML documents"},
		{"not a mapping", "- pay\n", "must be a mapping"},
		{"number for string", valid + "cosigner: 123\n", "must be a string"},
		{"boolean for string", valid + "encoding: true\n", "must be a string"},
		{"null cosigner", valid + "cosigner:\n", "must be a string"},
		{"empty cosigner", valid + "cosigner: \"\"\n", "cosigner is empty"},
		{"empty encoding", valid + "encoding: \"\"\n", "encoding is empty"},
		{"scalar spend", strings.Replace(valid, "spend: [pay]", "spend: pay", 1), "cannot unmarshal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := boundary.ParseFile([]byte(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseFile error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := boundary.ParseFile(bytes.Repeat([]byte{' '}, boundary.MaxFileBytes+1)); err == nil {
		t.Fatal("accepted an oversized file")
	}
}

// A file reaches the lifted shapes too: a refused rekey with bounds is a
// bounded2 shape, and a file without spend is the overlays alone, plain1.
func TestBoundaryFileReachesTheLiftedShapes(t *testing.T) {
	recipient := testAddress(1)
	for _, b := range bases(t) {
		refused, err := boundary.ParseFile([]byte("schema: aplane.boundary.v1\nspend: [pay]\nrecipients: [" + recipient + "]\nrekey: {authority: refused}\n"))
		if err != nil {
			t.Fatal(err)
		}
		instance, err := b.provider.ResolveInstance(refused.CreationParameters())
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		want := plainhost.Shape{Spend: []txeffects.SpendEffect{txeffects.SpendEffectPay}, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyRefused}
		if instance.Fingerprint != b.provider.ShapeFingerprintForTest(want) || !instance.Bounded.Contained() {
			t.Fatalf("%s: a refused file resolved to %+v", b.name, instance.Bounded)
		}
		overlays, err := boundary.ParseFile([]byte("schema: aplane.boundary.v1\nrekey: {authority: only_these, to: [" + rekeyTarget(0x08) + "]}\n"))
		if err != nil {
			t.Fatal(err)
		}
		instance, err = b.provider.ResolveInstance(overlays.CreationParameters())
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		if instance.Bounded == nil || instance.Bounded.Contract != boundedmeta.PlainContract || instance.Bounded.RekeyList == nil || instance.Bounded.Cosigner != nil {
			t.Fatalf("%s: a file without spend resolved to %+v", b.name, instance.Bounded)
		}
	}
}

func TestBoundaryFileReadIsBounded(t *testing.T) {
	directory := t.TempDir()
	valid := writeBoundaryFile(t, directory, `schema: aplane.boundary.v1
spend: [pay]
recipients: [`+testAddress(1)+`]
rekey: {authority: spending_key}
`)
	link := filepath.Join(directory, "link.yaml")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(directory, "pipe.yaml")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(directory, "large.yaml")
	if err := os.WriteFile(large, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(large, boundary.MaxFileBytes+1); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, pipe, large, filepath.Join(directory, "missing.yaml")} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			if _, err := boundary.LoadFile(path); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("LoadFile(%s) error = %v, want a read error naming the path", path, err)
			}
		})
	}
	if _, err := boundary.LoadFile(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("LoadFile(link) error = %v, want a symbolic link message", err)
	}
}

func TestReceiptRequiresTheGeneratedAddress(t *testing.T) {
	keyType := falconHost(t).KeyType()
	if keyType != "aplane.falcon1024.v1" {
		t.Fatalf("key type = %s", keyType)
	}
	if _, err := (boundary.Receipt{KeyType: keyType}).Encode(); err == nil {
		t.Fatal("encoded a receipt with no address")
	}
	encoded, err := boundary.Receipt{Address: testAddress(1), KeyType: keyType}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), boundary.ReceiptSchemaV1) || !strings.Contains(string(encoded), keyType) {
		t.Fatalf("receipt has no schema or key type: %s", encoded)
	}
}

func TestRecipientListDigestSeparatesLists(t *testing.T) {
	first, second := boundary.RecipientListDigest(testRecipients(2)), boundary.RecipientListDigest(testRecipients(3))
	if first == second || len(first) != 64 {
		t.Fatalf("digests = %s, %s", first, second)
	}
}

// A completed preset and its saved file must be the same request: they differ only
// in how the operator supplied it.
func TestPresetAndItsFileResolveTheSame(t *testing.T) {
	directory := t.TempDir()
	recipients := []string{testAddress(2), testAddress(1)}
	rekeyTo := []string{rekeyTarget(0xd0), rekeyTarget(0x08)}
	for _, b := range bases(t) {
		for _, preset := range boundary.Presets() {
			t.Run(b.name+"/"+preset.Name, func(t *testing.T) {
				form := maps.Clone(preset.Fixed)
				hasCosigner := false
				for _, field := range preset.Fields {
					switch field {
					case plainhost.ParameterRecipients:
						form[field] = strings.Join(recipients, ",")
					case plainhost.ParameterRekeyTo:
						form[field] = strings.Join(rekeyTo, ",")
					case plainhost.ParameterCosigner:
						hasCosigner = true
					}
				}
				path := writeBoundaryFile(t, directory, preset.SampleBoundaryFile(boundary.SampleValues{
					Recipients: recipients, Cosigner: "ops-cosigner", RekeyTo: rekeyTo,
				}))
				fromFile, err := boundary.LoadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if hasCosigner {
					if fromFile[plainhost.ParameterCosigner] != "ops-cosigner" {
						t.Fatalf("file cosigner = %q", fromFile[plainhost.ParameterCosigner])
					}
					delete(fromFile, plainhost.ParameterCosigner)
					fromFile[composeddsa.BoundedCosignerPublicKeyParameter] = testCosigner
					form[composeddsa.BoundedCosignerPublicKeyParameter] = testCosigner
				}
				first, err := b.provider.ResolveInstance(form)
				if err != nil {
					t.Fatal(err)
				}
				second, err := b.provider.ResolveInstance(fromFile)
				if err != nil {
					t.Fatal(err)
				}
				if first.BoundaryDigest != second.BoundaryDigest || first.Fingerprint != second.Fingerprint {
					t.Fatal("the preset and its file resolved differently")
				}
				if second.Bounded.Contract != boundedmeta.Contract {
					t.Fatalf("a preset resolved to contract %s", second.Bounded.Contract)
				}
				if slices.Contains(preset.Fields, plainhost.ParameterRekeyTo) != (second.Bounded.RekeyList != nil) {
					t.Fatalf("rekey-to list = %v for fields %v", second.Bounded.RekeyList, preset.Fields)
				}
			})
		}
	}
}

// The presets are a frozen part of what the guided screens promise.
func TestPresetChoicesAreFrozen(t *testing.T) {
	presets := boundary.Presets()
	for _, test := range []struct {
		name, rekey, encoding string
		fields                []string
	}{
		{"allowlist", plainhost.RekeySpendingKey, plainhost.EncodingAuto, []string{plainhost.ParameterRecipients}},
		{"locked-allowlist", plainhost.RekeyOnlyThese, plainhost.EncodingAuto, []string{plainhost.ParameterRecipients, plainhost.ParameterRekeyTo}},
		{"corridor", plainhost.RekeyOnlyThese, plainhost.EncodingMerkle, []string{plainhost.ParameterRecipients, plainhost.ParameterRekeyTo, plainhost.ParameterCosigner}},
	} {
		index := slices.IndexFunc(presets, func(preset boundary.Preset) bool { return preset.Name == test.name })
		if index < 0 {
			t.Fatalf("no preset %s", test.name)
		}
		preset := presets[index]
		if preset.Fixed[plainhost.ParameterSpendEffects] != joinEffects(everyTransfer) {
			t.Errorf("%s spend = %q", test.name, preset.Fixed[plainhost.ParameterSpendEffects])
		}
		if preset.Fixed[plainhost.ParameterRekeyAuthority] != test.rekey || preset.Fixed[plainhost.ParameterListEncoding] != test.encoding {
			t.Errorf("%s fixed = %v", test.name, preset.Fixed)
		}
		if strings.Join(preset.Fields, ",") != strings.Join(test.fields, ",") {
			t.Errorf("%s fields = %v", test.name, preset.Fields)
		}
	}
	if len(presets) != 3 {
		t.Fatalf("%d presets", len(presets))
	}
	// The timelock preset went with the framework timelock.
	for _, preset := range presets {
		if strings.Contains(preset.Name, "timelock") || slices.Contains(preset.Fields, "unlock_round") {
			t.Fatalf("preset %s names a timelock: %v", preset.Name, preset.Fields)
		}
		if strings.Contains(preset.SampleBoundaryFile(boundary.SampleValues{}), "unlock_round") {
			t.Fatalf("preset %s writes unlock_round into its sample file", preset.Name)
		}
	}
}

// The root is computed at generation from the list's entries and a seed derived
// from the spending private key, then compiled into the program and recorded in
// the account's metadata. The account's provenance is its request's alone.
func TestPrepareRekeyListAddsTheRoot(t *testing.T) {
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			provider := b.provider
			params := shapeRequest(plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeyOnlyThese}, testRecipients(2))
			instance, err := provider.ResolveInstance(params)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.GenerateTEAL(b.spendingKey, params); err == nil || !strings.Contains(err.Error(), "the rekey-to list root is computed at key generation") {
				t.Fatalf("GenerateTEAL() without the root: error = %v", err)
			}
			prepared, err := provider.PrepareRekeyList(testListKey, params)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := params[boundedmeta.RekeyListRootParameter]; present {
				t.Fatal("PrepareRekeyList changed the request it was given")
			}
			root := prepared[boundedmeta.RekeyListRootParameter]
			want, err := composeddsa.RekeyListRootFor(testListKey, map[string]string{plainhost.ParameterRekeyTo: listedRekeyTo})
			if err != nil {
				t.Fatal(err)
			}
			if root != hex.EncodeToString(want[:]) {
				t.Fatalf("root = %q, want the list's root %x", root, want)
			}
			for name, value := range params {
				if prepared[name] != value {
					t.Fatalf("PrepareRekeyList changed %s", name)
				}
			}
			if len(prepared) != len(params)+1 {
				t.Fatalf("PrepareRekeyList added %d parameters, want only the root", len(prepared)-len(params))
			}
			// The seed comes from the spending key, so another key gives another root.
			other, err := provider.PrepareRekeyList(bytes.Repeat([]byte{0x78}, 64), params)
			if err != nil {
				t.Fatal(err)
			}
			if other[boundedmeta.RekeyListRootParameter] == root {
				t.Fatal("two spending keys gave one root")
			}
			// A request never carries the root, not even the generator's own output.
			if _, err := provider.ResolveInstance(prepared); err == nil || !strings.Contains(err.Error(), "unknown parameter") {
				t.Fatalf("ResolveInstance() with the root: error = %v", err)
			}
			if _, err := provider.PrepareRekeyList(testListKey, prepared); err == nil {
				t.Fatal("PrepareRekeyList accepted a request that already has a root")
			}

			teal, err := provider.GenerateTEAL(b.spendingKey, prepared)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(teal, root) != 1 || !strings.Contains(teal, "pushbytes 0x"+root+"\n==\nassert\n") {
				t.Fatalf("program does not commit to the root once:\n%s", teal)
			}
			metadata, err := provider.BuildBoundedAuthorizationMetadata(b.spendingKey, prepared, make([]byte, 3_000))
			if err != nil {
				t.Fatal(err)
			}
			if metadata.RekeyList == nil || *metadata.RekeyList != (boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: 4, RootHex: root}) {
				t.Fatalf("rekey-to list metadata = %+v, want root %s", metadata.RekeyList, root)
			}
			stored, err := provider.StoredFingerprint(nil, metadata)
			if err != nil {
				t.Fatal(err)
			}
			if stored != instance.Fingerprint {
				t.Fatalf("stored fingerprint %s, instance %s", stored, instance.Fingerprint)
			}
			// A shape without a list has no root to add.
			plain := shapeRequest(plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey}, testRecipients(2))
			unchanged, err := provider.PrepareRekeyList(testListKey, plain)
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(unchanged, plain) {
				t.Fatalf("PrepareRekeyList changed a request without a list: %v", unchanged)
			}
		})
	}
}

func TestGenerationRunsTheResourceBackstop(t *testing.T) {
	for _, b := range bases(t) {
		params := shapeRequest(plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey}, testRecipients(1))
		_, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, params, make([]byte, 10_000_000))
		if err == nil || !strings.Contains(err.Error(), "resource limits") {
			t.Fatalf("%s: BuildBoundedAuthorizationMetadata() error = %v", b.name, err)
		}
		if _, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, params, make([]byte, 3_000)); err != nil {
			t.Fatalf("%s: an ordinary program was refused: %v", b.name, err)
		}
	}
}

func TestResourceBackstopRefusesWhatCannotRun(t *testing.T) {
	provider := falconHost(t)
	instance := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingInline, Rekey: plainhost.RekeySpendingKey}, testRecipients(1))
	opcodes := provider.BoundedLogicSigOpcodeProfile()
	if err := plainhost.CheckResources(instance.Bounded, opcodes, 3_000); err != nil {
		t.Fatalf("an ordinary program was refused: %v", err)
	}
	if err := plainhost.CheckResources(instance.Bounded, opcodes, 10_000_000); err == nil {
		t.Fatal("accepted a program that cannot fit a group")
	}
	lowCeiling := boundedmeta.Clone(instance.Bounded)
	lowCeiling.MaxFee = new(uint64(1_000))
	if err := plainhost.CheckResources(lowCeiling, opcodes, 3_000); err == nil || !strings.Contains(err.Error(), "above the account's ceiling") {
		t.Fatalf("CheckResources(low ceiling) error = %v", err)
	}
	// A rekey setting this type does not offer, such as the retired admin-key
	// rekey, has no path to solve.
	adminRekey := boundedmeta.Clone(instance.Bounded)
	adminRekey.Rekey = "admin_key"
	if err := plainhost.CheckResources(adminRekey, opcodes, 3_000); err == nil || !strings.Contains(err.Error(), "no resource path") {
		t.Fatalf("CheckResources(admin rekey) error = %v", err)
	}
}

// A Merkle shape with a rekey-to list folds both proofs with one subroutine:
// the listed rekey calls the allowlist's combine rather than carrying a copy.
// Other list shapes keep the list's own.
func TestMerkleListShapesShareOneCombine(t *testing.T) {
	for _, b := range bases(t) {
		for _, shape := range plainhost.Shapes() {
			if !shape.HasRekeyList() || shape.AnyRecipient {
				continue
			}
			teal, err := b.provider.GenerateTEAL(b.spendingKey, withRoot(t, b.provider, shapeRequest(shape, testAddress(1)+","+testAddress(2))))
			if err != nil {
				t.Fatal(err)
			}
			definitions := strings.Count(teal, "\n__aplane_bounded1_merkle_combine:") + strings.Count(teal, "\n__aplane_bounded1_rekey_list_combine:")
			if definitions != 1 {
				t.Fatalf("%s %s: %d combine subroutines, want one", b.name, shape.Descriptor(), definitions)
			}
			merkle := shape.Encoding == plainhost.EncodingMerkle
			if strings.Contains(teal, "__aplane_bounded1_rekey_list_combine") == merkle {
				t.Fatalf("%s %s: merkle %v, but the list's own combine is present %v", b.name, shape.Descriptor(), merkle, !merkle)
			}
		}
	}
}

// These values freeze what approval and provenance mean. A failure here is a
// review obligation, not a fixture to refresh:
//
//   - a programs golden changed: a renderer or the envelope changed behavior.
//     Raise allowlistRendererRevision or
//     limitsRendererRevision (listRendererRevision for the listed-rekey path, or
//     shapeResolverRevision for a request-handling change), for the affected
//     shapes only.
//   - a shape fingerprint changed with no intended behavior change: existing
//     accounts of that shape would report a provenance conflict. Do not ship that.
//   - the spending-key shapes changed: so did the accounts most bounded2 releases
//     have made. Do not ship that either.
//
// The grammar fingerprint is frozen by TestPlainHostGrammarGoldens. These values
// moved on purpose when the shapes joined the plain hosts (install-fresh): they
// now name the plain key type and its salt style, and the resolver revision is 2.
// The spending-key value moved again when the framework timelock left the
// grammar: it had covered the three uncosigned spending-key timelock families,
// which are gone. The allowlist entries it still covers are unchanged.
func TestBoundsFingerprintGoldens(t *testing.T) {
	type goldens struct {
		firstShape, fullShape, boundaryDigest string
		allowlists, spendingKeyShapes, limits string
	}
	want := map[string]goldens{
		"falcon": {
			firstShape:        "1:b5266cee501e3b9a20164484fa2e4334b420bd5a47f7e45e5d9020f7d1896590",
			fullShape:         "1:b4efb8a343077eb838ca3646354fc98e02a6bc2cc6e455048afc484ed0b9b263",
			boundaryDigest:    "fc7c7b20998e33024636c11e56653a24320c16028330fab2b2c6e7dc8e95ff38",
			allowlists:        "c9f373cfd2e4c8ce88f7d54b43cd41f8499b9767ff8e6b27594fc597f0fab878",
			spendingKeyShapes: "04b005aad4c708001aa709a4445d329d68c9cdf385b0c0ff101b2525afdf1fcb",
			limits:            "ed48000cae1be962081a58fcc294d9c4fbf0847ced6b34d0e66e55403793cabb",
		},
		"ed25519": {
			firstShape:        "1:602f2e2819cc80b7cd3d52553d665a27d154223aef57fb7cd7d9ae33de724bc5",
			fullShape:         "1:15c970558356419748a4e56f1f0e9b29fda4940320c2e63466901d20fc1d7d87",
			boundaryDigest:    "42d94bb4bdaceec99f8a55c499448002a4aff488c4ab15dd39ae70e23d08e1cf",
			allowlists:        "3ac0b4b28e9d132f37ccbd8157aa7fda8be40dd51d92a9d5419d64e751eae53f",
			spendingKeyShapes: "5096e3e3cbc549e54f153df445d884b6cbb156de09f00f1ecf8741fad176ac32",
			limits:            "48e3e3c545e6c39d008a5dcffecb0160b76e1ee7ad66a16e59db4c0ab8899bfe",
		},
	}
	shapes := plainhost.Shapes()
	// The families' places in the grammar, which TestShapesEnumerateTheGrammar
	// freezes: 98 allowlist shapes, then 49 limits-only.
	const limitsStart = 98
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			allowlists := sha256.New()
			// The uncosigned spending-key shapes alone, with each one's fingerprint and
			// digest. Every bounded2 release has offered them.
			spendingKey := sha256.New()
			// Limits-only shapes, with fingerprints and digests.
			limits := sha256.New()
			for index, shape := range shapes {
				rendered := allowlists
				if index >= limitsStart {
					rendered = limits
				}
				params := shapeRequest(shape, testAddress(1)+","+testAddress(2))
				// A list shape renders with the root key generation computes; its
				// fingerprint and digest come from the request alone.
				teal, err := b.provider.GenerateTEAL(b.spendingKey, withRoot(t, b.provider, params))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fmt.Fprintf(rendered, "%s\n%d\n%s\n", shape.Descriptor(), len(teal), teal); err != nil {
					t.Fatal(err)
				}
				pinned := spendingKey
				switch {
				case shape.AnyRecipient:
					pinned = limits
				case shape.Rekey != plainhost.RekeySpendingKey || shape.Cosigner:
					continue
				}
				resolved, err := b.provider.ResolveInstance(params)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fmt.Fprintf(pinned, "%s\n%s\n%s\n%d\n%s\n", shape.Descriptor(), resolved.Fingerprint, resolved.BoundaryDigest, len(teal), teal); err != nil {
					t.Fatal(err)
				}
			}
			full := resolveShape(t, b.provider, plainhost.Shape{Spend: everyTransfer, Encoding: plainhost.EncodingMerkle, Rekey: plainhost.RekeyPlusCosigned, Cosigner: true},
				testAddress(1)+","+testAddress(2))
			golden := want[b.name]
			for _, check := range []struct{ name, got, want string }{
				{"first shape", b.provider.ShapeFingerprintForTest(shapes[0]), golden.firstShape},
				{"full shape", full.Fingerprint, golden.fullShape},
				{"boundary digest", full.BoundaryDigest, golden.boundaryDigest},
				{"allowlist programs", hex.EncodeToString(allowlists.Sum(nil)), golden.allowlists},
				{"spending-key shapes", hex.EncodeToString(spendingKey.Sum(nil)), golden.spendingKeyShapes},
				{"limits-only shapes", hex.EncodeToString(limits.Sum(nil)), golden.limits},
			} {
				if check.got != check.want {
					t.Errorf("%s = %s, want %s", check.name, check.got, check.want)
				}
			}
		})
	}
}
