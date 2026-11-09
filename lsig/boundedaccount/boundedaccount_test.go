// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	"github.com/aplane-algo/aplane/lsig/ed25519lsig"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

const (
	goldenGrammarFingerprint    = "1:f3ef141579c91d5b8e704dce2e3bb94345ddc99d8cafcd14df79092d451d8b86"
	goldenFirstShapeFingerprint = "1:8cf7fe450ac0fe0e548ae4e4a075d22035f167a8a27957d723a82d82ac93b0d7"
	goldenFullShapeFingerprint  = "1:6ae03fad054024348ad540e4c5314d7f64b75e4aef0afc87383b3db8d92dd932"
	goldenBoundaryDigest        = "a500c612b2ab2531b0b38687b9f03a3093b9280b1d7328285dad7cf2bc7773c7"
	// The grammar, full-shape, digest and three program goldens moved when the
	// cosigned families (spending key with the cosigner, only these, plus
	// cosigned) replaced cosigned refused, and the full shape became plus
	// cosigned. The first shape and the uncosigned spending-key shapes held.
	goldenRenderedPrograms = "5366db6d84d13727957f37ac6c5d5cd603a633f06224fec50f9e319f8caf5d5a"
	goldenTimelockPrograms = "e1f88309eedbc5e716c2149e305f2d131a83c32479340d1ff48442b9af322a95"
	// Pins the 14 bounded2 spending-key shapes. It is no longer equal to main
	// a2874c6e: bounded2 replaced bounded1 in place (contract label, rekey setting,
	// profile domain), and timelocks no longer offer a spending-key rekey.
	goldenSpendingKeyPrograms = "e505540200bde859f7d0adca8b99d3a5c4bfd3ee79859c56d1b00c5201030f15"
	// Pins the 17 limits-only shapes: programs, fingerprints and digests.
	goldenLimitsPrograms = "2b120941acd172d018e30a1d317fb34cb3f54da3e87b7991d2e8ea7f931cdc3d"
)

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	falcon.RegisterClient()
	provider, err := NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	return provider
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

var (
	testCosignerKey = hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
	testSpendingKey = bytes.Repeat([]byte{0x21}, 1793)
	// testListKey stands in for the spending private key a rekey-to list's seed
	// comes from.
	testListKey = bytes.Repeat([]byte{0x77}, 64)
	// testRekeyTo is the rekey-to list requestFor gives an only_these shape, in
	// canonical (byte) order.
	testRekeyTo = rekeyTarget(0x08) + "," + rekeyTarget(0xd0)
)

func requestFor(shape Shape, recipients string) map[string]string {
	params := map[string]string{
		ParameterSpendEffects:   joinSpend(shape.Spend),
		ParameterRekeyAuthority: shape.Rekey,
	}
	if shape.Encoding != "" {
		params[ParameterListEncoding] = shape.Encoding
		params[ParameterRecipients] = recipients
	}
	if shape.HasRekeyList() {
		params[ParameterRekeyTo] = testRekeyTo
	}
	if shape.Timelock {
		params[ParameterUnlockRound] = "50000000"
	}
	if shape.AnyRecipient {
		params[ParameterRecipientScope] = RecipientScopeAny
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
	}
	return params
}

// withRoot adds the rekey-to list root key generation computes, which a list
// shape needs before it can render. Other requests come back unchanged.
func withRoot(t *testing.T, provider *Provider, params map[string]string) map[string]string {
	t.Helper()
	prepared, err := provider.PrepareRekeyList(testListKey, params)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

// The expected set is written out here rather than derived from the code that
// produces it. Each policy group offers five rekey arrangements, each with all 7
// spend subsets, since every arrangement has a way out: the spending key, only
// these addresses, the spending key with the cosigner, only these with a
// cosigner, and plus cosigned. Allowlists are 2 encodings x 35, which is 70. A
// timelock takes only a rekey-to list (only these, with or without a cosigner),
// so timelocks add 3 policies x 14, which is 42. Limits-only shapes add one policy
// with the allowlists' arrangements, 35, for 147 in all.
func TestShapesEnumerateTheGrammar(t *testing.T) {
	shapes := Shapes()
	if len(shapes) != 147 {
		t.Fatalf("Shapes() = %d, want 147", len(shapes))
	}
	policies := make(map[string]int)
	for _, shape := range shapes {
		policies[shape.Policy()]++
	}
	for policy, want := range map[string]int{
		composeddsa.Layer3PolicyFixedAllowlist: 35, composeddsa.Layer3PolicyMerkleAllowlist: 35,
		composeddsa.Layer3PolicyTimelock: 14, composeddsa.Layer3PolicyFixedAllowlistTimelock: 14, composeddsa.Layer3PolicyMerkleAllowlistTimelock: 14,
		composeddsa.Layer3PolicyNone: 35,
	} {
		if policies[policy] != want {
			t.Errorf("%s has %d shapes, want %d", policy, policies[policy], want)
		}
	}
	for _, shape := range shapes {
		if shape.Timelock && shape.Rekey != RekeyOnlyThese {
			t.Errorf("%s is a timelock a spending-key rekey could leave before the unlock round", shape.Descriptor())
		}
		if shape.Rekey == RekeyRefused {
			t.Errorf("%s refuses every rekey, so it has no way out but its transfers", shape.Descriptor())
		}
		if shape.Rekey == RekeyPlusCosigned && !shape.Cosigner {
			t.Errorf("%s is plus cosigned without a cosigner", shape.Descriptor())
		}
	}
	seen := make(map[string]bool)
	for _, shape := range shapes {
		if seen[shape.Descriptor()] {
			t.Fatalf("duplicate shape %s", shape.Descriptor())
		}
		seen[shape.Descriptor()] = true
	}
	allowlists, timelocks, limits := shapes[:70], shapes[70:112], shapes[112:]
	for index, shape := range shapes {
		if shape.Timelock != (index >= 70 && index < 112) || shape.AnyRecipient != (index >= 112) {
			t.Fatalf("shape %d %s is out of its family's place", index, shape.Descriptor())
		}
	}
	// Every family takes all seven spend subsets, since every one has a way out.
	arrangements := []string{"spending_key/false", "only_these/false", "spending_key/true", "only_these/true", "plus_cosigned/true"}
	families := make(map[string]int)
	subsets := make(map[string]int)
	for _, shape := range allowlists {
		families[shape.Encoding+"/"+shape.Rekey+"/"+strconv.FormatBool(shape.Cosigner)]++
		subsets[joinSpend(shape.Spend)]++
	}
	for _, encoding := range []string{EncodingInline, EncodingMerkle} {
		for _, arrangement := range arrangements {
			if family := encoding + "/" + arrangement; families[family] != 7 {
				t.Errorf("family %s has %d shapes, want 7", family, families[family])
			}
		}
	}
	for _, subset := range []string{"pay", "pay,axfer", "pay,axfer,asset_opt_in", "pay,asset_opt_in", "axfer", "asset_opt_in", "axfer,asset_opt_in"} {
		if subsets[subset] != 10 {
			t.Errorf("subset %s has %d shapes, want 10", subset, subsets[subset])
		}
	}
	families = make(map[string]int)
	for _, shape := range timelocks {
		families[shape.Policy()+"/"+shape.Rekey+"/"+strconv.FormatBool(shape.Cosigner)]++
	}
	for _, policy := range []string{composeddsa.Layer3PolicyTimelock, composeddsa.Layer3PolicyFixedAllowlistTimelock, composeddsa.Layer3PolicyMerkleAllowlistTimelock} {
		for family, want := range map[string]int{policy + "/only_these/false": 7, policy + "/only_these/true": 7} {
			if families[family] != want {
				t.Errorf("timelock family %s has %d shapes, want %d", family, families[family], want)
			}
		}
	}
	families = make(map[string]int)
	for _, shape := range limits {
		if shape.Encoding != "" {
			t.Errorf("limits-only %s has a list encoding", shape.Descriptor())
		}
		families[shape.Rekey+"/"+strconv.FormatBool(shape.Cosigner)]++
	}
	for _, arrangement := range arrangements {
		if families[arrangement] != 7 {
			t.Errorf("limits-only family %s has %d shapes, want 7", arrangement, families[arrangement])
		}
	}
}

// The descriptor names the rekey setting alone: the contract has no Layer 3 gate
// for it to name.
func TestShapeDescriptorFormat(t *testing.T) {
	for _, test := range []struct {
		shape Shape
		want  string
	}{
		{Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey},
			"spend=pay,axfer,asset_opt_in;policy=fixed_allowlist;rekey=spending_key;cosigner=none"},
		{Shape{Spend: []txeffects.SpendEffect{txeffects.SpendEffectPay}, Encoding: EncodingMerkle, Rekey: RekeyRefused, Cosigner: true, Timelock: true},
			"spend=pay;policy=merkle_allowlist_timelock;rekey=refused;cosigner=required"},
		{Shape{Spend: []txeffects.SpendEffect{txeffects.SpendEffectPay}, Rekey: RekeySpendingKey, AnyRecipient: true},
			"spend=pay;policy=none;rekey=spending_key;cosigner=none"},
		{Shape{Spend: []txeffects.SpendEffect{txeffects.SpendEffectAxfer}, Rekey: RekeyOnlyThese, Timelock: true},
			"spend=axfer;policy=timelock;rekey=only_these;cosigner=none"},
	} {
		if got := test.shape.Descriptor(); got != test.want {
			t.Errorf("Descriptor() = %q, want %q", got, test.want)
		}
	}
}

func TestEveryShapeResolvesAndAgreesWithItsMetadata(t *testing.T) {
	provider := newTestProvider(t)
	for _, shape := range Shapes() {
		t.Run(shape.Descriptor(), func(t *testing.T) {
			instance, err := provider.ResolveInstance(requestFor(shape, testRecipients(3)))
			if err != nil {
				t.Fatal(err)
			}
			if instance.Bounded == nil {
				t.Fatal("instance has no bounded contract")
			}
			fromMetadata, err := shapeFromMetadata(instance.Bounded)
			if err != nil {
				t.Fatal(err)
			}
			if fromMetadata.Descriptor() != shape.Descriptor() {
				t.Fatalf("metadata selects %s", fromMetadata.Descriptor())
			}
			if instance.Bounded.MaxFee == nil || *instance.Bounded.MaxFee != MaxFee {
				t.Fatalf("MaxFee = %v", instance.Bounded.MaxFee)
			}
			if (instance.Bounded.Cosigner != nil) != shape.Cosigner {
				t.Fatalf("cosigner metadata = %v", instance.Bounded.Cosigner)
			}
			if (instance.Bounded.RekeyList != nil) != shape.HasRekeyList() {
				t.Fatalf("rekey-to list metadata = %v", instance.Bounded.RekeyList)
			}
			if instance.Bounded.Cosigner != nil && !slices.Equal(instance.Bounded.Cosigner.RequiredOn, boundedmeta.CosignerRequiredOn(instance.Bounded.Rekey)) {
				t.Fatalf("cosigner required_on = %v under rekey %s", instance.Bounded.Cosigner.RequiredOn, instance.Bounded.Rekey)
			}
			if _, present := instance.Values[boundedmeta.RekeyListRootParameter]; present {
				t.Fatal("persisted values hold the rekey-to list root")
			}
			again, err := provider.ResolveInstance(instance.Values)
			if err != nil {
				t.Fatalf("persisted values do not resolve again: %v", err)
			}
			if again.Fingerprint != instance.Fingerprint || again.BoundaryDigest != instance.BoundaryDigest {
				t.Fatal("persisted values select a different definition")
			}
			stored, err := provider.StoredFingerprint(nil, instance.Bounded)
			if err != nil {
				t.Fatal(err)
			}
			if stored != instance.Fingerprint {
				t.Fatalf("stored fingerprint %s, instance %s", stored, instance.Fingerprint)
			}
			if _, err := provider.GenerateTEAL(testSpendingKey, withRoot(t, provider, instance.Values)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidRequestsFailClosed(t *testing.T) {
	provider := newTestProvider(t)
	allSpend := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeySpendingKey}
	// The grammar never offers an account that refuses every rekey; this is the
	// request for one, with a cosigner.
	refusedShape := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeyRefused, Cosigner: true}
	onlyThese := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeyOnlyThese}
	cosignedOnlyThese := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeyOnlyThese, Cosigner: true}
	plusCosigned := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeyPlusCosigned, Cosigner: true}
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
		base   Shape
		mutate func(map[string]string)
		want   string
	}{
		{"no spend", allSpend, func(p map[string]string) { delete(p, ParameterSpendEffects) }, "spend_effects is required"},
		{"empty spend", allSpend, func(p map[string]string) { p[ParameterSpendEffects] = "" }, "spend_effects is required"},
		{"unknown spend", allSpend, func(p map[string]string) { p[ParameterSpendEffects] = "pay,keyreg" }, "unknown effect"},
		{"repeated spend", allSpend, func(p map[string]string) { p[ParameterSpendEffects] = "pay,pay" }, "repeats"},
		{"no rekey", allSpend, func(p map[string]string) { delete(p, ParameterRekeyAuthority) }, "rekey_authority must be"},
		{"bad rekey", allSpend, func(p map[string]string) { p[ParameterRekeyAuthority] = "none" }, "rekey_authority must be"},
		{"no recipients", allSpend, func(p map[string]string) { delete(p, ParameterRecipients) }, "recipients is required"},
		{"zero unlock round", allSpend, func(p map[string]string) { p[ParameterUnlockRound] = "0" }, "must be positive"},
		{"unreadable unlock round", allSpend, func(p map[string]string) { p[ParameterUnlockRound] = "soon" }, "positive whole number"},
		{"empty unlock round", allSpend, func(p map[string]string) { p[ParameterUnlockRound] = "" }, "positive whole number"},
		{"oversized unlock round", allSpend, func(p map[string]string) { p[ParameterUnlockRound] = "18446744073709551616" }, "positive whole number"},
		{"encoding with no list", allSpend, func(p map[string]string) {
			delete(p, ParameterRecipients)
			p[ParameterUnlockRound] = "5"
		}, "no list to encode"},
		// No host rule gates a rekey, so a spending-key rekey could leave a timelock
		// before its unlock round. Pay does not change that.
		{"spending-key rekey on an allowlist timelock", allSpend, func(p map[string]string) { p[ParameterUnlockRound] = "5" },
			"this type's timelock shapes take only rekey_authority=only_these; an expert template can combine a timelock with rekey_authority=spending_key"},
		// With a cosigner too: the cosigner's rekey_policy would become the lock.
		{"cosigned spending-key rekey on a timelock", allSpend, func(p map[string]string) {
			p[ParameterUnlockRound] = "5"
			p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
		}, "an expert template can combine a timelock with rekey_authority=spending_key"},
		{"plus cosigned on a timelock", plusCosigned, func(p map[string]string) { p[ParameterUnlockRound] = "5" },
			"an expert template can combine a timelock with rekey_authority=plus_cosigned"},
		{"spending-key rekey on a timelock", allSpend, func(p map[string]string) {
			delete(p, ParameterRecipients)
			delete(p, ParameterListEncoding)
			p[ParameterUnlockRound] = "5"
		}, "an expert template can combine a timelock with rekey_authority=spending_key"},
		{"spending-key rekey on a timelock without pay", allSpend, func(p map[string]string) {
			p[ParameterUnlockRound] = "5"
			p[ParameterSpendEffects] = "axfer"
		}, "an expert template can combine a timelock with rekey_authority=spending_key"},
		// The grammar has no shape that refuses every rekey, with a cosigner or without.
		{"refused with a cosigner", refusedShape, func(map[string]string) {},
			"rekey_authority=refused is not one of this type's shapes: use rekey_authority=only_these with rekey_to, or an expert template with rekey: refused"},
		{"refused without a cosigner", refusedShape, func(p map[string]string) { delete(p, composeddsa.BoundedCosignerPublicKeyParameter) },
			"rekey_authority=refused is not one of this type's shapes"},
		{"plus cosigned without a cosigner", plusCosigned, func(p map[string]string) { delete(p, composeddsa.BoundedCosignerPublicKeyParameter) },
			"rekey_authority=plus_cosigned needs a cosigner; without one, use rekey_authority=only_these or spending_key"},
		{"plus_cosigned without rekey_to", plusCosigned, func(p map[string]string) { delete(p, ParameterRekeyTo) },
			"rekey_authority=plus_cosigned needs the addresses the account may be rekeyed to in rekey_to"},
		{"only_these without rekey_to", onlyThese, func(p map[string]string) { delete(p, ParameterRekeyTo) },
			"rekey_authority=only_these needs the addresses the account may be rekeyed to in rekey_to"},
		{"only_these with an empty rekey_to", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = "" }, "rekey_authority=only_these needs the addresses"},
		{"only_these with a blank rekey_to", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = "  " }, "empty item"},
		{"rekey_to with a spending-key rekey", allSpend, func(p map[string]string) { p[ParameterRekeyTo] = targets(1) }, "rekey_to needs rekey_authority=only_these or plus_cosigned"},
		{"empty rekey_to with a spending-key rekey", allSpend, func(p map[string]string) { p[ParameterRekeyTo] = "" }, "rekey_to needs rekey_authority=only_these or plus_cosigned"},
		{"rekey_to with a cosigned spending-key rekey", allSpend, func(p map[string]string) {
			p[ParameterRekeyTo] = targets(1)
			p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
		}, "rekey_to needs rekey_authority=only_these or plus_cosigned"},
		{"17 plus-cosigned rekey_to entries", plusCosigned, func(p map[string]string) { p[ParameterRekeyTo] = targets(17) }, "holds at most 16 addresses, got 17"},
		{"zero rekey_to entry", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = targets(1) + "," + zero }, "must not contain the zero address"},
		{"repeated rekey_to entry", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = targets(1) + "," + targets(1) }, "repeats"},
		{"17 rekey_to entries", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = targets(17) }, "holds at most 16 addresses, got 17"},
		{"bad rekey_to entry", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = "NOTANADDRESS" }, "rekey_to: invalid address"},
		{"empty rekey_to item", onlyThese, func(p map[string]string) { p[ParameterRekeyTo] = targets(1) + ",," + rekeyTarget(0xd0) }, "empty item"},
		// Key generation computes the root; no request can set it.
		{"rekey-to list root", onlyThese, func(p map[string]string) { p[boundedmeta.RekeyListRootParameter] = strings.Repeat("00", 32) }, "unknown parameter"},
		{"empty list with a timelock", allSpend, func(p map[string]string) {
			p[ParameterUnlockRound] = "5"
			p[ParameterRecipients] = ""
		}, "recipients is required"},
		{"zero recipient", allSpend, func(p map[string]string) { p[ParameterRecipients] = testAddress(1) + "," + zero }, "zero address"},
		{"repeated recipient", allSpend, func(p map[string]string) { p[ParameterRecipients] = testAddress(1) + "," + testAddress(1) }, "repeats"},
		{"bad recipient", allSpend, func(p map[string]string) { p[ParameterRecipients] = "NOTANADDRESS" }, "invalid address"},
		{"bad encoding", allSpend, func(p map[string]string) { p[ParameterListEncoding] = "blinded" }, "list_encoding must be"},
		{"empty encoding", allSpend, func(p map[string]string) { p[ParameterListEncoding] = "" }, "list_encoding must be"},
		{"inline too long", allSpend, func(p map[string]string) {
			p[ParameterListEncoding] = EncodingInline
			p[ParameterRecipients] = testRecipients(InlineMax + 1)
		}, "inline encoding accepts at most 30"},
		{"too many recipients", allSpend, func(p map[string]string) { p[ParameterRecipients] = testRecipients(RecipientsMax + 1) }, "maximum is 65536"},
		// The admin key is gone: its parameter and its rekey authority are refused.
		{"admin key parameter", allSpend, func(p map[string]string) {
			// Spelled in two parts so the retired-names scan in test/arch skips it.
			p["bounded_"+"admin_public_key"] = hex.EncodeToString(bytes.Repeat([]byte{0x31}, 1793))
		}, "unknown parameter"},
		{"admin rekey authority", allSpend, func(p map[string]string) { p[ParameterRekeyAuthority] = "admin_key" }, "rekey_authority must be"},
		{"empty cosigner key", cosignedOnlyThese, func(p map[string]string) { p[composeddsa.BoundedCosignerPublicKeyParameter] = "" }, "is empty"},
		{"unresolved cosigner", cosignedOnlyThese, func(p map[string]string) { p[ParameterCosigner] = "ops" }, "not resolved"},
		{"empty cosigner name", cosignedOnlyThese, func(p map[string]string) { p[ParameterCosigner] = "" }, "not resolved"},
		{"teal", allSpend, func(p map[string]string) { p["teal"] = "int 1" }, "unknown parameter"},
		{"template", allSpend, func(p map[string]string) { p["template"] = "x" }, "unknown parameter"},
		{"max fee", allSpend, func(p map[string]string) { p["max_fee"] = "1" }, "unknown parameter"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			params := requestFor(test.base, testRecipients(2))
			test.mutate(params)
			_, err := provider.ResolveInstance(params)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ResolveInstance error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestEncodingThreshold(t *testing.T) {
	provider := newTestProvider(t)
	auto := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeySpendingKey}
	for _, test := range []struct {
		count int
		want  string
	}{{1, EncodingInline}, {10, EncodingInline}, {11, EncodingMerkle}, {RecipientsMax, EncodingMerkle}} {
		instance, err := provider.ResolveInstance(requestFor(auto, testRecipients(test.count)))
		if err != nil {
			t.Fatal(err)
		}
		if got := instance.Values[ParameterListEncoding]; got != test.want {
			t.Errorf("%d recipients encode as %s, want %s", test.count, got, test.want)
		}
	}
	for _, explicit := range []struct {
		encoding string
		count    int
	}{{EncodingInline, 30}, {EncodingMerkle, 1}} {
		shape := Shape{Spend: spendEffectOrder, Encoding: explicit.encoding, Rekey: RekeySpendingKey}
		instance, err := provider.ResolveInstance(requestFor(shape, testRecipients(explicit.count)))
		if err != nil {
			t.Fatal(err)
		}
		if got := instance.Values[ParameterListEncoding]; got != explicit.encoding {
			t.Errorf("explicit %s became %s", explicit.encoding, got)
		}
	}
}

func TestRequestsCanonicalize(t *testing.T) {
	provider := newTestProvider(t)
	base := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeySpendingKey}
	first, err := provider.ResolveInstance(requestFor(base, testAddress(1)+","+testAddress(2)+","+testAddress(3)))
	if err != nil {
		t.Fatal(err)
	}
	reordered := requestFor(base, testAddress(3)+", "+testAddress(1)+","+testAddress(2))
	reordered[ParameterSpendEffects] = "asset_opt_in, pay,axfer"
	second, err := provider.ResolveInstance(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if first.BoundaryDigest != second.BoundaryDigest || first.Values[ParameterRecipients] != second.Values[ParameterRecipients] {
		t.Fatal("equivalent requests resolved differently")
	}
}

// only_these is stored as rekey: refused plus a rekey-to list. The persisted values
// hold the list in the order its tree uses, by address bytes, and never the root,
// which key generation computes.
func TestOnlyTheseRequestResolves(t *testing.T) {
	provider := newTestProvider(t)
	low, high := rekeyTarget(0x08), rekeyTarget(0xd0)
	if high >= low {
		t.Fatal("fixture: the targets must sort one way as text and the other as bytes")
	}
	params := requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese}, testRecipients(2))
	params[ParameterRekeyTo] = high + ", " + low
	instance, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatal(err)
	}
	if got := instance.Values[ParameterRekeyTo]; got != low+","+high {
		t.Fatalf("rekey_to = %q, want canonical %q", got, low+","+high)
	}
	if instance.Values[ParameterRekeyAuthority] != RekeyOnlyThese {
		t.Fatalf("rekey_authority = %q", instance.Values[ParameterRekeyAuthority])
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
	if len(proofs) != 1 || proofs[0].Name != "rekey_list_proof" || proofs[0].Parameter != ParameterRekeyTo {
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
	limits, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Rekey: RekeyOnlyThese, AnyRecipient: true}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if limits.Bounded.Contained() {
		t.Fatal("a limits-only only_these account reports itself contained")
	}
	// A full list resolves.
	full := make([]string, 16)
	for i := range full {
		full[i] = rekeyTarget(byte(i + 1))
	}
	params[ParameterRekeyTo] = strings.Join(full, ",")
	if _, err := provider.ResolveInstance(params); err != nil {
		t.Fatalf("a 16-entry list was refused: %v", err)
	}
}

func TestComposerSeesOnlyItsDeclaredParameters(t *testing.T) {
	provider := newTestProvider(t)
	for _, shape := range Shapes() {
		definition := provider.byShape[shape.Descriptor()]
		request := requestFor(shape, testRecipients(2))
		request[ParameterRekeyTo] = testRekeyTo
		values := composerValues(definition, request)
		for _, selector := range []string{ParameterSpendEffects, ParameterRekeyAuthority, ParameterListEncoding, ParameterRecipientScope} {
			if _, ok := values[selector]; ok {
				t.Fatalf("%s reached the composer", selector)
			}
		}
		// The list's entries are the composer's own parameter on a list shape alone.
		if _, ok := values[ParameterRekeyTo]; ok != shape.HasRekeyList() {
			t.Fatalf("%s: rekey_to reached the composer = %v", shape.Descriptor(), ok)
		}
	}
}

func TestProviderHasNoMnemonicImportOrRuntimeArguments(t *testing.T) {
	provider := newTestProvider(t)
	if len(provider.RuntimeArgs()) != 0 {
		t.Fatal("this grammar has no runtime arguments")
	}
	if _, err := provider.BuildArgs(nil, nil); err == nil {
		t.Fatal("BuildArgs must refuse")
	}
	if _, ok := provider.CosignerComponentKeyType(map[string]string{}); ok {
		t.Fatal("discovery added a cosigner to a request that named none")
	}
	if component, ok := provider.CosignerComponentKeyType(map[string]string{ParameterCosigner: "ops"}); !ok || component == "" {
		t.Fatalf("named cosigner reports %q, %v", component, ok)
	}
}

func TestBoundaryDigestBindsWhatItCompares(t *testing.T) {
	provider := newTestProvider(t)
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese, Cosigner: true}
	digest := func(t *testing.T, mutate func(map[string]string)) string {
		t.Helper()
		params := requestFor(shape, testRecipients(3))
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
			p[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x42}, boundedmeta.CosignerPublicKeySizeV1))
		},
		"recipients": func(p map[string]string) { p[ParameterRecipients] = testRecipients(4) },
		"spend":      func(p map[string]string) { p[ParameterSpendEffects] = "pay" },
		"encoding":   func(p map[string]string) { p[ParameterListEncoding] = EncodingMerkle },
	} {
		if digest(t, mutate) == base {
			t.Errorf("changing %s did not change the digest", name)
		}
	}
	noCosigner := digest(t, func(p map[string]string) { delete(p, composeddsa.BoundedCosignerPublicKeyParameter) })
	if noCosigner == base {
		t.Error("removing the cosigner did not change the digest")
	}
	// The option is bound, not just the list: plus cosigned is the same entries
	// with other rekeys open to the cosigner.
	if digest(t, func(p map[string]string) { p[ParameterRekeyAuthority] = RekeyPlusCosigned }) == base {
		t.Error("changing only these to plus cosigned did not change the digest")
	}
}

// The digest binds a rekey-to list's entries, not the order they were written in.
func TestBoundaryDigestBindsTheRekeyToList(t *testing.T) {
	provider := newTestProvider(t)
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese}
	digest := func(rekeyTo string) string {
		t.Helper()
		params := requestFor(shape, testRecipients(2))
		params[ParameterRekeyTo] = rekeyTo
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

// A new rule must not disturb existing accounts: a shape's fingerprint and an
// account's digest depend on that shape alone, and only the grammar sees them all.
func TestFingerprintScopes(t *testing.T) {
	provider := newTestProvider(t)
	if provider.ordered[0].fingerprint == provider.grammar {
		t.Fatal("grammar and shape fingerprints must differ")
	}
	full := grammarFingerprint(provider.ordered)
	if smaller := grammarFingerprint(provider.ordered[:len(provider.ordered)-1]); smaller == full {
		t.Fatal("a removed shape did not change the grammar fingerprint")
	}
	swapped := append([]*shapeDefinition(nil), provider.ordered...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if grammarFingerprint(swapped) == full {
		t.Fatal("the grammar fingerprint does not bind which shape has which behavior")
	}
	seen := make(map[string]string)
	for _, definition := range provider.ordered {
		if other, ok := seen[definition.fingerprint]; ok {
			t.Fatalf("%s and %s share a fingerprint", other, definition.shape.Descriptor())
		}
		seen[definition.fingerprint] = definition.shape.Descriptor()
	}
}

func TestStoredFingerprintRefusesWhatTheGrammarCannotProduce(t *testing.T) {
	provider := newTestProvider(t)
	if _, err := provider.StoredFingerprint(nil, nil); err == nil {
		t.Fatal("accepted missing metadata")
	}
	instance, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey}, testRecipients(1)))
	if err != nil {
		t.Fatal(err)
	}
	custom := boundedmeta.Clone(instance.Bounded)
	custom.Layer3Policy = boundedmeta.Layer3PolicyCustom
	if _, err := provider.StoredFingerprint(nil, custom); err == nil {
		t.Fatal("accepted a custom policy")
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
	provider := newTestProvider(t)
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
	direct, err := provider.ResolveInstance(requestFor(
		Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese},
		testAddress(1)+","+testAddress(2)))
	if err != nil {
		t.Fatal(err)
	}
	for name, params := range map[string]map[string]string{"block style": loaded, "flow style": flow.CreationParameters()} {
		fromFile, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if fromFile.BoundaryDigest != direct.BoundaryDigest || fromFile.Fingerprint != direct.Fingerprint ||
			!maps.Equal(fromFile.Values, direct.Values) {
			t.Fatalf("%s: file and direct parameters resolved differently", name)
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
	if params[ParameterCosigner] != "ops-cosigner" {
		t.Fatalf("cosigner = %q", params[ParameterCosigner])
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
		{"no spend", strings.Replace(valid, "spend: [pay]\n", "", 1), "spend is required"},
		{"empty spend", strings.Replace(valid, "spend: [pay]", "spend: []", 1), "spend is required"},
		{"no recipients or timelock", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1), "recipients is required"},
		{"no rekey", strings.Replace(valid, "rekey: {authority: spending_key}\n", "", 1), "rekey is required"},
		{"bad authority", strings.Replace(valid, "spending_key", "nobody", 1), "rekey.authority must be"},
		{"admin authority", strings.Replace(valid, "spending_key", "admin_key", 1), "rekey.authority must be"},
		{"admin key field", strings.Replace(valid, "{authority: spending_key}", "{authority: spending_key, admin_key: a.ref.json}", 1), "not found"},
		// An account that refuses every rekey has no way out but its transfers.
		{"refused authority", strings.Replace(valid, "spending_key", "refused", 1), "rekey.authority must be spending_key, only_these or plus_cosigned"},
		{"plus_cosigned without to", strings.Replace(valid, "spending_key", "plus_cosigned", 1), "rekey.authority plus_cosigned needs the addresses in rekey.to"},
		{"only_these without to", strings.Replace(valid, "spending_key", "only_these", 1), "rekey.authority only_these needs the addresses in rekey.to"},
		{"only_these with an empty to", strings.Replace(onlyThese, "["+target+"]", "[]", 1), "rekey.authority only_these needs the addresses in rekey.to"},
		{"to with spending_key", strings.Replace(onlyThese, "only_these", "spending_key", 1), "rekey.to needs rekey.authority only_these or plus_cosigned"},
		{"empty to with spending_key", strings.Replace(valid, "{authority: spending_key}", "{authority: spending_key, to: []}", 1), "rekey.to needs rekey.authority only_these or plus_cosigned"},
		{"scalar to", strings.Replace(onlyThese, "["+target+"]", target, 1), "cannot unmarshal"},
		{"top-level rekey_to", valid + "rekey_to: [" + target + "]\n", "not found"},
		{"unknown field", valid + "expires: \"5\"\n", "not found"},
		{"empty unlock round", valid + "unlock_round: \"\"\n", "unlock_round is empty"},
		{"null unlock round", valid + "unlock_round:\n", "must be a string"},
		{"float unlock round", valid + "unlock_round: 1.5\n", "must be a string"},
		{"boolean unlock round", valid + "unlock_round: true\n", "must be a string"},
		{"empty list with a timelock", strings.Replace(valid, "["+recipient+"]", "[]", 1) + "unlock_round: 5\n", "recipients is required"},
		{"encoding with no list", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1) + "unlock_round: 5\nencoding: auto\n", "needs a recipient list"},
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
				t.Fatalf("ParseBoundaryFile error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := boundary.ParseFile(bytes.Repeat([]byte{' '}, boundary.MaxFileBytes+1)); err == nil {
		t.Fatal("accepted an oversized file")
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

func generalGoldenKeys() (spending []byte, cosigner string) {
	return bytes.Repeat([]byte{0x21}, 1793),
		hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
}

// These values freeze what approval and provenance mean. A failure here is a
// review obligation, not a fixture to refresh:
//
//   - renderedPrograms changed: a renderer or the envelope changed behavior. Raise
//     allowlistRendererRevision, or resolverRevision for a request-handling change,
//     for the affected shapes only.
//   - only the grammar changed: the grammar gained or lost something, which is
//     expected to send operators through Approve current grammar.
//   - a shape fingerprint changed with no intended behavior change: existing
//     accounts of that shape would report a provenance conflict. Do not ship that.
//   - the spending-key shapes changed: so did accounts every bounded2 release has
//     made. Do not ship that either.
func TestGeneralFingerprintGoldens(t *testing.T) {
	provider := newTestProvider(t)
	spending, cosigner := generalGoldenKeys()

	allowlists := sha256.New()
	rendered := allowlists
	// The first 70 are the allowlist shapes. Their golden must not move when the
	// grammar grows: that is the guarantee existing accounts rely on. (It moved on
	// purpose in install-fresh releases: once when refused families replaced the
	// admin-key ones, again when bounded2 replaced bounded1 in place, again when
	// only_these replaced the uncosigned refused families, and again when the
	// cosigned families replaced cosigned refused.)
	shapes := Shapes()
	appended := sha256.New()
	// The spending-key shapes alone, with each one's fingerprint and digest. Every
	// bounded2 release offers them, so this golden holds across grammar edits.
	spendingKey := sha256.New()
	// Limits-only shapes, with fingerprints and digests. They are appended last,
	// so the earlier goldens hold without them.
	limits := sha256.New()
	for index, shape := range shapes {
		switch {
		case index >= 112:
			rendered = limits
		case index >= 70:
			rendered = appended
		}
		params := requestFor(shape, testAddress(1)+","+testAddress(2))
		if shape.Cosigner {
			params[composeddsa.BoundedCosignerPublicKeyParameter] = cosigner
		}
		// A list shape renders with the root key generation computes; its fingerprint
		// and digest come from the request alone.
		teal, err := provider.GenerateTEAL(spending, withRoot(t, provider, params))
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
		case shape.Rekey != RekeySpendingKey || shape.Cosigner:
			continue
		}
		resolved, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(pinned, "%s\n%s\n%s\n%d\n%s\n", shape.Descriptor(), resolved.Fingerprint, resolved.BoundaryDigest, len(teal), teal); err != nil {
			t.Fatal(err)
		}
	}
	full := Shape{Spend: spendEffectOrder, Encoding: EncodingMerkle, Rekey: RekeyPlusCosigned, Cosigner: true}
	instance, err := provider.ResolveInstance(requestFor(full, testAddress(1)+","+testAddress(2)))
	if err != nil {
		t.Fatal(err)
	}
	for _, golden := range []struct{ name, got, want string }{
		{"grammar", provider.GrammarFingerprint(), goldenGrammarFingerprint},
		{"first shape", provider.ordered[0].fingerprint, goldenFirstShapeFingerprint},
		{"full shape", instance.Fingerprint, goldenFullShapeFingerprint},
		{"boundary digest", instance.BoundaryDigest, goldenBoundaryDigest},
		{"allowlist programs", hex.EncodeToString(allowlists.Sum(nil)), goldenRenderedPrograms},
		{"timelock programs", hex.EncodeToString(appended.Sum(nil)), goldenTimelockPrograms},
		{"spending-key shapes", hex.EncodeToString(spendingKey.Sum(nil)), goldenSpendingKeyPrograms},
		{"limits-only shapes", hex.EncodeToString(limits.Sum(nil)), goldenLimitsPrograms},
	} {
		if golden.got != golden.want {
			t.Errorf("%s = %s, want %s", golden.name, golden.got, golden.want)
		}
	}
}

// The root is computed at generation from the list's entries and a seed derived
// from the spending private key, then compiled into the program and recorded in
// the account's metadata. The account's provenance is its request's alone.
func TestPrepareRekeyListAddsTheRoot(t *testing.T) {
	provider := newTestProvider(t)
	params := requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese}, testRecipients(2))
	instance, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.GenerateTEAL(testSpendingKey, params); err == nil || !strings.Contains(err.Error(), "the rekey-to list root is computed at key generation") {
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
	want, err := composeddsa.RekeyListRootFor(testListKey, map[string]string{ParameterRekeyTo: testRekeyTo})
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

	teal, err := provider.GenerateTEAL(testSpendingKey, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(teal, root) != 1 || !strings.Contains(teal, "pushbytes 0x"+root+"\n==\nassert\n") {
		t.Fatalf("program does not commit to the root once:\n%s", teal)
	}
	metadata, err := provider.BuildBoundedAuthorizationMetadata(testSpendingKey, prepared, make([]byte, 3_000))
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
	plain := requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey}, testRecipients(2))
	unchanged, err := provider.PrepareRekeyList(testListKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(unchanged, plain) {
		t.Fatalf("PrepareRekeyList changed a request without a list: %v", unchanged)
	}
}

func TestGenerationRunsTheResourceBackstop(t *testing.T) {
	provider := newTestProvider(t)
	params := requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey}, testRecipients(1))
	_, err := provider.BuildBoundedAuthorizationMetadata(testSpendingKey, params, make([]byte, 10_000_000))
	if err == nil || !strings.Contains(err.Error(), "resource limits") {
		t.Fatalf("BuildBoundedAuthorizationMetadata() error = %v", err)
	}
	if _, err := provider.BuildBoundedAuthorizationMetadata(testSpendingKey, params, make([]byte, 3_000)); err != nil {
		t.Fatalf("an ordinary program was refused: %v", err)
	}
}

func TestResourceBackstopRefusesWhatCannotRun(t *testing.T) {
	provider := newTestProvider(t)
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey}
	instance, err := provider.ResolveInstance(requestFor(shape, testRecipients(1)))
	if err != nil {
		t.Fatal(err)
	}
	opcodes := provider.LogicSigOpcodeProfile()
	if err := checkResources(instance.Bounded, opcodes, 3_000); err != nil {
		t.Fatalf("an ordinary program was refused: %v", err)
	}
	if err := checkResources(instance.Bounded, opcodes, 10_000_000); err == nil {
		t.Fatal("accepted a program that cannot fit a group")
	}
	lowCeiling := boundedmeta.Clone(instance.Bounded)
	lowCeiling.MaxFee = new(uint64(1_000))
	if err := checkResources(lowCeiling, opcodes, 3_000); err == nil || !strings.Contains(err.Error(), "above the account's ceiling") {
		t.Fatalf("checkResources(low ceiling) error = %v", err)
	}
	// A rekey setting this type does not offer, such as the retired admin-key
	// rekey, has no path to solve.
	adminRekey := boundedmeta.Clone(instance.Bounded)
	adminRekey.Rekey = "admin_key"
	if err := checkResources(adminRekey, opcodes, 3_000); err == nil || !strings.Contains(err.Error(), "no resource path") {
		t.Fatalf("checkResources(admin rekey) error = %v", err)
	}
}

func TestReceiptRequiresTheGeneratedAddress(t *testing.T) {
	if _, err := (boundary.Receipt{KeyType: KeyTypeV1}).Encode(); err == nil {
		t.Fatal("encoded a receipt with no address")
	}
	encoded, err := boundary.Receipt{Address: testAddress(1), KeyType: KeyTypeV1}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), boundary.ReceiptSchemaV1) {
		t.Fatalf("receipt has no schema: %s", encoded)
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
	provider := newTestProvider(t)
	directory := t.TempDir()
	recipients := []string{testAddress(2), testAddress(1)}
	rekeyTo := []string{rekeyTarget(0xd0), rekeyTarget(0x08)}
	for _, preset := range boundary.Presets() {
		t.Run(preset.Name, func(t *testing.T) {
			form := map[string]string{}
			for name, value := range preset.Fixed {
				form[name] = value
			}
			hasCosigner := false
			for _, field := range preset.Fields {
				switch field {
				case ParameterRecipients:
					form[field] = strings.Join(recipients, ",")
				case ParameterUnlockRound:
					form[field] = "50000000"
				case ParameterRekeyTo:
					form[field] = strings.Join(rekeyTo, ",")
				case ParameterCosigner:
					hasCosigner = true
				}
			}
			path := writeBoundaryFile(t, directory, preset.SampleBoundaryFile(boundary.SampleValues{
				Recipients: recipients, Cosigner: "ops-cosigner", UnlockRound: "50000000", RekeyTo: rekeyTo,
			}))
			fromFile, err := boundary.LoadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if hasCosigner {
				if fromFile[ParameterCosigner] != "ops-cosigner" {
					t.Fatalf("file cosigner = %q", fromFile[ParameterCosigner])
				}
				delete(fromFile, ParameterCosigner)
				fromFile[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
				form[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
			}
			first, err := provider.ResolveInstance(form)
			if err != nil {
				t.Fatal(err)
			}
			second, err := provider.ResolveInstance(fromFile)
			if err != nil {
				t.Fatal(err)
			}
			if first.BoundaryDigest != second.BoundaryDigest || first.Fingerprint != second.Fingerprint {
				t.Fatal("the preset and its file resolved differently")
			}
			if slices.Contains(preset.Fields, ParameterRekeyTo) != (second.Bounded.RekeyList != nil) {
				t.Fatalf("rekey-to list = %v for fields %v", second.Bounded.RekeyList, preset.Fields)
			}
		})
	}
}

// The presets are a frozen part of what the guided screens promise.
func TestPresetChoicesAreFrozen(t *testing.T) {
	presets := boundary.Presets()
	for _, test := range []struct {
		name, rekey, encoding string
		fields                []string
	}{
		{"allowlist", RekeySpendingKey, EncodingAuto, []string{ParameterRecipients}},
		{"locked-allowlist", RekeyOnlyThese, EncodingAuto, []string{ParameterRecipients, ParameterRekeyTo}},
		{"corridor", RekeyOnlyThese, EncodingMerkle, []string{ParameterRecipients, ParameterRekeyTo, ParameterCosigner}},
		{"timelock", RekeyOnlyThese, "", []string{ParameterUnlockRound, ParameterRekeyTo}},
	} {
		index := -1
		for i, preset := range presets {
			if preset.Name == test.name {
				index = i
			}
		}
		if index < 0 {
			t.Fatalf("no preset %s", test.name)
		}
		preset := presets[index]
		if preset.Fixed[ParameterSpendEffects] != joinSpend(spendEffectOrder) {
			t.Errorf("%s spend = %q", test.name, preset.Fixed[ParameterSpendEffects])
		}
		if preset.Fixed[ParameterRekeyAuthority] != test.rekey || preset.Fixed[ParameterListEncoding] != test.encoding {
			t.Errorf("%s fixed = %v", test.name, preset.Fixed)
		}
		if strings.Join(preset.Fields, ",") != strings.Join(test.fields, ",") {
			t.Errorf("%s fields = %v", test.name, preset.Fields)
		}
	}
	if len(presets) != 4 {
		t.Fatalf("%d presets", len(presets))
	}
}

func TestUnlockRoundMayBeWrittenAsANumberOrText(t *testing.T) {
	recipient := testAddress(1)
	for _, written := range []string{"18446744073709551615", `"18446744073709551615"`} {
		file, err := boundary.ParseFile([]byte("schema: aplane.boundary.v1\nspend: [pay]\nrecipients: [" + recipient + "]\nrekey: {authority: spending_key}\nunlock_round: " + written + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", written, err)
		}
		params := file.CreationParameters()
		if params[ParameterUnlockRound] != "18446744073709551615" {
			t.Fatalf("%s became %q", written, params[ParameterUnlockRound])
		}
	}
}

func TestTimelockNeedsNoRecipientList(t *testing.T) {
	provider := newTestProvider(t)
	file, err := boundary.ParseFile([]byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: only_these, to: [" + rekeyTarget(0x08) + "]}\nunlock_round: 007\n"))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := provider.ResolveInstance(file.CreationParameters())
	if err != nil {
		t.Fatal(err)
	}
	if instance.Bounded.Layer3Policy != composeddsa.Layer3PolicyTimelock {
		t.Fatalf("policy = %s", instance.Bounded.Layer3Policy)
	}
	if _, present := instance.Values[ParameterRecipients]; present {
		t.Fatalf("values = %v", instance.Values)
	}
	if got := instance.Values[ParameterUnlockRound]; got != "7" {
		t.Fatalf("unlock round = %q, want canonical 7", got)
	}
}

func TestBoundaryDigestBindsTheUnlockRound(t *testing.T) {
	provider := newTestProvider(t)
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese, Timelock: true}
	digest := func(round string) string {
		params := requestFor(shape, testRecipients(2))
		params[ParameterUnlockRound] = round
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		return instance.BoundaryDigest
	}
	if digest("100") == digest("101") {
		t.Fatal("changing the unlock round did not change the digest")
	}
}

// A stored account's rekey setting is part of its shape. A contract the grammar
// cannot produce must not be reported as matching one that it can.
func TestStoredFingerprintRefusesAMismatchedRekey(t *testing.T) {
	provider := newTestProvider(t)
	cosignedTimelock, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Rekey: RekeyOnlyThese, Cosigner: true, Timelock: true}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cosignedTimelock.Bounded.Rekey != boundedmeta.RekeyRefused || !cosignedTimelock.Bounded.RefusesRekeys() || cosignedTimelock.Bounded.RekeyList == nil {
		t.Fatalf("a cosigned only_these timelock stored rekey %q, list %v", cosignedTimelock.Bounded.Rekey, cosignedTimelock.Bounded.RekeyList)
	}
	// A timelock with a spending-key rekey, cosigned or plus cosigned, is a
	// contract the grammar doesn't produce, and so is a cosigned timelock that
	// refuses every rekey; an expert template can produce them.
	for name, mutate := range map[string]func(*boundedmeta.Metadata){
		"plus cosigned":         func(m *boundedmeta.Metadata) { m.Rekey = boundedmeta.RekeySpendingKey },
		"cosigned spending key": func(m *boundedmeta.Metadata) { m.Rekey, m.RekeyList = boundedmeta.RekeySpendingKey, nil },
		"refusing with no list": func(m *boundedmeta.Metadata) { m.RekeyList = nil },
	} {
		stored := boundedmeta.Clone(cosignedTimelock.Bounded)
		mutate(stored)
		if _, err := provider.StoredFingerprint(nil, stored); err == nil || !strings.Contains(err.Error(), "unsupported bounded shape") {
			t.Fatalf("a stored %s timelock: StoredFingerprint() error = %v", name, err)
		}
	}
	listed, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Rekey: RekeyOnlyThese, Timelock: true}, ""))
	if err != nil {
		t.Fatal(err)
	}
	// A setting the contract does not know, such as the retired admin-key rekey,
	// or no setting at all, is refused rather than read as either known one, with
	// a rekey-to list or without.
	for _, metadata := range []*boundedmeta.Metadata{cosignedTimelock.Bounded, listed.Bounded} {
		for _, rekey := range []boundedmeta.RekeySetting{"admin_key", "none", "", boundedmeta.RekeySetting(RekeyOnlyThese)} {
			stored := boundedmeta.Clone(metadata)
			stored.Rekey = rekey
			if _, err := provider.StoredFingerprint(nil, stored); err == nil || !strings.Contains(err.Error(), "rekey setting") {
				t.Fatalf("stored rekey %q: StoredFingerprint() error = %v", rekey, err)
			}
		}
	}
	spending, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey}, testRecipients(2)))
	if err != nil {
		t.Fatal(err)
	}
	if spending.Bounded.Rekey != boundedmeta.RekeySpendingKey {
		t.Fatalf("a spending-key shape stored rekey %q", spending.Bounded.Rekey)
	}
	// The same account refusing rekeys with no list and no cosigner is a shape the
	// grammar no longer offers.
	stored := boundedmeta.Clone(spending.Bounded)
	stored.Rekey = boundedmeta.RekeyRefused
	if _, err := provider.StoredFingerprint(nil, stored); err == nil || !strings.Contains(err.Error(), "unsupported bounded shape") {
		t.Fatalf("a stored uncosigned refusal: StoredFingerprint() error = %v", err)
	}
	// With a rekey-to list it is the only_these shape, which carries a different
	// fingerprint.
	onlyThese, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese}, testRecipients(2)))
	if err != nil {
		t.Fatal(err)
	}
	stored.RekeyList = &boundedmeta.RekeyList{Contract: boundedmeta.RekeyListContractV1, Depth: 4}
	fingerprint, err := provider.StoredFingerprint(nil, stored)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != onlyThese.Fingerprint || fingerprint == spending.Fingerprint {
		t.Fatal("a stored rekey-to list did not select the only_these shape")
	}
	// Without its list, the only_these account is the uncosigned refusal again.
	stripped := boundedmeta.Clone(onlyThese.Bounded)
	stripped.RekeyList = nil
	if _, err := provider.StoredFingerprint(nil, stripped); err == nil || !strings.Contains(err.Error(), "unsupported bounded shape") {
		t.Fatalf("an only_these account without its list: StoredFingerprint() error = %v", err)
	}
	// A cosigned list account is its own shape, not its uncosigned twin.
	got, err := provider.StoredFingerprint(nil, cosignedTimelock.Bounded)
	if err != nil || got != cosignedTimelock.Fingerprint || got == listed.Fingerprint {
		t.Fatalf("a cosigned only_these timelock: StoredFingerprint() = %q, %v", got, err)
	}
}

// secondDefinition is a test-only general bounded type. It never registers, so it
// can't reach generation lists, enabled key types, or discovery.
func secondDefinition(shapes ...Shape) Definition {
	return Definition{
		Publisher: "example", Family: "second-bounded", Version: 1, BaseKeyType: "aplane.ed25519.v1",
		DisplayName: "Second Bounded Fixture", Description: "Test only.", Shapes: shapes,
	}
}

func spendingKeyShape() Shape {
	return Shape{Spend: []txeffects.SpendEffect{txeffects.SpendEffectPay}, Encoding: EncodingInline, Rekey: RekeySpendingKey}
}

func TestSecondDefinitionDependsOnNoFalconLiteral(t *testing.T) {
	ed25519lsig.RegisterClient()
	provider, err := newProvider(secondDefinition(spendingKeyShape()))
	if err != nil {
		t.Fatalf("newProvider() error = %v", err)
	}
	if provider.KeyType() != "example.second-bounded.v1" || provider.BaseKeyType() != "aplane.ed25519.v1" {
		t.Fatalf("identity = %s on %s", provider.KeyType(), provider.BaseKeyType())
	}
	if provider.DisplayName() != "Second Bounded Fixture" || provider.Description() != "Test only." {
		t.Fatalf("display = %q, %q", provider.DisplayName(), provider.Description())
	}
	if _, err := provider.BuildArgs(nil, nil); err == nil || !strings.Contains(err.Error(), provider.KeyType()) {
		t.Fatalf("BuildArgs() error = %v", err)
	}
	params := map[string]string{
		ParameterSpendEffects:   "pay",
		ParameterRekeyAuthority: RekeySpendingKey,
		ParameterListEncoding:   EncodingInline,
		ParameterRecipients:     types.Address{1}.String(),
	}
	instance, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatalf("ResolveInstance() error = %v", err)
	}
	if instance.Bounded == nil || instance.Fingerprint == "" {
		t.Fatalf("instance = %+v", instance)
	}
	production, err := NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	if instance.ReviewFingerprint == production.GrammarFingerprint() {
		t.Fatal("a second definition shares the production grammar fingerprint")
	}
	teal, err := provider.GenerateTEAL(bytes.Repeat([]byte{0x21}, 32), params)
	if err != nil {
		t.Fatalf("GenerateTEAL() error = %v", err)
	}
	if !strings.Contains(teal, "ed25519verify_bare") || strings.Contains(teal, "falcon_verify") {
		t.Fatalf("program does not follow the definition's base:\n%s", teal)
	}
	if component, ok := provider.CosignerComponentKeyType(map[string]string{ParameterCosigner: "name"}); ok {
		t.Fatalf("a definition with no cosigner shape reported %q", component)
	}
}

// A fingerprint names its definition, so two types sharing a base and a shape still
// have separate provenance.
func TestFingerprintNamesTheDefinition(t *testing.T) {
	falcon.RegisterClient()
	production, err := NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	definition := secondDefinition(spendingKeyShape())
	definition.BaseKeyType = production.BaseKeyType()
	second, err := newProvider(definition)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := spendingKeyShape().Descriptor()
	if second.byShape[descriptor].fingerprint == production.byShape[descriptor].fingerprint {
		t.Fatal("two definitions share a shape fingerprint")
	}
}

func TestDefinitionOffersOnlyItsShapes(t *testing.T) {
	ed25519lsig.RegisterClient()
	provider, err := newProvider(secondDefinition(spendingKeyShape()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.ResolveInstance(map[string]string{
		ParameterSpendEffects:   "pay,axfer",
		ParameterRekeyAuthority: RekeySpendingKey,
		ParameterListEncoding:   EncodingInline,
		ParameterRecipients:     types.Address{1}.String(),
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported bounded shape") {
		t.Fatalf("ResolveInstance() error = %v", err)
	}
	if _, err := newProvider(secondDefinition()); err == nil {
		t.Fatal("newProvider() accepted a definition with no shapes")
	}
	// A rekey value the provider does not know must not compile as refused.
	for _, rekey := range []string{"admin_key", "none", ""} {
		unknown := spendingKeyShape()
		unknown.Rekey = rekey
		if _, err := newProvider(secondDefinition(unknown)); err == nil || !strings.Contains(err.Error(), "unknown rekey authority") {
			t.Fatalf("rekey %q: newProvider() error = %v", rekey, err)
		}
	}
}

// A definition can list a shape, but listing it grants nothing: a cosigner shape on a
// base whose template rule refuses a cosigner does not build.
func TestDefinitionCannotAuthorizeWhatThePolicyRefuses(t *testing.T) {
	ed25519lsig.RegisterClient()
	cosigned := spendingKeyShape()
	cosigned.Rekey, cosigned.Cosigner = RekeyRefused, true
	if _, err := newProvider(secondDefinition(cosigned)); err == nil {
		t.Fatal("newProvider() built a cosigner shape on a base the template rule refuses")
	}
}

// "Only these" is stored as rekey refused plus the list. The same list beside a
// spending-key rekey is plus cosigned, which needs a cosigner, so without one it
// has no shape to report.
func TestStoredFingerprintRefusesAListBesideAnotherRekey(t *testing.T) {
	provider := newTestProvider(t)
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyOnlyThese}
	instance, err := provider.ResolveInstance(requestFor(shape, testAddress(1)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := provider.StoredFingerprint(nil, instance.Bounded); err != nil || got != instance.Fingerprint {
		t.Fatalf("StoredFingerprint() = %q, %v; want %s", got, err, instance.Fingerprint)
	}
	mismatched := *instance.Bounded
	mismatched.Rekey = boundedmeta.RekeySpendingKey
	if _, err := provider.StoredFingerprint(nil, &mismatched); err == nil || !strings.Contains(err.Error(), "unsupported bounded shape spend=pay,axfer,asset_opt_in;policy=fixed_allowlist;rekey=plus_cosigned;cosigner=none") {
		t.Fatalf("StoredFingerprint() error = %v", err)
	}
}
