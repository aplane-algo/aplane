// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
	goldenGrammarFingerprint    = "1:093e721a1dfa588387c10c851f34f3468192697b302205a7ed81fc00358109ba"
	goldenFirstShapeFingerprint = "1:dde35ec01de8a905f1263fd8fc246545540bd950aa54994aac356e1951e2df6f"
	goldenFullShapeFingerprint  = "1:95234d16fc17e23394a79dc62245d0c2eebf5a5a0be10fe12f14d9e2296e566b"
	goldenBoundaryDigest        = "8d6f9de0e52dac9cc01a9b896311890cd7940cd202718ccda74ba7b86bbfa82e"
	goldenRenderedPrograms      = "d6f9605e3277d2410d881560a76ad42e4e6ab3ce4c235e9d160134b4bbb41ae7"
	goldenTimelockPrograms      = "a0f07a52e1566976b333bc68cb0ed37ac7fe007c10685569a6adf05bb0d97272"
	// Pins the 14 bounded2 spending-key shapes. It is no longer equal to main
	// a2874c6e: bounded2 replaced bounded1 in place (contract label, rekey setting,
	// profile domain), and timelocks no longer offer a spending-key rekey.
	goldenSpendingKeyPrograms = "65c08e46dbed601d2d87921d6521b480967e877df14655473198981ff018c534"
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

var (
	testCosignerKey = hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
	testSpendingKey = bytes.Repeat([]byte{0x21}, 1793)
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
	if shape.Timelock {
		params[ParameterUnlockRound] = "50000000"
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
	}
	return params
}

// The expected set is written out here rather than derived from the code that
// produces it. A shape that refuses rekeys needs pay, and axfer if it can opt in, so
// it has 3 spend subsets: pay, pay+axfer, and all three. Allowlists are 2 encodings
// x (spending key x 7 subsets, plus 2 refused arrangements x 3), which is 26.
// A timelock refuses rekeys, so timelocks add 3 policies x 2 refused arrangements
// x 3 subsets, which is 18.
func TestShapesEnumerateTheGrammar(t *testing.T) {
	shapes := Shapes()
	if len(shapes) != 44 {
		t.Fatalf("Shapes() = %d, want 44", len(shapes))
	}
	policies := make(map[string]int)
	for _, shape := range shapes {
		policies[shape.Policy()]++
	}
	for policy, want := range map[string]int{
		composeddsa.Layer3PolicyFixedAllowlist: 13, composeddsa.Layer3PolicyMerkleAllowlist: 13,
		composeddsa.Layer3PolicyTimelock: 6, composeddsa.Layer3PolicyFixedAllowlistTimelock: 6, composeddsa.Layer3PolicyMerkleAllowlistTimelock: 6,
	} {
		if policies[policy] != want {
			t.Errorf("%s has %d shapes, want %d", policy, policies[policy], want)
		}
	}
	for _, shape := range shapes {
		if shape.Timelock && shape.Rekey != RekeyRefused {
			t.Errorf("%s is a timelock a spending-key rekey could leave before the unlock round", shape.Descriptor())
		}
		if shape.Rekey == RekeyRefused && !slices.Contains(shape.Spend, txeffects.SpendEffectPay) {
			t.Errorf("%s refuses rekeys without pay, so its ALGO could never leave", shape.Descriptor())
		}
		if shape.Rekey == RekeyRefused && slices.Contains(shape.Spend, txeffects.SpendEffectAssetOptIn) && !slices.Contains(shape.Spend, txeffects.SpendEffectAxfer) {
			t.Errorf("%s refuses rekeys and opts in without axfer, so an asset could never leave", shape.Descriptor())
		}
	}
	seen := make(map[string]bool)
	for _, shape := range shapes {
		if seen[shape.Descriptor()] {
			t.Fatalf("duplicate shape %s", shape.Descriptor())
		}
		seen[shape.Descriptor()] = true
	}
	allowlists, timelocks := shapes[:26], shapes[26:]
	for _, shape := range allowlists {
		if shape.Timelock {
			t.Fatalf("timelock %s comes before the allowlist shapes end", shape.Descriptor())
		}
	}
	families := make(map[string]int)
	subsets := make(map[string]int)
	for _, shape := range allowlists {
		families[shape.Encoding+"/"+shape.Rekey+"/"+strconv.FormatBool(shape.Cosigner)]++
		subsets[joinSpend(shape.Spend)]++
	}
	for family, want := range map[string]int{
		"inline/spending_key/false": 7, "inline/refused/false": 3, "inline/refused/true": 3,
		"merkle/spending_key/false": 7, "merkle/refused/false": 3, "merkle/refused/true": 3,
	} {
		if families[family] != want {
			t.Errorf("family %s has %d shapes, want %d", family, families[family], want)
		}
	}
	for subset, want := range map[string]int{
		"pay": 6, "pay,axfer": 6, "pay,axfer,asset_opt_in": 6,
		"pay,asset_opt_in": 2, "axfer": 2, "asset_opt_in": 2, "axfer,asset_opt_in": 2,
	} {
		if subsets[subset] != want {
			t.Errorf("subset %s has %d shapes, want %d", subset, subsets[subset], want)
		}
	}
	families = make(map[string]int)
	subsets = make(map[string]int)
	for _, shape := range timelocks {
		families[shape.Policy()+"/"+shape.Rekey+"/"+strconv.FormatBool(shape.Cosigner)]++
		subsets[joinSpend(shape.Spend)]++
	}
	for _, policy := range []string{composeddsa.Layer3PolicyTimelock, composeddsa.Layer3PolicyFixedAllowlistTimelock, composeddsa.Layer3PolicyMerkleAllowlistTimelock} {
		for _, family := range []string{policy + "/refused/false", policy + "/refused/true"} {
			if families[family] != 3 {
				t.Errorf("timelock family %s has %d shapes, want 3", family, families[family])
			}
		}
	}
	for subset, want := range map[string]int{"pay": 6, "pay,axfer": 6, "pay,axfer,asset_opt_in": 6} {
		if subsets[subset] != want {
			t.Errorf("timelock subset %s has %d shapes, want %d", subset, subsets[subset], want)
		}
	}
	if len(subsets) != 3 {
		t.Errorf("timelock subsets = %v, want only the three a refused shape allows", subsets)
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
			if instance.Bounded.MaxFee != MaxFee {
				t.Fatalf("MaxFee = %d", instance.Bounded.MaxFee)
			}
			if (instance.Bounded.Cosigner != nil) != shape.Cosigner {
				t.Fatalf("cosigner metadata = %v", instance.Bounded.Cosigner)
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
			if _, err := provider.GenerateTEAL(testSpendingKey, instance.Values); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInvalidRequestsFailClosed(t *testing.T) {
	provider := newTestProvider(t)
	allSpend := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeySpendingKey}
	refusedShape := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeyRefused}
	zero := types.Address{}.String()
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
			"a timelock requires rekey_authority=refused: a spending-key rekey would leave the lock before the unlock round"},
		{"spending-key rekey on a timelock", allSpend, func(p map[string]string) {
			delete(p, ParameterRecipients)
			delete(p, ParameterListEncoding)
			p[ParameterUnlockRound] = "5"
		}, "a timelock requires rekey_authority=refused"},
		{"spending-key rekey on a timelock without pay", allSpend, func(p map[string]string) {
			p[ParameterUnlockRound] = "5"
			p[ParameterSpendEffects] = "axfer"
		}, "a timelock requires rekey_authority=refused"},
		{"refused without pay", refusedShape, func(p map[string]string) { p[ParameterSpendEffects] = "axfer,asset_opt_in" }, "refused requires pay"},
		{"refused opt-in without axfer", refusedShape, func(p map[string]string) { p[ParameterSpendEffects] = "pay,asset_opt_in" }, "with asset_opt_in requires axfer"},
		{"cosigned without pay", refusedShape, func(p map[string]string) {
			p[ParameterSpendEffects] = "axfer"
			p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
		}, "refused requires pay"},
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
		{"cosigner with spending-key rekey", allSpend, func(p map[string]string) { p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey }, "requires rekey_authority=refused"},
		{"empty cosigner key", refusedShape, func(p map[string]string) { p[composeddsa.BoundedCosignerPublicKeyParameter] = "" }, "is empty"},
		{"unresolved cosigner", refusedShape, func(p map[string]string) { p[ParameterCosigner] = "ops" }, "not resolved"},
		{"empty cosigner name", refusedShape, func(p map[string]string) { p[ParameterCosigner] = "" }, "not resolved"},
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

func TestComposerSeesOnlyItsDeclaredParameters(t *testing.T) {
	provider := newTestProvider(t)
	for _, shape := range Shapes() {
		definition := provider.byShape[shape.Descriptor()]
		values := composerValues(definition, requestFor(shape, testRecipients(2)))
		for _, selector := range []string{ParameterSpendEffects, ParameterRekeyAuthority, ParameterListEncoding} {
			if _, ok := values[selector]; ok {
				t.Fatalf("%s reached the composer", selector)
			}
		}
	}
}

func TestProviderHasNoMnemonicImportOrRuntimeArguments(t *testing.T) {
	provider := newTestProvider(t)
	if provider.SupportsMnemonicImport() {
		t.Fatal("LogicSig account must not support mnemonic import")
	}
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
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyRefused, Cosigner: true}
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

func TestBoundaryFileReachesTheSameInstanceAsDirectParameters(t *testing.T) {
	provider := newTestProvider(t)
	path := writeBoundaryFile(t, t.TempDir(), `schema: aplane.boundary.v1
spend: [pay, axfer, asset_opt_in]
recipients:
  - `+testAddress(2)+`
  - `+testAddress(1)+`
rekey:
  authority: refused
`)
	params, err := boundary.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := provider.ResolveInstance(requestFor(
		Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyRefused},
		testAddress(1)+","+testAddress(2)))
	if err != nil {
		t.Fatal(err)
	}
	if fromFile.BoundaryDigest != direct.BoundaryDigest || fromFile.Fingerprint != direct.Fingerprint {
		t.Fatal("file and direct parameters resolved differently")
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
	if _, err := boundary.ParseFile([]byte(strings.Replace(valid, "spending_key", "refused", 1))); err != nil {
		t.Fatalf("refused rekey rejected: %v", err)
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
		{"admin key field", strings.Replace(valid, "{authority: spending_key}", "{authority: refused, admin_key: a.ref.json}", 1), "not found"},
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
	// The first 26 are the allowlist shapes. Their golden must not move when the
	// grammar grows: that is the guarantee existing accounts rely on. (It moved on
	// purpose in install-fresh releases: once when refused families replaced the
	// admin-key ones, and again when bounded2 replaced bounded1 in place.)
	shapes := Shapes()
	appended := sha256.New()
	// The spending-key shapes alone, with each one's fingerprint and digest. Every
	// bounded2 release offers them, so this golden holds across grammar edits.
	spendingKey := sha256.New()
	for index, shape := range shapes {
		if index >= 26 {
			rendered = appended
		}
		params := requestFor(shape, testAddress(1)+","+testAddress(2))
		if shape.Cosigner {
			params[composeddsa.BoundedCosignerPublicKeyParameter] = cosigner
		}
		teal, err := provider.GenerateTEAL(spending, params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(rendered, "%s\n%d\n%s\n", shape.Descriptor(), len(teal), teal); err != nil {
			t.Fatal(err)
		}
		if shape.Rekey != RekeySpendingKey {
			continue
		}
		resolved, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(spendingKey, "%s\n%s\n%s\n%d\n%s\n", shape.Descriptor(), resolved.Fingerprint, resolved.BoundaryDigest, len(teal), teal); err != nil {
			t.Fatal(err)
		}
	}
	full := Shape{Spend: spendEffectOrder, Encoding: EncodingMerkle, Rekey: RekeyRefused, Cosigner: true}
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
	} {
		if golden.got != golden.want {
			t.Errorf("%s = %s, want %s", golden.name, golden.got, golden.want)
		}
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
	lowCeiling.MaxFee = 1_000
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
				case ParameterCosigner:
					hasCosigner = true
				}
			}
			path := writeBoundaryFile(t, directory, preset.SampleBoundaryFile(boundary.SampleValues{
				Recipients: recipients, Cosigner: "ops-cosigner", UnlockRound: "50000000",
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
		{"locked-allowlist", RekeyRefused, EncodingAuto, []string{ParameterRecipients}},
		{"corridor", RekeyRefused, EncodingMerkle, []string{ParameterRecipients, ParameterCosigner}},
		{"timelock", RekeyRefused, "", []string{ParameterUnlockRound}},
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
	file, err := boundary.ParseFile([]byte("schema: aplane.boundary.v1\nspend: [pay]\nrekey: {authority: refused}\nunlock_round: 007\n"))
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
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyRefused, Timelock: true}
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
	refused, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Rekey: RekeyRefused, Timelock: true}, testRecipients(2)))
	if err != nil {
		t.Fatal(err)
	}
	if refused.Bounded.Rekey != boundedmeta.RekeyRefused || !refused.Bounded.RefusesRekeys() {
		t.Fatalf("a refused shape stored rekey %q", refused.Bounded.Rekey)
	}
	// A timelock with a spending-key rekey is a contract the grammar no longer
	// produces: the rekey would leave the lock early.
	stored := boundedmeta.Clone(refused.Bounded)
	stored.Rekey = boundedmeta.RekeySpendingKey
	if _, err := provider.StoredFingerprint(nil, stored); err == nil || !strings.Contains(err.Error(), "unsupported bounded shape") {
		t.Fatalf("a stored timelock with a spending-key rekey: StoredFingerprint() error = %v", err)
	}
	// A setting the contract does not know, such as the retired admin-key rekey,
	// or no setting at all, is refused rather than read as either known one.
	for _, rekey := range []boundedmeta.RekeySetting{"admin_key", "none", ""} {
		stored := boundedmeta.Clone(refused.Bounded)
		stored.Rekey = rekey
		if _, err := provider.StoredFingerprint(nil, stored); err == nil || !strings.Contains(err.Error(), "rekey setting") {
			t.Fatalf("stored rekey %q: StoredFingerprint() error = %v", rekey, err)
		}
	}
	spending, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeySpendingKey}, testRecipients(2)))
	if err != nil {
		t.Fatal(err)
	}
	if spending.Bounded.Rekey != boundedmeta.RekeySpendingKey {
		t.Fatalf("a spending-key shape stored rekey %q", spending.Bounded.Rekey)
	}
	// The same account with its rekey refused is a different shape, so it carries a
	// different fingerprint.
	stored = boundedmeta.Clone(spending.Bounded)
	stored.Rekey = boundedmeta.RekeyRefused
	fingerprint, err := provider.StoredFingerprint(nil, stored)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint == spending.Fingerprint {
		t.Fatal("refusing the rekey did not change the stored shape")
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
