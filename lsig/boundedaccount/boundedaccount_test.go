// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
)

const (
	goldenGrammarFingerprint    = "1:f623ed7c8601a81433f1fe67150cc49ab7b7589a88764007783627e4744b183c"
	goldenFirstShapeFingerprint = "1:4cd1c6fd6b43ce9085574e3124f041c47c53e317e395b43272e8a7453eec5a3c"
	goldenFullShapeFingerprint  = "1:0d5f6c9957c7cd219527f2110910d873982bdfd46e136b5f06742d741827ea4c"
	goldenBoundaryDigest        = "5403a32fc1b8ae9d8c9fc18d11c881d65f418e03c2dddd7aed1e6afdbae6c727"
	goldenRenderedPrograms      = "d9c422d5b5e496e84e2aaa853daed7a1a9f7faa9d62f444c84729edeee6364bc"
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
	testAdminKey    = hex.EncodeToString(bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize))
	testCosignerKey = hex.EncodeToString(bytes.Repeat([]byte{0x41}, boundedmeta.CosignerPublicKeySizeV1))
	testSpendingKey = bytes.Repeat([]byte{0x21}, 1793)
)

func requestFor(shape Shape, recipients string) map[string]string {
	params := map[string]string{
		ParameterSpendEffects:   joinSpend(shape.Spend),
		ParameterRekeyAuthority: shape.Rekey,
		ParameterListEncoding:   shape.Encoding,
		ParameterRecipients:     recipients,
	}
	if shape.Rekey == RekeyAdminKey {
		params[composeddsa.BoundedAdminPublicKeyParameter] = testAdminKey
	}
	if shape.Cosigner {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
	}
	return params
}

// The expected set is written out here rather than derived from the code that
// produces it: 2 encodings x 3 authority families x 7 spend subsets.
func TestShapesEnumerateTheGrammar(t *testing.T) {
	shapes := Shapes()
	if len(shapes) != 42 {
		t.Fatalf("Shapes() = %d, want 42", len(shapes))
	}
	families := make(map[string]int)
	subsets := make(map[string]int)
	seen := make(map[string]bool)
	for _, shape := range shapes {
		if seen[shape.Descriptor()] {
			t.Fatalf("duplicate shape %s", shape.Descriptor())
		}
		seen[shape.Descriptor()] = true
		families[shape.Encoding+"/"+shape.Rekey+"/"+strconv.FormatBool(shape.Cosigner)]++
		subsets[joinSpend(shape.Spend)]++
	}
	for _, family := range []string{
		"inline/spending_key/false", "inline/admin_key/false", "inline/admin_key/true",
		"merkle/spending_key/false", "merkle/admin_key/false", "merkle/admin_key/true",
	} {
		if families[family] != 7 {
			t.Errorf("family %s has %d shapes, want 7", family, families[family])
		}
	}
	for _, subset := range []string{
		"pay", "axfer", "asset_opt_in", "pay,axfer", "pay,asset_opt_in", "axfer,asset_opt_in", "pay,axfer,asset_opt_in",
	} {
		if subsets[subset] != 6 {
			t.Errorf("subset %s has %d shapes, want 6", subset, subsets[subset])
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
	admin := Shape{Spend: spendEffectOrder, Encoding: EncodingAuto, Rekey: RekeyAdminKey}
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
		{"admin rekey without key", admin, func(p map[string]string) { delete(p, composeddsa.BoundedAdminPublicKeyParameter) }, "requires bounded_admin_public_key"},
		{"unused admin key", allSpend, func(p map[string]string) { p[composeddsa.BoundedAdminPublicKeyParameter] = testAdminKey }, "does not use"},
		{"cosigner without admin", allSpend, func(p map[string]string) { p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey }, "requires rekey_authority=admin_key"},
		{"empty cosigner key", admin, func(p map[string]string) { p[composeddsa.BoundedCosignerPublicKeyParameter] = "" }, "is empty"},
		{"unresolved cosigner", admin, func(p map[string]string) { p[ParameterCosigner] = "ops" }, "not resolved"},
		{"empty cosigner name", admin, func(p map[string]string) { p[ParameterCosigner] = "" }, "not resolved"},
		{"same authority", admin, func(p map[string]string) {
			p[composeddsa.BoundedAdminPublicKeyParameter] = testCosignerKey
			p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
		}, "must differ"},
		{"short admin key", admin, func(p map[string]string) { p[composeddsa.BoundedAdminPublicKeyParameter] = "abcd" }, "bounded_admin_public_key"},
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
	shape := Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyAdminKey, Cosigner: true}
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
		"admin key": func(p map[string]string) {
			p[composeddsa.BoundedAdminPublicKeyParameter] = hex.EncodeToString(bytes.Repeat([]byte{0x32}, composeddsa.BoundedAdminPublicKeySize))
		},
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
	if smaller := grammarFingerprint(provider.ordered[:41]); smaller == full {
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
	directory := t.TempDir()
	id, err := witness.ID(witness.Falcon1024V1, mustHex(t, testAdminKey))
	if err != nil {
		t.Fatal(err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, id, testAdminKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "admin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "admin", "ops.wit.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeBoundaryFile(t, directory, `schema: aplane.boundary.v1
spend: [pay, axfer, asset_opt_in]
recipients:
  - `+testAddress(2)+`
  - `+testAddress(1)+`
rekey:
  authority: admin_key
  admin_key: ./admin/ops.wit.json
`)
	params, err := LoadBoundaryFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := provider.ResolveInstance(params)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := provider.ResolveInstance(requestFor(
		Shape{Spend: spendEffectOrder, Encoding: EncodingInline, Rekey: RekeyAdminKey},
		testAddress(1)+","+testAddress(2)))
	if err != nil {
		t.Fatal(err)
	}
	if fromFile.BoundaryDigest != direct.BoundaryDigest || fromFile.Fingerprint != direct.Fingerprint {
		t.Fatal("file and direct parameters resolved differently")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestBoundaryFileLeavesCosignerNameForTheSigner(t *testing.T) {
	file, err := ParseBoundaryFile([]byte(`schema: aplane.boundary.v1
spend: [pay]
recipients: [` + testAddress(1) + `]
rekey: {authority: spending_key}
cosigner: ops-cosigner
`))
	if err != nil {
		t.Fatal(err)
	}
	params, err := file.CreationParameters(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if params[ParameterCosigner] != "ops-cosigner" {
		t.Fatalf("cosigner = %q", params[ParameterCosigner])
	}
}

func TestBoundaryFileRejections(t *testing.T) {
	recipient := testAddress(1)
	valid := "schema: aplane.boundary.v1\nspend: [pay]\nrecipients: [" + recipient + "]\nrekey: {authority: spending_key}\n"
	if _, err := ParseBoundaryFile([]byte(valid)); err != nil {
		t.Fatalf("valid file rejected: %v", err)
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
		{"no recipients", strings.Replace(valid, "recipients: ["+recipient+"]\n", "", 1), "recipients is required"},
		{"no rekey", strings.Replace(valid, "rekey: {authority: spending_key}\n", "", 1), "rekey is required"},
		{"bad authority", strings.Replace(valid, "spending_key", "nobody", 1), "rekey.authority must be"},
		{"admin path with spending key", strings.Replace(valid, "{authority: spending_key}", "{authority: spending_key, admin_key: a.wit.json}", 1), "not used"},
		{"admin key without path", strings.Replace(valid, "spending_key", "admin_key", 1), "requires rekey.admin_key"},
		{"unknown field", valid + "unlock_round: \"5\"\n", "not found"},
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
			_, err := ParseBoundaryFile([]byte(test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ParseBoundaryFile error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := ParseBoundaryFile(bytes.Repeat([]byte{' '}, MaxBoundaryFileBytes+1)); err == nil {
		t.Fatal("accepted an oversized file")
	}
}

func TestAdminWitnessMustBeAPublicFalconReference(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "private.wit"), []byte("not a reference"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := writeBoundaryFile(t, directory, `schema: aplane.boundary.v1
spend: [pay]
recipients: [`+testAddress(1)+`]
rekey: {authority: admin_key, admin_key: private.wit}
`)
	if _, err := LoadBoundaryFile(file); err == nil || !strings.Contains(err.Error(), "admin witness") {
		t.Fatalf("LoadBoundaryFile error = %v", err)
	}
}

func generalGoldenKeys() (spending []byte, admin, cosigner string) {
	return bytes.Repeat([]byte{0x21}, 1793),
		hex.EncodeToString(bytes.Repeat([]byte{0x31}, composeddsa.BoundedAdminPublicKeySize)),
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
func TestGeneralFingerprintGoldens(t *testing.T) {
	provider := newTestProvider(t)
	spending, admin, cosigner := generalGoldenKeys()

	rendered := sha256.New()
	for _, shape := range Shapes() {
		params := requestFor(shape, testAddress(1)+","+testAddress(2))
		if shape.Rekey == RekeyAdminKey {
			params[composeddsa.BoundedAdminPublicKeyParameter] = admin
		}
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
	}
	full := Shape{Spend: spendEffectOrder, Encoding: EncodingMerkle, Rekey: RekeyAdminKey, Cosigner: true}
	instance, err := provider.ResolveInstance(requestFor(full, testAddress(1)+","+testAddress(2)))
	if err != nil {
		t.Fatal(err)
	}
	for _, golden := range []struct{ name, got, want string }{
		{"grammar", provider.GrammarFingerprint(), goldenGrammarFingerprint},
		{"first shape", provider.ordered[0].fingerprint, goldenFirstShapeFingerprint},
		{"full shape", instance.Fingerprint, goldenFullShapeFingerprint},
		{"boundary digest", instance.BoundaryDigest, goldenBoundaryDigest},
		{"rendered programs", hex.EncodeToString(rendered.Sum(nil)), goldenRenderedPrograms},
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
}
