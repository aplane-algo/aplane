// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	ed25519v1 "github.com/aplane-algo/aplane/lsig/ed25519lsig/v1"
	"github.com/aplane-algo/aplane/lsig/falcon1024/family"
	falconv1 "github.com/aplane-algo/aplane/lsig/falcon1024/v1"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

type base struct {
	name        string
	provider    *plainhost.Provider
	spendingKey []byte
}

func bases(t *testing.T) []base {
	t.Helper()
	falcon, err := plainhost.Wrap(&falconv1.Falcon1024V1{}, plainhost.Base{Ops: falconv1.NewFalconOps(family.FalconBase), SaltStyle: lsigsalt.StyleAlgodAutoSalt})
	if err != nil {
		t.Fatal(err)
	}
	ed, err := plainhost.Wrap(ed25519v1.NewProvider(), plainhost.Base{Ops: ed25519v1.NewOps(), SaltStyle: lsigsalt.StyleAlgodAutoSalt})
	if err != nil {
		t.Fatal(err)
	}
	return []base{
		{"falcon", falcon, bytes.Repeat([]byte{0x22}, family.PublicKeySize)},
		{"ed25519", ed, bytes.Repeat([]byte{0x22}, 32)},
	}
}

// falconCosigner is the default cosigner key type, Falcon-1024.
const falconCosigner = boundedmeta.DefaultCosignerComponentKeyType

var (
	testCosigner = strings.Repeat("44", boundedmeta.DefaultCosignerPublicKeySize)
	testListKey  = bytes.Repeat([]byte{0x77}, 64)
)

func testRekeyTo() string {
	var a, b types.Address
	a[0], b[0] = 0x31, 0x32
	return b.String() + "," + a.String()
}

func request(rekey string) map[string]string {
	return requestFor(plainhost.Arrangement{Rekey: rekey, Cosigner: falconCosigner})
}

// testCosignerFor is a test cosigner key of componentKeyType's size.
func testCosignerFor(componentKeyType string) string {
	size, _, ok := boundedmeta.CosignerSizes(componentKeyType)
	if !ok {
		panic("no test cosigner for " + componentKeyType)
	}
	return strings.Repeat("44", size)
}

// legacyArrangement prints an arrangement as the goldens printed it when the
// cosigner was a flag, so a default-cosigner arrangement hashes as it did.
func legacyArrangement(a plainhost.Arrangement) string {
	return fmt.Sprintf("{Rekey:%s Cosigner:%t}", a.Rekey, a.Cosigner != "")
}

func requestFor(arrangement plainhost.Arrangement) map[string]string {
	params := map[string]string{plainhost.ParameterRekeyAuthority: arrangement.Rekey}
	if arrangement.Cosigner != "" {
		params[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerFor(arrangement.Cosigner)
		if arrangement.Cosigner != boundedmeta.DefaultCosignerComponentKeyType {
			params[boundedmeta.CosignerKeyTypeParameter] = arrangement.Cosigner
		}
	}
	if arrangement.Rekey == plainhost.RekeyOnlyThese || arrangement.Rekey == plainhost.RekeyPlusCosigned {
		params[plainhost.ParameterRekeyTo] = testRekeyTo()
	}
	return params
}

// With no parameters the key type is the plain program it was, with no overlay
// contract; it can be created as an account like any other.
func TestNoParametersIsThePlainProgram(t *testing.T) {
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			instance, err := b.provider.ResolveInstance(nil)
			if err != nil {
				t.Fatal(err)
			}
			if instance.Bounded != nil || instance.Fingerprint != "" {
				t.Fatalf("instance = %+v", instance)
			}
			got, err := b.provider.GenerateTEAL(b.spendingKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			want, err := b.provider.Plain.GenerateTEAL(b.spendingKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("plain program changed:\n%s\nwant\n%s", got, want)
			}
			metadata, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, nil, []byte{1})
			if err != nil || metadata != nil {
				t.Fatalf("plain program metadata = %+v, %v", metadata, err)
			}
			if _, ok := b.provider.CosignerComponentKeyTypes(nil); ok {
				t.Fatal("the plain program asks for a cosigner")
			}
			if err := b.provider.ValidateCreationParams(nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Every arrangement, with or without a cosigner, renders plain1 with no envelope
// and records a fingerprint its stored metadata leads back to.
func TestEveryArrangementResolvesToPlain1(t *testing.T) {
	if got := len(plainhost.Arrangements()); got != 11 {
		t.Fatalf("%d arrangements, want 11: four rekey settings with each of two cosigner types, three without", got)
	}
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			seen := map[string]bool{}
			for _, arrangement := range plainhost.Arrangements() {
				rekey := fmt.Sprintf("%s/cosigner=%v", arrangement.Rekey, arrangement.Cosigner)
				params := requestFor(arrangement)
				instance, err := b.provider.ResolveInstance(params)
				if err != nil {
					t.Fatalf("%s: %v", rekey, err)
				}
				metadata := instance.Bounded
				if metadata == nil || metadata.Contract != boundedmeta.PlainContract || metadata.MaxFee != nil ||
					(metadata.Cosigner != nil) != (arrangement.Cosigner != "") || metadata.Layer3Policy != boundedmeta.Layer3PolicyNone {
					t.Fatalf("%s: instance = %+v", rekey, instance)
				}
				wantList := arrangement.Rekey == plainhost.RekeyOnlyThese || arrangement.Rekey == plainhost.RekeyPlusCosigned
				wantSpendingKey := arrangement.Rekey == plainhost.RekeySpendingKey || arrangement.Rekey == plainhost.RekeyPlusCosigned
				if (metadata.RekeyList != nil) != wantList || (metadata.Rekey == boundedmeta.RekeySpendingKey) != wantSpendingKey {
					t.Fatalf("%s: rekey %s, list %v", rekey, metadata.Rekey, metadata.RekeyList)
				}
				if instance.ReviewFingerprint != b.provider.GrammarFingerprint() || instance.BoundaryDigest == "" || seen[instance.Fingerprint] {
					t.Fatalf("%s: fingerprints %+v", rekey, instance)
				}
				seen[instance.Fingerprint] = true
				if metadata.Cosigner != nil && metadata.Cosigner.ComponentKeyType != arrangement.Cosigner {
					t.Fatalf("%s: cosigner type %s", rekey, metadata.Cosigner.ComponentKeyType)
				}
				if components, ok := b.provider.CosignerComponentKeyTypes(params); ok != (arrangement.Cosigner != "") || (ok && !slices.Equal(components, plainhost.CosignerKeyTypes)) {
					t.Fatalf("%s: cosigner components %v, %v", rekey, components, ok)
				}

				prepared, err := b.provider.PrepareRekeyList(testListKey, params)
				if err != nil {
					t.Fatalf("%s: %v", rekey, err)
				}
				teal, err := b.provider.GenerateTEAL(b.spendingKey, prepared)
				if err != nil {
					t.Fatalf("%s: GenerateTEAL() error = %v", rekey, err)
				}
				if !strings.Contains(teal, "plain host: rekey dispatch") || strings.Contains(teal, "txn Fee") {
					t.Fatalf("%s: not a plain1 program:\n%s", rekey, teal)
				}
				stored, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, prepared, make([]byte, 3_000))
				if err != nil {
					t.Fatalf("%s: %v", rekey, err)
				}
				if err := stored.Validate(); err != nil {
					t.Fatalf("%s: stored metadata: %v", rekey, err)
				}
				fingerprint, err := b.provider.StoredFingerprint(nil, stored)
				if err != nil || fingerprint != instance.Fingerprint {
					t.Fatalf("%s: stored fingerprint %s, %v; want %s", rekey, fingerprint, err, instance.Fingerprint)
				}
			}
		})
	}
}

func TestOverlayRequestsFailClosed(t *testing.T) {
	provider := bases(t)[0].provider
	withList := request(plainhost.RekeyOnlyThese)
	for _, tc := range []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"plus cosigned without a cosigner", map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyPlusCosigned, plainhost.ParameterRekeyTo: testRekeyTo()}, "without one it is rekey_authority=spending_key"},
		{"a misspelled overlay parameter", map[string]string{"rekey_authorty": plainhost.RekeyOnlyThese, "rekey_too": testRekeyTo()}, "unknown parameter"},
		{"no rekey authority", map[string]string{composeddsa.BoundedCosignerPublicKeyParameter: testCosigner}, "rekey_authority must be"},
		{"unknown rekey authority", map[string]string{plainhost.ParameterRekeyAuthority: "admin_key", composeddsa.BoundedCosignerPublicKeyParameter: testCosigner}, "rekey_authority"},
		{"a list without only_these", func() map[string]string {
			params := request(plainhost.RekeySpendingKey)
			params[plainhost.ParameterRekeyTo] = testRekeyTo()
			return params
		}(), "rekey_to needs"},
		{"only_these without a list", func() map[string]string {
			params := request(plainhost.RekeyOnlyThese)
			delete(params, plainhost.ParameterRekeyTo)
			return params
		}(), "needs the addresses"},
		{"an unresolved cosigner name", map[string]string{plainhost.ParameterCosigner: "corp", plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused}, "not resolved"},
		{"bounds without a recipient list", map[string]string{plainhost.ParameterSpendEffects: "pay", plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, composeddsa.BoundedCosignerPublicKeyParameter: testCosigner}, "recipients is required"},
		{"bounds without transfer kinds", map[string]string{plainhost.ParameterRecipientScope: plainhost.RecipientScopeAny, plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused}, "spend_effects is required"},
		{"a generated root", map[string]string{boundedmeta.RekeyListRootParameter: strings.Repeat("ab", 32), plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese, composeddsa.BoundedCosignerPublicKeyParameter: testCosigner, plainhost.ParameterRekeyTo: withList[plainhost.ParameterRekeyTo]}, "unknown parameter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := provider.ResolveInstance(tc.params); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ResolveInstance() error = %v, want %q", err, tc.want)
			}
			if err := provider.ValidateCreationParams(tc.params); err == nil {
				t.Fatal("ValidateCreationParams() accepted it")
			}
		})
	}
}

// The cosigner's key type rules: the default type is never recorded, another
// is, and a type is refused when it means nothing, is not one a plain host
// takes, or doesn't fit the key. Each holds for a bounds request too.
func TestCosignerKeyTypeRules(t *testing.T) {
	for _, b := range bases(t) {
		for _, bounded := range []bool{false, true} {
			withBounds := func(params map[string]string) map[string]string {
				if bounded {
					params[plainhost.ParameterSpendEffects] = "pay"
					params[plainhost.ParameterRecipients] = testAddress(1)
				}
				return params
			}
			name := fmt.Sprintf("%s bounded=%t", b.name, bounded)
			falcon := withBounds(request(plainhost.RekeySpendingKey))
			explicit := withBounds(request(plainhost.RekeySpendingKey))
			explicit[boundedmeta.CosignerKeyTypeParameter] = falconCosigner
			implicit, err := b.provider.ResolveInstance(falcon)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			named, err := b.provider.ResolveInstance(explicit)
			if err != nil {
				t.Fatalf("%s: explicit default: %v", name, err)
			}
			if _, recorded := named.Values[boundedmeta.CosignerKeyTypeParameter]; recorded || named.Fingerprint != implicit.Fingerprint {
				t.Fatalf("%s: an explicit default type is recorded or selects another program: %v", name, named.Values)
			}

			ed := withBounds(requestFor(plainhost.Arrangement{Rekey: plainhost.RekeySpendingKey, Cosigner: witness.Ed25519V1}))
			instance, err := b.provider.ResolveInstance(ed)
			if err != nil {
				t.Fatalf("%s: Ed25519 cosigner: %v", name, err)
			}
			if instance.Values[boundedmeta.CosignerKeyTypeParameter] != witness.Ed25519V1 || instance.Bounded.Cosigner.ComponentKeyType != witness.Ed25519V1 ||
				instance.Bounded.Cosigner.SignatureMaxSize != witness.Ed25519SignatureSize || instance.Fingerprint == implicit.Fingerprint {
				t.Fatalf("%s: Ed25519 cosigner = %v, %+v", name, instance.Values, instance.Bounded.Cosigner)
			}

			// A stored account is looked up by its recorded type, at its own
			// fee ceiling too: never as the default-cosigned program.
			if bounded {
				custom := maps.Clone(ed)
				custom[plainhost.ParameterMaxFee] = "20000"
				customFalcon := maps.Clone(falcon)
				customFalcon[plainhost.ParameterMaxFee] = "20000"
				edInstance, err := b.provider.ResolveInstance(custom)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				falconInstance, err := b.provider.ResolveInstance(customFalcon)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				stored, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, edInstance.Values, make([]byte, 3_000))
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				fingerprint, err := b.provider.StoredFingerprint(edInstance.Values, stored)
				if err != nil || fingerprint != edInstance.Fingerprint || fingerprint == falconInstance.Fingerprint {
					t.Fatalf("%s: stored fingerprint %s, %v; want %s, not the Falcon-cosigned %s", name, fingerprint, err, edInstance.Fingerprint, falconInstance.Fingerprint)
				}
			}

			for _, tc := range []struct {
				name string
				edit func(map[string]string)
				want string
			}{
				{"a type without a cosigner", func(p map[string]string) { delete(p, composeddsa.BoundedCosignerPublicKeyParameter) }, "needs a cosigner"},
				{"an unknown type", func(p map[string]string) { p[boundedmeta.CosignerKeyTypeParameter] = "aplane.witness-rsa.v1" }, "cosigner_key_type"},
				{"a Falcon key named Ed25519", func(p map[string]string) {
					p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerFor(falconCosigner)
				}, "a aplane.witness-ed25519.v1 key is 32"},
				{"an Ed25519 key with no type", func(p map[string]string) { delete(p, boundedmeta.CosignerKeyTypeParameter) }, "a aplane.witness-falcon1024.v1 key is 1793"},
			} {
				params := maps.Clone(ed)
				tc.edit(params)
				if _, err := b.provider.ResolveInstance(params); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("%s: %s: error = %v, want %q", name, tc.name, err, tc.want)
				}
				if err := b.provider.ValidateCreationParams(params); err == nil {
					t.Errorf("%s: %s: ValidateCreationParams() accepted it", name, tc.name)
				}
			}
		}
	}
}

// The boundary digest binds the cosigner and the rekey-to list, the two external
// authorities a review compares.
func TestBoundaryDigestBindsTheOverlays(t *testing.T) {
	provider := bases(t)[0].provider
	digest := func(params map[string]string) string {
		t.Helper()
		instance, err := provider.ResolveInstance(params)
		if err != nil {
			t.Fatal(err)
		}
		return instance.BoundaryDigest
	}
	base := request(plainhost.RekeyPlusCosigned)
	otherCosigner := request(plainhost.RekeyPlusCosigned)
	otherCosigner[composeddsa.BoundedCosignerPublicKeyParameter] = strings.Repeat("45", boundedmeta.DefaultCosignerPublicKeySize)
	var c types.Address
	c[0] = 0x33
	otherList := request(plainhost.RekeyPlusCosigned)
	otherList[plainhost.ParameterRekeyTo] = c.String()
	reordered := request(plainhost.RekeyPlusCosigned)
	parts := strings.Split(reordered[plainhost.ParameterRekeyTo], ",")
	reordered[plainhost.ParameterRekeyTo] = parts[1] + "," + parts[0]
	if digest(base) == digest(otherCosigner) || digest(base) == digest(otherList) {
		t.Fatal("the digest does not bind the cosigner and the list")
	}
	if digest(base) != digest(reordered) {
		t.Fatal("the digest depends on the list's order")
	}
	if digest(base) == digest(request(plainhost.RekeyOnlyThese)) {
		t.Fatal("the digest does not bind the arrangement")
	}
}

func TestStoredFingerprintRefusesAnotherContract(t *testing.T) {
	provider := bases(t)[0].provider
	if _, err := provider.StoredFingerprint(nil, &boundedmeta.Metadata{Contract: boundedmeta.Contract}); err == nil {
		t.Fatal("a bounded2 account resolved to a plain host arrangement")
	}
	if _, err := provider.StoredFingerprint(nil, nil); err == nil {
		t.Fatal("an account without metadata resolved to an arrangement")
	}
}

func TestBoundedOpcodeProfileIsSeparate(t *testing.T) {
	provider := bases(t)[0].provider
	plain, err := lsigprovider.ResolveOpcodeProfile(provider, false)
	if err != nil {
		t.Fatal(err)
	}
	bounded, err := lsigprovider.ResolveOpcodeProfile(provider, true)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Default == 0 || bounded.Spend == 0 || bounded.ListedRekey == 0 || bounded.Default != 0 {
		t.Fatalf("profiles plain %+v, bounded %+v", plain, bounded)
	}
}

// The grammar fingerprints hash configuration, so a rendering change must be
// declared by a revision; these goldens make that review unavoidable. They moved
// when the framework timelock left the grammar: the fingerprint is over every
// program in order, and 147 timelock shapes are no longer among them. No
// remaining program changed. They moved again when plain hosts took Ed25519
// cosigners: 88 programs joined (4 arrangements, 84 shapes), and no existing
// one changed, as TestArrangementGoldens and TestBoundsFingerprintGoldens show.
func TestPlainHostGrammarGoldens(t *testing.T) {
	want := map[string]string{
		"falcon":  "1:a9b67bca1c1432de249ec04c84275d28b1f7a7b8e84b75f2129ab023cfcef6d2",
		"ed25519": "1:692c4726da53ea27092e3c8dc0205e268201ecc418c24076ec237d95911689f2",
	}
	for _, b := range bases(t) {
		if got := b.provider.GrammarFingerprint(); got != want[b.name] {
			t.Errorf("%s grammar fingerprint = %s, want %s", b.name, got, want[b.name])
		}
	}
}

// These values freeze what each plain1 arrangement renders and the provenance it
// reports. A failure is a review obligation, not a fixture to refresh: a changed
// program means arrangementRendererRevision (listRendererRevision for the
// listed-rekey path, arrangementResolverRevision for request handling) must be
// raised for the arrangements it touches; a changed fingerprint with no intended
// behavior change would give existing accounts a provenance conflict.
func TestArrangementGoldens(t *testing.T) {
	// The default cosigner's arrangements, and those without one, hash as they
	// did before accounts could take another cosigner type: their programs and
	// fingerprints must not have moved. Each other type has its own values.
	type golden struct{ programs, fingerprints string }
	want := map[string]map[string]golden{
		"falcon": {
			"": {
				programs:     "644ffc120e9210f5b20eef7c0e0d2cac450027eb4c7e9025be5cffeba16a1c82",
				fingerprints: "808c62e885ed2b74ac925f679114e2d4dcff18b2fe7a628177dd1ece776aa10b",
			},
			witness.Ed25519V1: {
				programs:     "3f96db42c2a6ce3389ec653d74b7188dd12297d4f1a63e371d8e5e5338f4ca5e",
				fingerprints: "faa2fde48d2fe21eee16f58d29d53b39ad0a83a75885bdaaf8a859cc025071c1",
			},
		},
		"ed25519": {
			"": {
				programs:     "8a7dd8014f1e120630d9c2988b7fbdd7caff757b1bda9c4da414073bbc5d15b4",
				fingerprints: "543167f1c324a353b89f9d0d666a8bf0e987889ccab7afb2ae01d3064590f52e",
			},
			witness.Ed25519V1: {
				programs:     "d0a89a199b81fd0614c498713fe2eea1a7bebde66fbdc6dea0254c8790344b74",
				fingerprints: "ccf0ff44eef5dc71bb34e8fd600fe43c62d0cc2062d12f3985e5d73a3591a7f3",
			},
		},
	}
	for _, b := range bases(t) {
		programs, fingerprints := map[string]hash.Hash{}, map[string]hash.Hash{}
		for _, arrangement := range plainhost.Arrangements() {
			set, label := "", legacyArrangement(arrangement)
			if arrangement.Cosigner != "" && arrangement.Cosigner != boundedmeta.DefaultCosignerComponentKeyType {
				set, label = arrangement.Cosigner, fmt.Sprintf("%+v", arrangement)
			}
			if programs[set] == nil {
				programs[set], fingerprints[set] = sha256.New(), sha256.New()
			}
			params := requestFor(arrangement)
			teal, err := b.provider.GenerateTEAL(b.spendingKey, withRoot(t, b.provider, params))
			if err != nil {
				t.Fatalf("%s %+v: %v", b.name, arrangement, err)
			}
			resolved, err := b.provider.ResolveInstance(params)
			if err != nil {
				t.Fatalf("%s %+v: %v", b.name, arrangement, err)
			}
			if _, err := fmt.Fprintf(programs[set], "%s\n%d\n%s\n", label, len(teal), teal); err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(fingerprints[set], "%s\n%s\n%s\n", label, resolved.Fingerprint, resolved.BoundaryDigest); err != nil {
				t.Fatal(err)
			}
		}
		for set, wantSet := range want[b.name] {
			if programs[set] == nil {
				t.Errorf("%s: no arrangements for cosigner set %q", b.name, set)
				continue
			}
			got := golden{hex.EncodeToString(programs[set].Sum(nil)), hex.EncodeToString(fingerprints[set].Sum(nil))}
			if got != wantSet {
				t.Errorf("%s arrangements (cosigner set %q): programs %s, fingerprints %s; want %+v", b.name, set, got.programs, got.fingerprints, wantSet)
			}
		}
	}
}

// No parameters is the plain program; a parameter with an empty value is
// refused rather than read as absent, so a mistyped request never selects a
// weaker program.
func TestEmptyParametersAreRefused(t *testing.T) {
	provider := bases(t)[0].provider
	instance, err := provider.ResolveInstance(map[string]string{})
	if err != nil || instance.Bounded != nil {
		t.Fatalf("no parameters: instance = %+v, %v; want the plain program", instance, err)
	}
	if err := provider.ValidateCreationParams(map[string]string{"recipients": "X"}); err == nil {
		t.Fatal("the plain program accepted a parameter")
	}
	for _, name := range []string{plainhost.ParameterRekeyTo, plainhost.ParameterCosigner, composeddsa.BoundedCosignerPublicKeyParameter, plainhost.ParameterRekeyAuthority} {
		named := map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused, name: " "}
		if _, err := provider.ResolveInstance(named); err == nil || !strings.Contains(err.Error(), name+" is empty") {
			t.Fatalf("ResolveInstance(empty %s) error = %v", name, err)
		}
		if err := provider.ValidateCreationParams(named); err == nil {
			t.Fatalf("ValidateCreationParams accepted an empty %s", name)
		}
		if _, err := provider.GenerateTEAL(make([]byte, 32), named); err == nil {
			t.Fatalf("GenerateTEAL accepted an empty %s", name)
		}
	}
}

// Every entry point refuses a request that names only parameters no program
// reads, as validation does: deriving without validating first must not give
// the plain program, which is weaker than any account the caller meant.
func TestMisspelledParametersAreRefusedEverywhere(t *testing.T) {
	for _, b := range bases(t) {
		for _, params := range []map[string]string{{"rekey_authorty": plainhost.RekeyRefused}, {"cosigner_pubkey": testCosigner}} {
			if _, err := b.provider.GenerateTEAL(b.spendingKey, params); err == nil || !strings.Contains(err.Error(), "unknown parameter") {
				t.Fatalf("%s GenerateTEAL(%v) error = %v", b.name, params, err)
			}
			if _, _, err := b.provider.DeriveLsig(t.Context(), b.spendingKey, params); err == nil {
				t.Fatalf("%s DeriveLsig(%v) accepted it", b.name, params)
			}
			if _, err := b.provider.DeriveLsigWithSalt(t.Context(), b.spendingKey, params); err == nil {
				t.Fatalf("%s DeriveLsigWithSalt(%v) accepted it", b.name, params)
			}
			if _, err := b.provider.PrepareRekeyList(testListKey, params); err == nil {
				t.Fatalf("%s PrepareRekeyList(%v) accepted it", b.name, params)
			}
			if _, err := b.provider.BuildBoundedAuthorizationMetadata(b.spendingKey, params, nil); err == nil {
				t.Fatalf("%s BuildBoundedAuthorizationMetadata(%v) accepted it", b.name, params)
			}
		}
		// No parameters is still the plain program.
		if _, err := b.provider.GenerateTEAL(b.spendingKey, nil); err != nil {
			t.Fatalf("%s plain program: %v", b.name, err)
		}
	}
}

// Building every shape costs more than a process start should, so a host builds
// them on first use, and a request without bounds doesn't need them.
func TestShapesAreBuiltOnFirstUse(t *testing.T) {
	for _, b := range bases(t) {
		if b.provider.ShapesBuiltForTest() {
			t.Fatalf("%s built its shapes at registration", b.name)
		}
		if err := b.provider.ValidateCreationParams(request(plainhost.RekeyRefused)); err != nil || b.provider.ShapesBuiltForTest() {
			t.Fatalf("%s: an overlays-only check built the shapes (err %v)", b.name, err)
		}
		if b.provider.GrammarFingerprint() == "" || !b.provider.ShapesBuiltForTest() {
			t.Fatalf("%s: the grammar fingerprint did not build the shapes", b.name)
		}
	}
}
