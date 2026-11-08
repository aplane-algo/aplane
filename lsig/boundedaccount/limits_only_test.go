// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package boundedaccount

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/txeffects"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

// limitsOnlyShapes are the appended shapes. Index order is frozen by the goldens.
func limitsOnlyShapes(t *testing.T) []Shape {
	t.Helper()
	shapes := Shapes()[112:]
	if len(shapes) != 35 {
		t.Fatalf("%d limits-only shapes, want 35", len(shapes))
	}
	return shapes
}

// listedTwin is the inline-allowlist shape with the same transfer kinds and
// authorities, so the two programs differ only in what Layer 3 renders.
func listedTwin(shape Shape) Shape {
	shape.AnyRecipient = false
	shape.Encoding = EncodingInline
	return shape
}

func TestLimitsOnlyShapeResolvesFromAnExplicitScope(t *testing.T) {
	provider := newTestProvider(t)
	instance, err := provider.ResolveInstance(map[string]string{
		ParameterSpendEffects:   "pay",
		ParameterRekeyAuthority: RekeySpendingKey,
		ParameterRecipientScope: RecipientScopeAny,
	})
	if err != nil {
		t.Fatal(err)
	}
	if instance.Bounded.Layer3Policy != boundedmeta.Layer3PolicyNone {
		t.Fatalf("policy = %s", instance.Bounded.Layer3Policy)
	}
	if instance.Bounded.MaxFee != MaxFee || !slices.Equal(instance.Bounded.SpendEffects, []string{"pay"}) {
		t.Fatalf("limits = %d %v", instance.Bounded.MaxFee, instance.Bounded.SpendEffects)
	}
	if len(instance.Bounded.DerivedArgs) != 0 || len(instance.Bounded.RuntimeArgs) != 0 {
		t.Fatal("limits-only shape declares Layer 3 arguments")
	}
	if _, present := instance.Values[ParameterRecipients]; present || instance.Values[ParameterRecipientScope] != RecipientScopeAny {
		t.Fatalf("values = %v", instance.Values)
	}
	if len(instance.Parameters) != 0 {
		t.Fatalf("the composer declares %v, want no behavior parameters", instance.Parameters)
	}
	if instance.Bounded.Contained() {
		t.Fatal("a limits-only account reports itself contained")
	}
	stored, err := provider.StoredFingerprint(nil, instance.Bounded)
	if err != nil || stored != instance.Fingerprint {
		t.Fatalf("stored fingerprint %s, %v; instance %s", stored, err, instance.Fingerprint)
	}
	again, err := provider.ResolveInstance(instance.Values)
	if err != nil || again.Fingerprint != instance.Fingerprint || again.BoundaryDigest != instance.BoundaryDigest {
		t.Fatalf("persisted values resolved to another shape: %v", err)
	}
}

// Leaving the list out must never be read as asking for no list.
func TestLimitsOnlyRequestsFailClosed(t *testing.T) {
	provider := newTestProvider(t)
	base := func() map[string]string {
		return map[string]string{
			ParameterSpendEffects:   "pay,axfer,asset_opt_in",
			ParameterRekeyAuthority: RekeySpendingKey,
			ParameterRecipientScope: RecipientScopeAny,
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"no scope and no list", func(p map[string]string) { delete(p, ParameterRecipientScope) }, "recipients is required"},
		{"listed scope and no list", func(p map[string]string) { p[ParameterRecipientScope] = RecipientScopeListed }, "recipients is required"},
		{"listed scope with only a timelock", func(p map[string]string) {
			p[ParameterRecipientScope] = RecipientScopeListed
			p[ParameterRekeyAuthority] = RekeyOnlyThese
			p[ParameterRekeyTo] = testRekeyTo
			p[ParameterUnlockRound] = "5"
		}, "recipients is required"},
		{"empty scope", func(p map[string]string) { p[ParameterRecipientScope] = "" }, "recipient_scope must be"},
		{"unknown scope", func(p map[string]string) { p[ParameterRecipientScope] = "open" }, "recipient_scope must be"},
		{"any with recipients", func(p map[string]string) { p[ParameterRecipients] = testRecipients(1) }, "takes no recipients"},
		{"any with an empty list", func(p map[string]string) { p[ParameterRecipients] = "" }, "takes no recipients"},
		{"any with an encoding", func(p map[string]string) { p[ParameterListEncoding] = EncodingInline }, "no list to encode"},
		{"any with a timelock", func(p map[string]string) {
			p[ParameterRekeyAuthority] = RekeyOnlyThese
			p[ParameterRekeyTo] = testRekeyTo
			p[ParameterUnlockRound] = "5"
		}, "does not combine"},
		{"any refusing every rekey", func(p map[string]string) {
			p[ParameterRekeyAuthority] = RekeyRefused
			p[composeddsa.BoundedCosignerPublicKeyParameter] = testCosignerKey
		}, "rekey_authority=refused is not offered"},
		{"any with only_these and no rekey-to list", func(p map[string]string) { p[ParameterRekeyAuthority] = RekeyOnlyThese },
			"rekey_authority=only_these needs the addresses"},
		{"any with plus_cosigned and no cosigner", func(p map[string]string) {
			p[ParameterRekeyAuthority] = RekeyPlusCosigned
			p[ParameterRekeyTo] = testRekeyTo
		}, "rekey_authority=plus_cosigned needs a cosigner"},
	} {
		t.Run(test.name, func(t *testing.T) {
			params := base()
			test.mutate(params)
			if _, err := provider.ResolveInstance(params); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ResolveInstance error = %v, want %q", err, test.want)
			}
		})
	}
}

// The new shapes must not share provenance with any earlier shape, or a stored
// allowlist account could be reported as matching a program with no list.
func TestLimitsOnlyFingerprintsAreDistinct(t *testing.T) {
	provider := newTestProvider(t)
	earlier := make(map[string]string)
	for _, definition := range provider.ordered[:112] {
		earlier[definition.fingerprint] = definition.shape.Descriptor()
	}
	for _, shape := range limitsOnlyShapes(t) {
		definition := provider.byShape[shape.Descriptor()]
		if other, ok := earlier[definition.fingerprint]; ok {
			t.Fatalf("%s shares a fingerprint with %s", shape.Descriptor(), other)
		}
		earlier[definition.fingerprint] = shape.Descriptor()

		limited, err := provider.ResolveInstance(requestFor(shape, ""))
		if err != nil {
			t.Fatal(err)
		}
		listed, err := provider.ResolveInstance(requestFor(listedTwin(shape), testRecipients(1)))
		if err != nil {
			t.Fatal(err)
		}
		if limited.BoundaryDigest == listed.BoundaryDigest {
			t.Fatalf("%s has its allowlist twin's boundary digest", shape.Descriptor())
		}
		limitedProfile := canonicalProfile(t, provider, shape)
		listedProfile := canonicalProfile(t, provider, listedTwin(shape))
		// The only difference is field(layer3_policy): "none" against
		// "fixed_allowlist", which differ in length, so the encodings cannot meet.
		want := strings.Replace(hex.EncodeToString(listedProfile),
			hex.EncodeToString(boundedmeta.AppendField(nil, []byte(boundedmeta.Layer3PolicyFixedAllowlist))),
			hex.EncodeToString(boundedmeta.AppendField(nil, []byte(boundedmeta.Layer3PolicyNone))), 1)
		if hex.EncodeToString(limitedProfile) != want {
			t.Fatalf("%s profile differs from its twin in more than the policy", shape.Descriptor())
		}
	}
}

func canonicalProfile(t *testing.T, provider *Provider, shape Shape) []byte {
	t.Helper()
	composer := provider.byShape[shape.Descriptor()].composer
	encoded, err := composeddsa.CanonicalBoundedProfile(composer.BoundedAuthorizationProfile(), composer.BoundedAuthorizationMetadata())
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// After the envelope and the spending signature, a limits-only spend goes straight
// to the accept block. Its program is its allowlist twin with Layer 3 cut out, so
// the fee ceiling, effect gate, close fields and rekey path are the shipped ones.
func TestLimitsOnlyProgramIsTheEnvelopeAlone(t *testing.T) {
	provider := newTestProvider(t)
	spending, cosigner := generalGoldenKeys()
	render := func(shape Shape, recipients string) string {
		t.Helper()
		params := requestFor(shape, recipients)
		if shape.Cosigner {
			params[composeddsa.BoundedCosignerPublicKeyParameter] = cosigner
		}
		teal, err := provider.GenerateTEAL(spending, withRoot(t, provider, params))
		if err != nil {
			t.Fatal(err)
		}
		return teal
	}
	const (
		feeCeiling = "txn Fee\npushint 10000\n<=\nassert\n"
		noLayer3   = "// === no framework Layer 3: the envelope bounds every spend ===\n"
		layer3Done = "__aplane_bounded1_layer3_done:\n"
	)
	labels := map[txeffects.SpendEffect]string{
		txeffects.SpendEffectPay:        "__aplane_bounded1_effect_pay:\n",
		txeffects.SpendEffectAssetOptIn: "__aplane_bounded1_effect_asset_opt_in:\n",
	}
	for _, shape := range limitsOnlyShapes(t) {
		t.Run(shape.Descriptor(), func(t *testing.T) {
			teal := render(shape, "")
			if !strings.Contains(teal, "// === bounded transaction envelope ===\n"+feeCeiling) {
				t.Fatal("program has no fee ceiling")
			}
			for effect, label := range labels {
				decision := "err\n"
				if slices.Contains(shape.Spend, effect) {
					decision = "b __aplane_bounded1_spend\n"
				}
				if !strings.Contains(teal, label+decision) {
					t.Fatalf("%s decision is not %q", effect, decision)
				}
			}
			axfer := "__aplane_bounded1_effect_axfer:\ntxn AssetAmount\npushint 0\n==\ntxn AssetReceiver\ntxn Sender\n==\n&&\nbnz __aplane_bounded1_effect_asset_opt_in\n"
			axferDecision := "err\n"
			if slices.Contains(shape.Spend, txeffects.SpendEffectAxfer) {
				axferDecision = "b __aplane_bounded1_spend\n"
			}
			if !strings.Contains(teal, axfer+axferDecision) {
				t.Fatalf("axfer decision is not %q", axferDecision)
			}
			if strings.Contains(teal, "framework-owned") || strings.Contains(teal, "recipient_allowed") {
				t.Fatal("program renders a recipient or timelock check")
			}
			tail := noLayer3 + "\n\nb __aplane_bounded1_accept\n\n__aplane_bounded1_accept:\npushint 1\nreturn\n"
			if !strings.HasSuffix(teal, tail) {
				t.Fatalf("program does not accept straight after the envelope:\n%s", teal[len(teal)-300:])
			}
			if !shape.Cosigner && !strings.Contains(teal, "__aplane_bounded1_spend:\n"+tail) {
				t.Fatal("spend boundary is not followed by the accept block")
			}
			// bounded2 embeds no profile digest in the program, so every twin pair,
			// cosigned or not, differs in Layer 3 alone.
			listed := render(listedTwin(shape), testAddress(1))
			start := strings.Index(listed, "// === framework-owned fixed allowlist ===\n")
			end := strings.Index(listed, layer3Done)
			if start < 0 || end < start {
				t.Fatal("allowlist twin has no Layer 3 block")
			}
			cut := listed[:start] + noLayer3 + listed[end+len(layer3Done):]
			if cut != teal {
				t.Fatalf("program is not the allowlist twin minus Layer 3:\n%s\n---\n%s", teal, cut)
			}
		})
	}
}

func TestLimitsOnlyBoundaryFile(t *testing.T) {
	provider := newTestProvider(t)
	const head = "schema: aplane.boundary.v1\nspend: [pay, axfer]\nrekey: {authority: spending_key}\n"
	file, err := boundary.ParseFile([]byte(head + "recipient_scope: any\n"))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := provider.ResolveInstance(file.CreationParameters())
	if err != nil {
		t.Fatal(err)
	}
	direct, err := provider.ResolveInstance(requestFor(Shape{Spend: spendEffectOrder[:2], Rekey: RekeySpendingKey, AnyRecipient: true}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if instance.Fingerprint != direct.Fingerprint || instance.BoundaryDigest != direct.BoundaryDigest {
		t.Fatal("the file and direct parameters resolved differently")
	}
	path := filepath.Join(t.TempDir(), "boundary.yaml")
	if err := os.WriteFile(path, []byte(head+"recipient_scope: any\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := boundary.LoadFile(path); err != nil || loaded[ParameterRecipientScope] != RecipientScopeAny {
		t.Fatalf("LoadFile = %v, %v", loaded, err)
	}
	for body, want := range map[string]string{
		head: "recipients is required unless",
		head + "recipient_scope: any\nrecipients: [" + testAddress(1) + "]\n": "takes no recipients",
		head + "recipient_scope: any\nrecipients: []\n":                       "takes no recipients",
		head + "recipient_scope: any\nunlock_round: 5\n":                      "does not combine with unlock_round",
		head + "recipient_scope: any\nencoding: inline\n":                     "encoding needs a recipient list",
		head + "recipient_scope: anyone\n":                                    "recipient_scope must be",
		head + "recipient_scope: \"\"\n":                                      "recipient_scope must be",
		head + "recipient_scope: listed\n":                                    "recipient_scope listed needs recipients",
		head + "recipient_scope: listed\nunlock_round: 5\n":                   "recipient_scope listed needs recipients",
	} {
		if _, err := boundary.ParseFile([]byte(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseFile(%q) error = %v, want %q", body, err, want)
		}
	}
}
