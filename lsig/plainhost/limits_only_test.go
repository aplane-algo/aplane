// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package plainhost_test

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
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// limitsShapesStart is where the limits-only shapes begin; they are the last
// family, every arrangement with every transfer subset.
const limitsShapesStart = 245

// limitsOnlyShapes are the last family. Index order is frozen by the goldens.
func limitsOnlyShapes(t *testing.T) []plainhost.Shape {
	t.Helper()
	shapes := plainhost.Shapes()[limitsShapesStart:]
	if len(shapes) != 49 {
		t.Fatalf("%d limits-only shapes, want 49", len(shapes))
	}
	for _, shape := range shapes {
		if !shape.AnyRecipient {
			t.Fatalf("%s is in the limits-only family", shape.Descriptor())
		}
	}
	return shapes
}

// listedTwin is the inline-allowlist shape with the same transfer kinds and
// authorities, so the two programs differ only in what Layer 3 renders.
func listedTwin(shape plainhost.Shape) plainhost.Shape {
	shape.AnyRecipient = false
	shape.Encoding = plainhost.EncodingInline
	return shape
}

func TestLimitsOnlyShapeResolvesFromAnExplicitScope(t *testing.T) {
	for _, b := range bases(t) {
		instance, err := b.provider.ResolveInstance(map[string]string{
			plainhost.ParameterSpendEffects:   "pay",
			plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
			plainhost.ParameterRecipientScope: plainhost.RecipientScopeAny,
		})
		if err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		bounded := instance.Bounded
		if bounded.Contract != boundedmeta.Contract || bounded.Layer3Policy != boundedmeta.Layer3PolicyNone {
			t.Fatalf("%s: contract %s, policy %s", b.name, bounded.Contract, bounded.Layer3Policy)
		}
		if bounded.MaxFee == nil || *bounded.MaxFee != plainhost.MaxFee || !slices.Equal(bounded.SpendEffects, []string{"pay"}) {
			t.Fatalf("%s: limits = %v %v", b.name, bounded.MaxFee, bounded.SpendEffects)
		}
		if len(bounded.DerivedArgs) != 0 || len(bounded.RuntimeArgs) != 0 {
			t.Fatalf("%s: limits-only shape declares Layer 3 arguments", b.name)
		}
		if _, present := instance.Values[plainhost.ParameterRecipients]; present || instance.Values[plainhost.ParameterRecipientScope] != plainhost.RecipientScopeAny {
			t.Fatalf("%s: values = %v", b.name, instance.Values)
		}
		if len(instance.Parameters) != 0 {
			t.Fatalf("%s: the composer declares %v, want no behavior parameters", b.name, instance.Parameters)
		}
		if bounded.Contained() {
			t.Fatalf("%s: a limits-only account reports itself contained", b.name)
		}
		stored, err := b.provider.StoredFingerprint(nil, bounded)
		if err != nil || stored != instance.Fingerprint {
			t.Fatalf("%s: stored fingerprint %s, %v; instance %s", b.name, stored, err, instance.Fingerprint)
		}
		again, err := b.provider.ResolveInstance(instance.Values)
		if err != nil || again.Fingerprint != instance.Fingerprint || again.BoundaryDigest != instance.BoundaryDigest {
			t.Fatalf("%s: persisted values resolved to another shape: %v", b.name, err)
		}
	}
}

// Leaving the list out must never be read as asking for no list.
func TestLimitsOnlyRequestsFailClosed(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			plainhost.ParameterSpendEffects:   "pay,axfer,asset_opt_in",
			plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
			plainhost.ParameterRecipientScope: plainhost.RecipientScopeAny,
		}
	}
	tests := []struct {
		name   string
		mutate func(map[string]string)
		want   string
	}{
		{"no scope and no list", func(p map[string]string) { delete(p, plainhost.ParameterRecipientScope) }, "recipients is required"},
		// An empty scope is unset, which is listed: it is not any.
		{"empty scope", func(p map[string]string) { p[plainhost.ParameterRecipientScope] = "" }, "recipient_scope is empty"},
		{"listed scope and no list", func(p map[string]string) { p[plainhost.ParameterRecipientScope] = plainhost.RecipientScopeListed }, "recipients is required"},
		{"listed scope with only a timelock", func(p map[string]string) {
			p[plainhost.ParameterRecipientScope] = plainhost.RecipientScopeListed
			p[plainhost.ParameterUnlockRound] = "5"
		}, "recipients is required"},
		{"unknown scope", func(p map[string]string) { p[plainhost.ParameterRecipientScope] = "open" }, "recipient_scope must be"},
		{"any with recipients", func(p map[string]string) { p[plainhost.ParameterRecipients] = testRecipients(1) }, "takes no recipients"},
		{"any with an encoding", func(p map[string]string) { p[plainhost.ParameterListEncoding] = plainhost.EncodingInline }, "no list to encode"},
		// A timelock already admits any recipient once it unlocks, whatever the
		// rekey setting beside it.
		{"any with a timelock", func(p map[string]string) { p[plainhost.ParameterUnlockRound] = "5" }, "does not combine"},
		{"any with a timelock and a rekey-to list", func(p map[string]string) {
			p[plainhost.ParameterRekeyAuthority] = plainhost.RekeyOnlyThese
			p[plainhost.ParameterRekeyTo] = listedRekeyTo
			p[plainhost.ParameterUnlockRound] = "5"
		}, "does not combine"},
		{"any with a zero unlock round", func(p map[string]string) { p[plainhost.ParameterUnlockRound] = "0" }, "must be positive"},
		{"any with only_these and no rekey-to list", func(p map[string]string) { p[plainhost.ParameterRekeyAuthority] = plainhost.RekeyOnlyThese },
			"rekey_authority=only_these needs the addresses"},
		{"any with plus_cosigned and no cosigner", func(p map[string]string) {
			p[plainhost.ParameterRekeyAuthority] = plainhost.RekeyPlusCosigned
			p[plainhost.ParameterRekeyTo] = listedRekeyTo
		}, "rekey_authority=plus_cosigned needs a cosigner"},
	}
	for _, b := range bases(t) {
		for _, test := range tests {
			t.Run(b.name+"/"+test.name, func(t *testing.T) {
				params := base()
				test.mutate(params)
				if _, err := b.provider.ResolveInstance(params); err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("ResolveInstance error = %v, want %q", err, test.want)
				}
			})
		}
	}
}

// Limits-only shapes must not share provenance with any other program, or a
// stored allowlist account could be reported as matching a program with no list,
// and a limits-only account as its plain1 arrangement, which has no fee ceiling.
func TestLimitsOnlyFingerprintsAreDistinct(t *testing.T) {
	for _, b := range bases(t) {
		t.Run(b.name, func(t *testing.T) {
			descriptors, fingerprints := b.provider.ProgramsForTest()
			earlier := make(map[string]string)
			arrangements := len(plainhost.Arrangements())
			for i := range arrangements + limitsShapesStart {
				earlier[fingerprints[i]] = descriptors[i]
			}
			for _, shape := range limitsOnlyShapes(t) {
				fingerprint := b.provider.ShapeFingerprintForTest(shape)
				if other, ok := earlier[fingerprint]; ok {
					t.Fatalf("%s shares a fingerprint with %s", shape.Descriptor(), other)
				}
				earlier[fingerprint] = shape.Descriptor()

				limited := resolveShape(t, b.provider, shape, "")
				listed := resolveShape(t, b.provider, listedTwin(shape), testRecipients(1))
				if limited.BoundaryDigest == listed.BoundaryDigest {
					t.Fatalf("%s has its allowlist twin's boundary digest", shape.Descriptor())
				}
				arrangement, err := b.provider.ResolveInstance(requestFor(plainhost.Arrangement{Rekey: shape.Rekey, Cosigner: shape.Cosigner}))
				if err != nil {
					t.Fatal(err)
				}
				if arrangement.Bounded.Contract != boundedmeta.PlainContract || limited.BoundaryDigest == arrangement.BoundaryDigest {
					t.Fatalf("%s has its plain1 arrangement's boundary digest", shape.Descriptor())
				}
				limitedProfile := canonicalProfile(t, b.provider, shape)
				listedProfile := canonicalProfile(t, b.provider, listedTwin(shape))
				// The only difference is field(layer3_policy): "none" against
				// "fixed_allowlist", which differ in length, so the encodings cannot meet.
				want := strings.Replace(hex.EncodeToString(listedProfile),
					hex.EncodeToString(boundedmeta.AppendField(nil, []byte(boundedmeta.Layer3PolicyFixedAllowlist))),
					hex.EncodeToString(boundedmeta.AppendField(nil, []byte(boundedmeta.Layer3PolicyNone))), 1)
				if hex.EncodeToString(limitedProfile) != want {
					t.Fatalf("%s profile differs from its twin in more than the policy", shape.Descriptor())
				}
			}
		})
	}
}

func canonicalProfile(t *testing.T, provider *plainhost.Provider, shape plainhost.Shape) []byte {
	t.Helper()
	composer := provider.ShapeComposerForTest(shape)
	if composer == nil {
		t.Fatalf("no shape %s", shape.Descriptor())
	}
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
	const (
		feeCeiling = "txn Fee\npushint 10000\n<=\nassert\n"
		noLayer3   = "// === no framework Layer 3: the envelope bounds every spend ===\n"
		layer3Done = "__aplane_bounded1_layer3_done:\n"
	)
	labels := map[txeffects.SpendEffect]string{
		txeffects.SpendEffectPay:        "__aplane_bounded1_effect_pay:\n",
		txeffects.SpendEffectAssetOptIn: "__aplane_bounded1_effect_asset_opt_in:\n",
	}
	for _, b := range bases(t) {
		render := func(t *testing.T, shape plainhost.Shape, recipients string) string {
			t.Helper()
			teal, err := b.provider.GenerateTEAL(b.spendingKey, withRoot(t, b.provider, shapeRequest(shape, recipients)))
			if err != nil {
				t.Fatal(err)
			}
			return teal
		}
		for _, shape := range limitsOnlyShapes(t) {
			t.Run(b.name+"/"+shape.Descriptor(), func(t *testing.T) {
				teal := render(t, shape, "")
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
				listed := render(t, listedTwin(shape), testAddress(1))
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
}

func TestLimitsOnlyBoundaryFile(t *testing.T) {
	provider := falconHost(t)
	const head = "schema: aplane.boundary.v1\nspend: [pay, axfer]\nrekey: {authority: spending_key}\n"
	file, err := boundary.ParseFile([]byte(head + "recipient_scope: any\n"))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := provider.ResolveInstance(file.CreationParameters())
	if err != nil {
		t.Fatal(err)
	}
	direct := resolveShape(t, provider, plainhost.Shape{Spend: everyTransfer[:2], Rekey: plainhost.RekeySpendingKey, AnyRecipient: true}, "")
	if instance.Fingerprint != direct.Fingerprint || instance.BoundaryDigest != direct.BoundaryDigest {
		t.Fatal("the file and direct parameters resolved differently")
	}
	path := filepath.Join(t.TempDir(), "boundary.yaml")
	if err := os.WriteFile(path, []byte(head+"recipient_scope: any\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := boundary.LoadFile(path); err != nil || loaded[plainhost.ParameterRecipientScope] != plainhost.RecipientScopeAny {
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
