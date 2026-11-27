// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"bytes"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundary"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/witness"
)

const plainHostKeyType = "aplane.falcon1024.v1"

func setupPlainHost(t *testing.T) (*productruntime.Runtime, Service, []byte) {
	t.Helper()
	configureFalconCompileMock(t)
	ir := setupProductRuntime(t)
	if err := keytypestate.Put(ir.KeyPaths(), keytypestate.Record{
		KeyType: plainHostKeyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled,
	}); err != nil {
		t.Fatal(err)
	}
	publicKey, _ := importPrepareReference(t, ir, prepareTestReference, 0x63)
	return ir, Service{Runtime: ir}, publicKey
}

// A plain host creates what the request asks for: the plain program with no
// parameters, or plain1 with any overlays, a cosigner included or not.
func TestPlainHostCreatesWhatTheRequestAsks(t *testing.T) {
	ir, service, _ := setupPlainHost(t)
	plain, err := service.GenerateKey(context.Background(), plainHostKeyType, nil)
	if err != nil {
		t.Fatalf("GenerateKey(no parameters) error = %#v", err)
	}
	if summary := ir.KeyStore().GetSigningSummary()[plain.Address]; summary.Host != nil {
		t.Fatalf("the plain program has an overlay contract: %+v", summary.Host)
	}
	prepared, prepareErr := service.PrepareGenerateKey(plainHostKeyType, map[string]string{
		boundary.ParameterRekeyAuthority: boundary.RekeyOnlyThese,
		boundary.ParameterRekeyTo:        listedTarget.String(),
	})
	if prepareErr != nil {
		t.Fatalf("PrepareGenerateKey(only these, no cosigner) error = %#v", prepareErr)
	}
	if bounded := prepared.Host; bounded == nil || bounded.Contract != hostmeta.PlainContract || bounded.Cosigner != nil || bounded.RekeyList == nil {
		t.Fatalf("prepared contract = %+v", bounded)
	}
	listed, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest})
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	metadata := ir.KeyStore().GetSigningSummary()[listed.Address].Host
	if metadata == nil || metadata.Contract != hostmeta.PlainContract || metadata.Cosigner != nil || metadata.RekeyList == nil {
		t.Fatalf("stored contract = %+v", metadata)
	}
}

// A fee limit below what the account's own transactions cost is the user's
// choice: preparation succeeds and carries the provider's warning to the
// review, and generation creates the account with that limit. The default
// limit, named or not, and a limit above it warn of nothing.
func TestPrepareCarriesTheFeeLimitWarning(t *testing.T) {
	ir, service, _ := setupPlainHost(t)
	request := func(maxFee string) map[string]string {
		params := map[string]string{
			boundary.ParameterSpendEffects:   "pay",
			boundary.ParameterRecipientScope: boundary.RecipientScopeAny,
			boundary.ParameterRekeyAuthority: boundary.RekeySpendingKey,
		}
		if maxFee != "" {
			params[boundary.ParameterMaxFee] = maxFee
		}
		return params
	}
	unnamed, prepareErr := service.PrepareGenerateKey(plainHostKeyType, request(""))
	if prepareErr != nil {
		t.Fatalf("PrepareGenerateKey(no max_fee) error = %#v", prepareErr)
	}
	for _, test := range []struct {
		name, maxFee string
		want         uint64
		warns        bool
	}{
		{"no limit named", "", 10_000, false},
		{"the default named", "10000", 10_000, false},
		{"above the old cap", "20000", 20_000, false},
		{"zero", "0", 0, true},
		{"one minimum fee", "1000", 1_000, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, prepareErr := service.PrepareGenerateKey(plainHostKeyType, request(test.maxFee))
			if prepareErr != nil {
				t.Fatalf("PrepareGenerateKey() error = %#v", prepareErr)
			}
			if prepared.Host == nil || prepared.Host.Contract != hostmeta.BoundedContract || prepared.Host.FeeCeiling() == nil || *prepared.Host.FeeCeiling() != test.want {
				t.Fatalf("prepared contract = %+v", prepared.Host)
			}
			// Only a limit other than the default is a parameter of the account, and
			// the default is the account that names none.
			persisted, present := prepared.Parameters[boundary.ParameterMaxFee]
			if test.want == boundary.DefaultMaxFee {
				if present || prepared.Fingerprint != unnamed.Fingerprint || prepared.BoundaryDigest != unnamed.BoundaryDigest {
					t.Fatalf("the default limit prepared another account: max_fee=%q present=%v", persisted, present)
				}
			} else if persisted != test.maxFee || prepared.Fingerprint == unnamed.Fingerprint || prepared.BoundaryDigest == unnamed.BoundaryDigest {
				t.Fatalf("a limit of %s prepared max_fee=%q, fingerprint %s", test.maxFee, persisted, prepared.Fingerprint)
			}
			if prepared.ReviewFingerprint != unnamed.ReviewFingerprint {
				t.Fatalf("the limit changed the review fingerprint: %s != %s", prepared.ReviewFingerprint, unnamed.ReviewFingerprint)
			}
			projected := ProjectPrepareGenerateIPC(prepared, nil)
			if !test.warns {
				if len(prepared.Warnings) != 0 || len(projected.Warnings) != 0 {
					t.Fatalf("Warnings = %q", prepared.Warnings)
				}
				// Generation, reviewed or not, has nothing to say either.
				generated, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, prepared.Parameters,
					ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest})
				if err != nil || len(generated.Warnings) != 0 {
					t.Fatalf("GenerateReviewedKey() error = %#v, warnings = %q; want none", err, warningsOf(generated))
				}
				unreviewed, err := service.GenerateKey(context.Background(), plainHostKeyType, request(test.maxFee))
				if err != nil || len(unreviewed.Warnings) != 0 {
					t.Fatalf("GenerateKey() error = %#v, warnings = %q; want none", err, warningsOf(unreviewed))
				}
				return
			}
			want := "Fee limit " + test.maxFee + " is too low to pay alone. A transaction on its own costs more: spend (at least "
			if len(prepared.Warnings) != 1 || !strings.HasPrefix(prepared.Warnings[0], want) {
				t.Fatalf("Warnings = %q, want one starting %q", prepared.Warnings, want)
			}
			if !projected.Success || len(projected.Warnings) != 1 || projected.Warnings[0] != prepared.Warnings[0] ||
				projected.Host == nil || projected.Host.Bounds == nil || projected.Host.Bounds.MaxFee != test.want {
				t.Fatalf("projected = %+v", projected)
			}

			// The warning refuses nothing: the reviewed account is generated, with
			// the limit it was reviewed with.
			generated, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, prepared.Parameters,
				ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest})
			if err != nil {
				t.Fatalf("GenerateReviewedKey() error = %#v", err)
			}
			metadata := ir.KeyStore().GetSigningSummary()[generated.Address].Host
			if metadata == nil || metadata.FeeCeiling() == nil || *metadata.FeeCeiling() != test.want {
				t.Fatalf("stored contract = %+v", metadata)
			}
			if generated.Parameters[boundary.ParameterMaxFee] != test.maxFee {
				t.Fatalf("generated parameters = %v", generated.Parameters)
			}
			// Generation carries the same advice the review showed, and so does a
			// generation nobody reviewed, which has no other place to show it.
			if !slices.Equal(generated.Warnings, prepared.Warnings) {
				t.Fatalf("generated Warnings = %q, want %q", generated.Warnings, prepared.Warnings)
			}
			unreviewed, err := service.GenerateKey(context.Background(), plainHostKeyType, request(test.maxFee))
			if err != nil {
				t.Fatalf("GenerateKey() error = %#v", err)
			}
			if !slices.Equal(unreviewed.Warnings, prepared.Warnings) {
				t.Fatalf("unreviewed generation Warnings = %q, want %q", unreviewed.Warnings, prepared.Warnings)
			}
		})
	}
	// The preparation's warnings are its own: changing them changes no later one.
	first, prepareErr := service.PrepareGenerateKey(plainHostKeyType, request("0"))
	if prepareErr != nil || len(first.Warnings) != 1 {
		t.Fatalf("PrepareGenerateKey(max_fee=0) = %+v, %#v", first, prepareErr)
	}
	kept := first.Warnings[0]
	first.Warnings[0] = "changed"
	if second, prepareErr := service.PrepareGenerateKey(plainHostKeyType, request("0")); prepareErr != nil || len(second.Warnings) != 1 || second.Warnings[0] != kept {
		t.Fatalf("a second preparation = %+v, %#v", second, prepareErr)
	}
	// An account with no bounds, and the plain program, have no limit to warn of.
	for _, params := range []map[string]string{nil, {boundary.ParameterRekeyAuthority: boundary.RekeyRefused}} {
		generated, err := service.GenerateKey(context.Background(), plainHostKeyType, params)
		if err != nil || len(generated.Warnings) != 0 {
			t.Fatalf("GenerateKey(%v) error = %#v, warnings = %q; want none", params, err, warningsOf(generated))
		}
	}
	// What the provider refuses is still refused, with no warning in its place.
	for _, bad := range []string{"abc", "-1", "1.5", "010", "18446744073709551616"} {
		if _, err := service.PrepareGenerateKey(plainHostKeyType, request(bad)); err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, "max_fee must be a whole number") {
			t.Fatalf("PrepareGenerateKey(max_fee=%s) error = %#v", bad, err)
		}
		if _, err := service.GenerateKey(context.Background(), plainHostKeyType, request(bad)); err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, "max_fee must be a whole number") {
			t.Fatalf("GenerateKey(max_fee=%s) error = %#v", bad, err)
		}
	}
	// The largest limit is the largest whole number every client reads exactly.
	for _, bad := range []string{"9007199254740992", "18446744073709551615"} {
		want := "max_fee " + bad + " is above 9007199254740991, the largest value every client reads exactly"
		if _, err := service.PrepareGenerateKey(plainHostKeyType, request(bad)); err == nil || err.Kind != ErrorInvalidInput || err.Message != want {
			t.Fatalf("PrepareGenerateKey(max_fee=%s) error = %#v", bad, err)
		}
		if _, err := service.GenerateKey(context.Background(), plainHostKeyType, request(bad)); err == nil || err.Kind != ErrorInvalidInput || err.Message != want {
			t.Fatalf("GenerateKey(max_fee=%s) error = %#v", bad, err)
		}
	}
	largest, prepareErr := service.PrepareGenerateKey(plainHostKeyType, request("9007199254740991"))
	if prepareErr != nil || largest.Host == nil || largest.Host.FeeCeiling() == nil || *largest.Host.FeeCeiling() != hostmeta.MaxFeeLimit || len(largest.Warnings) != 0 {
		t.Fatalf("PrepareGenerateKey(largest max_fee) = %+v, %#v", largest, prepareErr)
	}
	if generated, err := service.GenerateKey(context.Background(), plainHostKeyType, request("9007199254740991")); err != nil ||
		generated.Parameters[boundary.ParameterMaxFee] != "9007199254740991" || len(generated.Warnings) != 0 {
		t.Fatalf("GenerateKey(largest max_fee) error = %#v, warnings = %q", err, warningsOf(generated))
	}
	withoutBounds := map[string]string{boundary.ParameterRekeyAuthority: boundary.RekeySpendingKey, boundary.ParameterMaxFee: "20000"}
	if _, err := service.PrepareGenerateKey(plainHostKeyType, withoutBounds); err == nil || !strings.Contains(err.Message, "spend_effects is required") {
		t.Fatalf("PrepareGenerateKey(max_fee without transfer kinds) error = %#v", err)
	}
}

// warningsOf reads a generation's warnings for a failure message, without the
// key material beside them.
func warningsOf(result *GenerateResult) []string {
	if result == nil {
		return nil
	}
	return result.Warnings
}

func TestPlainHostGeneratesFromAReview(t *testing.T) {
	ir, service, cosignerKey := setupPlainHost(t)
	params := map[string]string{
		cosignerrefs.ParamCosignerName:   prepareTestReference,
		boundary.ParameterRekeyAuthority: boundary.RekeyPlusCosigned,
		boundary.ParameterRekeyTo:        listedTarget.String(),
	}
	prepared, err := service.PrepareGenerateKey(plainHostKeyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	bounded := prepared.Host
	if bounded == nil || bounded.Contract != hostmeta.PlainContract || bounded.Bounds != nil || bounded.Cosigner == nil ||
		bounded.RekeyList == nil || bounded.Rekey != hostmeta.RekeySpendingKey {
		t.Fatalf("prepared contract = %+v", bounded)
	}
	if prepared.BoundaryDigest == "" || prepared.Fingerprint == prepared.ReviewFingerprint {
		t.Fatalf("prepared provenance = %+v", prepared)
	}
	// A plain host is its own signature base; the review reads it from here.
	if prepared.BaseKeyType != plainHostKeyType {
		t.Fatalf("prepared base key type = %q, want %q", prepared.BaseKeyType, plainHostKeyType)
	}
	assertNoKeys(t, service)

	result, genErr := service.GenerateReviewedKey(context.Background(), plainHostKeyType, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest})
	if genErr != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", genErr)
	}
	summary := ir.KeyStore().GetSigningSummary()[result.Address]
	metadata := summary.Host
	if metadata == nil || metadata.Contract != hostmeta.PlainContract || metadata.Cosigner == nil ||
		metadata.Cosigner.PublicKeyHex != hex.EncodeToString(cosignerKey) || metadata.RekeyList == nil || metadata.RekeyList.RootHex == "" {
		t.Fatalf("stored contract = %+v", metadata)
	}
	if summary.TemplateFingerprint != prepared.Fingerprint {
		t.Fatalf("stored fingerprint %q, prepared %q", summary.TemplateFingerprint, prepared.Fingerprint)
	}
	if summary.LogicSigResources == nil || summary.LogicSigResources.Spend == nil || summary.LogicSigResources.ListedRekey == nil {
		t.Fatalf("stored resources = %+v", summary.LogicSigResources)
	}
}

// The boundary requirements govern the plain hosts too, the plain program
// included: it has no cosigner and contains nothing.
func TestGenerationRequirementsGovernPlainHosts(t *testing.T) {
	ir, service, _ := setupPlainHost(t)
	cosigned := map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference, boundary.ParameterRekeyAuthority: boundary.RekeyRefused}
	uncosigned := map[string]string{boundary.ParameterRekeyAuthority: boundary.RekeyOnlyThese, boundary.ParameterRekeyTo: listedTarget.String()}

	ir.Config().SetGenerationRequirements(false, true)
	t.Cleanup(func() { ir.Config().SetGenerationRequirements(false, false) })
	for name, params := range map[string]map[string]string{"the plain program": nil, "an uncosigned plain host": uncosigned} {
		if _, err := service.PrepareGenerateKey(plainHostKeyType, params); err == nil || !strings.Contains(err.Message, "require_cosigner") {
			t.Fatalf("%s: PrepareGenerateKey() error = %#v", name, err)
		}
		if _, err := service.GenerateKey(context.Background(), plainHostKeyType, params); err == nil || !strings.Contains(err.Message, "require_cosigner") {
			t.Fatalf("%s: GenerateKey() error = %#v", name, err)
		}
	}
	if _, err := service.PrepareGenerateKey(plainHostKeyType, cosigned); err != nil {
		t.Fatalf("a cosigned plain host: PrepareGenerateKey() error = %#v", err)
	}

	// Every plain host spends anywhere, so none is contained.
	ir.Config().SetGenerationRequirements(true, false)
	if _, err := service.PrepareGenerateKey(plainHostKeyType, cosigned); err == nil || !strings.Contains(err.Message, "require_contained") {
		t.Fatalf("contained: PrepareGenerateKey() error = %#v", err)
	}
	assertNoKeys(t, service)
}

// Key details name a cosigned account's cosigner by its Witness Key ID, never
// the raw public key; an account without a cosigner keeps its parameters.
func TestKeyDetailsNameTheCosignerByWitnessKeyID(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x61}, hostmeta.DefaultCosignerPublicKeySize)
	id, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	parameters := map[string]string{
		hostmeta.CosignerPublicKeyParameter: hex.EncodeToString(publicKey),
		"rekey_authority":                   "refused",
	}
	metadata := &hostmeta.Metadata{Cosigner: &hostmeta.CosignerAuthorization{
		ComponentKeyType: witness.Falcon1024V1, PublicKeyHex: hex.EncodeToString(publicKey), ComponentKeyID: id,
	}}
	got := keyDetailsParameters(parameters, metadata)
	if got[keyDetailsCosignerParameter] != id || got[hostmeta.CosignerPublicKeyParameter] != "" || got["rekey_authority"] != "refused" {
		t.Fatalf("details = %v", got)
	}
	if plain := keyDetailsParameters(parameters, &hostmeta.Metadata{}); plain[hostmeta.CosignerPublicKeyParameter] == "" || plain[keyDetailsCosignerParameter] != "" {
		t.Fatalf("uncosigned details = %v", plain)
	}
	if parameters[hostmeta.CosignerPublicKeyParameter] == "" {
		t.Fatal("the projection changed the account's own parameters")
	}
}
