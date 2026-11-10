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

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/lsig/plainhost"
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
	plain, err := service.GenerateKey(context.Background(), plainHostKeyType, nil, nil)
	if err != nil {
		t.Fatalf("GenerateKey(no parameters) error = %#v", err)
	}
	if summary := ir.KeyStore().GetSigningSummary()[plain.Address]; summary.BoundedAuthorization != nil {
		t.Fatalf("the plain program has an overlay contract: %+v", summary.BoundedAuthorization)
	}
	prepared, prepareErr := service.PrepareGenerateKey(plainHostKeyType, map[string]string{
		plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese,
		plainhost.ParameterRekeyTo:        listedTarget.String(),
	})
	if prepareErr != nil {
		t.Fatalf("PrepareGenerateKey(only these, no cosigner) error = %#v", prepareErr)
	}
	if bounded := prepared.Bounded; bounded == nil || bounded.Contract != boundedmeta.PlainContract || bounded.Cosigner != nil || bounded.RekeyList == nil {
		t.Fatalf("prepared contract = %+v", bounded)
	}
	listed, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	metadata := ir.KeyStore().GetSigningSummary()[listed.Address].BoundedAuthorization
	if metadata == nil || metadata.Contract != boundedmeta.PlainContract || metadata.Cosigner != nil || metadata.RekeyList == nil {
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
			plainhost.ParameterSpendEffects:   "pay",
			plainhost.ParameterRecipientScope: plainhost.RecipientScopeAny,
			plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey,
		}
		if maxFee != "" {
			params[plainhost.ParameterMaxFee] = maxFee
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
			if prepared.Bounded == nil || prepared.Bounded.Contract != boundedmeta.Contract || prepared.Bounded.MaxFee == nil || *prepared.Bounded.MaxFee != test.want {
				t.Fatalf("prepared contract = %+v", prepared.Bounded)
			}
			// Only a limit other than the default is a parameter of the account, and
			// the default is the account that names none.
			persisted, present := prepared.Parameters[plainhost.ParameterMaxFee]
			if test.want == plainhost.DefaultMaxFee {
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
					ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
				if err != nil || len(generated.Warnings) != 0 {
					t.Fatalf("GenerateReviewedKey() error = %#v, warnings = %q; want none", err, warningsOf(generated))
				}
				unreviewed, err := service.GenerateKey(context.Background(), plainHostKeyType, request(test.maxFee), nil)
				if err != nil || len(unreviewed.Warnings) != 0 {
					t.Fatalf("GenerateKey() error = %#v, warnings = %q; want none", err, warningsOf(unreviewed))
				}
				return
			}
			want := "Fee limit " + test.maxFee + " is below its own costs. It can't pay for these transactions itself: spend (at least "
			if len(prepared.Warnings) != 1 || !strings.HasPrefix(prepared.Warnings[0], want) {
				t.Fatalf("Warnings = %q, want one starting %q", prepared.Warnings, want)
			}
			if !projected.Success || len(projected.Warnings) != 1 || projected.Warnings[0] != prepared.Warnings[0] ||
				projected.Bounded == nil || projected.Bounded.MaxFee == nil || *projected.Bounded.MaxFee != test.want {
				t.Fatalf("projected = %+v", projected)
			}

			// The warning refuses nothing: the reviewed account is generated, with
			// the limit it was reviewed with.
			generated, err := service.GenerateReviewedKey(context.Background(), plainHostKeyType, prepared.Parameters,
				ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
			if err != nil {
				t.Fatalf("GenerateReviewedKey() error = %#v", err)
			}
			metadata := ir.KeyStore().GetSigningSummary()[generated.Address].BoundedAuthorization
			if metadata == nil || metadata.MaxFee == nil || *metadata.MaxFee != test.want {
				t.Fatalf("stored contract = %+v", metadata)
			}
			if generated.Parameters[plainhost.ParameterMaxFee] != test.maxFee {
				t.Fatalf("generated parameters = %v", generated.Parameters)
			}
			// Generation carries the same advice the review showed, and so does a
			// generation nobody reviewed, which has no other place to show it.
			if !slices.Equal(generated.Warnings, prepared.Warnings) {
				t.Fatalf("generated Warnings = %q, want %q", generated.Warnings, prepared.Warnings)
			}
			unreviewed, err := service.GenerateKey(context.Background(), plainHostKeyType, request(test.maxFee), nil)
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
	for _, params := range []map[string]string{nil, {plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused}} {
		generated, err := service.GenerateKey(context.Background(), plainHostKeyType, params, nil)
		if err != nil || len(generated.Warnings) != 0 {
			t.Fatalf("GenerateKey(%v) error = %#v, warnings = %q; want none", params, err, warningsOf(generated))
		}
	}
	// What the provider refuses is still refused, with no warning in its place.
	for _, bad := range []string{"abc", "-1", "1.5", "010", "18446744073709551616"} {
		if _, err := service.PrepareGenerateKey(plainHostKeyType, request(bad)); err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, "max_fee must be a whole number") {
			t.Fatalf("PrepareGenerateKey(max_fee=%s) error = %#v", bad, err)
		}
		if _, err := service.GenerateKey(context.Background(), plainHostKeyType, request(bad), nil); err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, "max_fee must be a whole number") {
			t.Fatalf("GenerateKey(max_fee=%s) error = %#v", bad, err)
		}
	}
	// The largest limit is the largest whole number every client reads exactly.
	for _, bad := range []string{"9007199254740992", "18446744073709551615"} {
		want := "max_fee " + bad + " is above 9007199254740991, the largest value every client reads exactly"
		if _, err := service.PrepareGenerateKey(plainHostKeyType, request(bad)); err == nil || err.Kind != ErrorInvalidInput || err.Message != want {
			t.Fatalf("PrepareGenerateKey(max_fee=%s) error = %#v", bad, err)
		}
		if _, err := service.GenerateKey(context.Background(), plainHostKeyType, request(bad), nil); err == nil || err.Kind != ErrorInvalidInput || err.Message != want {
			t.Fatalf("GenerateKey(max_fee=%s) error = %#v", bad, err)
		}
	}
	largest, prepareErr := service.PrepareGenerateKey(plainHostKeyType, request("9007199254740991"))
	if prepareErr != nil || largest.Bounded == nil || largest.Bounded.MaxFee == nil || *largest.Bounded.MaxFee != boundedmeta.MaxFeeLimit || len(largest.Warnings) != 0 {
		t.Fatalf("PrepareGenerateKey(largest max_fee) = %+v, %#v", largest, prepareErr)
	}
	if generated, err := service.GenerateKey(context.Background(), plainHostKeyType, request("9007199254740991"), nil); err != nil ||
		generated.Parameters[plainhost.ParameterMaxFee] != "9007199254740991" || len(generated.Warnings) != 0 {
		t.Fatalf("GenerateKey(largest max_fee) error = %#v, warnings = %q", err, warningsOf(generated))
	}
	withoutBounds := map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey, plainhost.ParameterMaxFee: "20000"}
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
		cosignerrefs.ParamCosignerName:    prepareTestReference,
		plainhost.ParameterRekeyAuthority: plainhost.RekeyPlusCosigned,
		plainhost.ParameterRekeyTo:        listedTarget.String(),
	}
	prepared, err := service.PrepareGenerateKey(plainHostKeyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	bounded := prepared.Bounded
	if bounded == nil || bounded.Contract != boundedmeta.PlainContract || bounded.MaxFee != nil || bounded.Cosigner == nil ||
		bounded.RekeyList == nil || bounded.Rekey != boundedmeta.RekeySpendingKey {
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
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if genErr != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", genErr)
	}
	summary := ir.KeyStore().GetSigningSummary()[result.Address]
	metadata := summary.BoundedAuthorization
	if metadata == nil || metadata.Contract != boundedmeta.PlainContract || metadata.Cosigner == nil ||
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
	cosigned := map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference, plainhost.ParameterRekeyAuthority: plainhost.RekeyRefused}
	uncosigned := map[string]string{plainhost.ParameterRekeyAuthority: plainhost.RekeyOnlyThese, plainhost.ParameterRekeyTo: listedTarget.String()}

	ir.Config().SetGenerationRequirements(false, true)
	t.Cleanup(func() { ir.Config().SetGenerationRequirements(false, false) })
	for name, params := range map[string]map[string]string{"the plain program": nil, "an uncosigned plain host": uncosigned} {
		if _, err := service.PrepareGenerateKey(plainHostKeyType, params); err == nil || !strings.Contains(err.Message, "require_cosigner") {
			t.Fatalf("%s: PrepareGenerateKey() error = %#v", name, err)
		}
		if _, err := service.GenerateKey(context.Background(), plainHostKeyType, params, nil); err == nil || !strings.Contains(err.Message, "require_cosigner") {
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
	publicKey := bytes.Repeat([]byte{0x61}, boundedmeta.CosignerPublicKeySizeV1)
	id, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	parameters := map[string]string{
		boundedmeta.CosignerPublicKeyParameter: hex.EncodeToString(publicKey),
		"rekey_authority":                      "refused",
	}
	metadata := &boundedmeta.Metadata{Cosigner: &boundedmeta.CosignerAuthorization{
		ComponentKeyType: witness.Falcon1024V1, PublicKeyHex: hex.EncodeToString(publicKey), ComponentKeyID: id,
	}}
	got := keyDetailsParameters(parameters, metadata)
	if got[keyDetailsCosignerParameter] != id || got[boundedmeta.CosignerPublicKeyParameter] != "" || got["rekey_authority"] != "refused" {
		t.Fatalf("details = %v", got)
	}
	if plain := keyDetailsParameters(parameters, &boundedmeta.Metadata{}); plain[boundedmeta.CosignerPublicKeyParameter] == "" || plain[keyDetailsCosignerParameter] != "" {
		t.Fatalf("uncosigned details = %v", plain)
	}
	if parameters[boundedmeta.CosignerPublicKeyParameter] == "" {
		t.Fatal("the projection changed the account's own parameters")
	}
}
