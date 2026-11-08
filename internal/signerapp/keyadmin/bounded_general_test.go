// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	"github.com/aplane-algo/aplane/lsig/boundedaccount"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

func setupGeneralProvider(t *testing.T) (*productruntime.Runtime, Service) {
	t.Helper()
	configureFalconCompileMock(t)
	boundedaccount.RegisterClient()
	ir := setupProductRuntime(t)
	return ir, Service{Runtime: ir}
}

func generalParams(rekey string) map[string]string {
	var recipient types.Address
	recipient[31] = 7
	params := map[string]string{
		boundedaccount.ParameterSpendEffects:   "pay,axfer,asset_opt_in",
		boundedaccount.ParameterRekeyAuthority: rekey,
		boundedaccount.ParameterRecipients:     recipient.String(),
	}
	return params
}

func TestGeneralProviderGeneratesFromAReview(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	params := generalParams(boundedaccount.RekeySpendingKey)
	prepared, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if prepared.Fingerprint == "" || prepared.ReviewFingerprint == "" || prepared.Fingerprint == prepared.ReviewFingerprint {
		t.Fatalf("shape %q and grammar %q fingerprints must both exist and differ", prepared.Fingerprint, prepared.ReviewFingerprint)
	}
	if prepared.BoundaryDigest == "" {
		t.Fatal("prepared request has no boundary digest")
	}
	if prepared.Parameters[boundedaccount.ParameterListEncoding] != boundedaccount.EncodingInline {
		t.Fatalf("auto encoding was not resolved: %v", prepared.Parameters)
	}
	assertNoKeys(t, service)

	result, err := service.GenerateReviewedKey(context.Background(), boundedaccount.KeyTypeV1, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	if result.Parameters[boundedaccount.ParameterRekeyAuthority] != boundedaccount.RekeySpendingKey {
		t.Fatalf("result parameters = %v", result.Parameters)
	}
	details, detailsErr := service.GetKeyDetails(result.Address)
	if detailsErr != nil {
		t.Fatalf("GetKeyDetails() error = %#v", detailsErr)
	}
	if details.TemplateProvenanceStatus != "" {
		t.Fatalf("new account has provenance status %q: %s", details.TemplateProvenanceStatus, details.TemplateProvenanceNote)
	}
	if details.PolicyLabel != "Allowlist · spending-key rekey" {
		t.Fatalf("policy label = %q", details.PolicyLabel)
	}
	snapshot, _ := ir.KeySnapshot()
	readErr := ir.WithKeyring(func(mk *crypto.Keyring) error {
		info, err := keymgmt.DetectKeyInfoFromFileWithKeyring(snapshot[result.Address], mk)
		if err != nil {
			return err
		}
		// A provenance status is empty for an empty fingerprint too, so check
		// that the account recorded its shape, not the grammar it was approved under.
		if info.TemplateFingerprint != prepared.Fingerprint {
			t.Fatalf("account records %q, want its shape fingerprint %q", info.TemplateFingerprint, prepared.Fingerprint)
		}
		if info.BoundedAuthorization == nil {
			t.Fatal("account has no bounded contract")
		}
		return nil
	})
	if readErr != nil {
		t.Fatal(readErr)
	}
}

func TestGeneralProviderRejectsAChangedReview(t *testing.T) {
	_, service := setupGeneralProvider(t)
	params := generalParams(boundedaccount.RekeyRefused)
	prepared, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	stale := strings.Repeat("0", 64)
	for name, reviewed := range map[string]ReviewedValues{
		"grammar": {Fingerprint: "1:" + stale, BoundaryDigest: prepared.BoundaryDigest},
		"digest":  {Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: stale},
	} {
		_, err := service.GenerateReviewedKey(context.Background(), boundedaccount.KeyTypeV1, prepared.Parameters, reviewed, nil)
		if err == nil || !strings.Contains(err.Message, "changed after this request was reviewed") {
			t.Fatalf("%s: GenerateReviewedKey() error = %#v", name, err)
		}
	}
	changed := make(map[string]string, len(prepared.Parameters))
	for key, value := range prepared.Parameters {
		changed[key] = value
	}
	var other types.Address
	other[31] = 8
	changed[boundedaccount.ParameterRecipients] = other.String()
	_, err = service.GenerateReviewedKey(context.Background(), boundedaccount.KeyTypeV1, changed,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err == nil || !strings.Contains(err.Message, "changed after this request was reviewed") {
		t.Fatalf("substituted recipient: GenerateReviewedKey() error = %#v", err)
	}
	assertNoKeys(t, service)
}

func TestBoundaryRequirements(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	publicKey, _ := importPrepareReference(t, ir, prepareTestReference, 0x61)
	spendingKey := generalParams(boundedaccount.RekeySpendingKey)
	refused := generalParams(boundedaccount.RekeyRefused)
	cosigned := generalParams(boundedaccount.RekeyRefused)
	cosigned[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(publicKey)
	// Refusing rekeys is not containment on its own: a timelock with no list
	// pays anyone once it opens.
	timelockOnly := generalParams(boundedaccount.RekeyRefused)
	delete(timelockOnly, boundedaccount.ParameterRecipients)
	timelockOnly[boundedaccount.ParameterUnlockRound] = "100"

	tests := []struct {
		name               string
		requireContained   bool
		requireCosigner    bool
		rejected, accepted []map[string]string
		want               string
	}{
		{"contained", true, false, []map[string]string{spendingKey, timelockOnly}, []map[string]string{refused, cosigned}, "boundary_require_contained"},
		{"cosigner", false, true, []map[string]string{spendingKey, refused}, []map[string]string{cosigned}, "boundary_require_cosigner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ir.Config().SetBoundaryRequirements(test.requireContained, test.requireCosigner)
			t.Cleanup(func() { ir.Config().SetBoundaryRequirements(false, false) })
			for _, params := range test.rejected {
				if _, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params); err == nil || !strings.Contains(err.Message, test.want) {
					t.Fatalf("PrepareGenerateKey() error = %#v", err)
				}
				if _, err := service.GenerateKey(context.Background(), boundedaccount.KeyTypeV1, params, nil); err == nil || !strings.Contains(err.Message, test.want) {
					t.Fatalf("GenerateKey() error = %#v", err)
				}
			}
			for _, params := range test.accepted {
				if _, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params); err != nil {
					t.Fatalf("PrepareGenerateKey() error = %#v", err)
				}
			}
		})
	}
}

// No host rule holds a rekey until the unlock round, so a timelock a spending key
// could rekey out of is refused before review and before anything is created.
func TestGeneralProviderRefusesASpendingKeyRekeyOnATimelock(t *testing.T) {
	_, service := setupGeneralProvider(t)
	timelockOnly := generalParams(boundedaccount.RekeySpendingKey)
	delete(timelockOnly, boundedaccount.ParameterRecipients)
	timelockOnly[boundedaccount.ParameterUnlockRound] = "100"
	listAndTimelock := generalParams(boundedaccount.RekeySpendingKey)
	listAndTimelock[boundedaccount.ParameterUnlockRound] = "100"
	for name, params := range map[string]map[string]string{"timelock": timelockOnly, "allowlist and timelock": listAndTimelock} {
		const want = "a timelock requires " + boundedaccount.ParameterRekeyAuthority + "=" + boundedaccount.RekeyRefused
		if _, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params); err == nil || !strings.Contains(err.Message, want) {
			t.Fatalf("%s: PrepareGenerateKey() error = %#v", name, err)
		}
		if _, err := service.GenerateKey(context.Background(), boundedaccount.KeyTypeV1, params, nil); err == nil || !strings.Contains(err.Message, want) {
			t.Fatalf("%s: GenerateKey() error = %#v", name, err)
		}
	}
	assertNoKeys(t, service)
}

func TestBoundaryRequirementIsRecheckedAfterReview(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	prepared, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, generalParams(boundedaccount.RekeySpendingKey))
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	ir.Config().SetBoundaryRequirements(true, false)
	t.Cleanup(func() { ir.Config().SetBoundaryRequirements(false, false) })
	_, err = service.GenerateReviewedKey(context.Background(), boundedaccount.KeyTypeV1, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err == nil || !strings.Contains(err.Message, "boundary_require_contained") {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	assertNoKeys(t, service)
}

func TestBoundaryRequirementsDoNotReachExpertTemplates(t *testing.T) {
	const keyType = "test.bounded-expert.v1"
	ir, _, _ := setupPrepareTest(t, keyType, "bounded-expert")
	ir.Config().SetBoundaryRequirements(true, true)
	service := Service{Runtime: ir}
	// This template refuses rekeys but is not the general type; the settings must not care.
	if _, err := service.GenerateKey(context.Background(), keyType, map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference}, nil); err != nil {
		t.Fatalf("GenerateKey() error = %#v", err)
	}
}

func TestCosignerReferenceResolvesBeforeTheShapeIsChosen(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	publicKey, keyID := importPrepareReference(t, ir, prepareTestReference, 0x61)
	params := generalParams(boundedaccount.RekeyRefused)
	params[cosignerrefs.ParamCosignerName] = prepareTestReference
	prepared, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if prepared.Parameters[composeddsa.BoundedCosignerPublicKeyParameter] != hex.EncodeToString(publicKey) || prepared.CosignerKeyID != keyID {
		t.Fatalf("resolved cosigner = %v, %s", prepared.Parameters, prepared.CosignerKeyID)
	}
	if _, present := prepared.Parameters[cosignerrefs.ParamCosignerName]; present {
		t.Fatal("the reference name reached the resolved request")
	}

	params[cosignerrefs.ParamCosignerName] = "missing"
	if _, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params); err == nil {
		t.Fatal("an unknown reference fell through")
	}
	params[cosignerrefs.ParamCosignerName] = ""
	if _, err := service.PrepareGenerateKey(boundedaccount.KeyTypeV1, params); err == nil {
		t.Fatal("an explicitly empty reference selected an account with no cosigner")
	}
}
