// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"bytes"
	"context"
	"encoding/hex"
	"maps"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falcon "github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/plainhost"
)

// boundedHostKeyType is the Falcon plain host, which takes bounds as well as
// the overlays.
const boundedHostKeyType = "aplane.falcon1024.v1"

func setupGeneralProvider(t *testing.T) (*productruntime.Runtime, Service) {
	t.Helper()
	configureFalconCompileMock(t)
	falcon.RegisterClient()
	ir := setupProductRuntime(t)
	return ir, Service{Runtime: ir}
}

// listedTarget is the address an only_these test account may be rekeyed to.
var listedTarget = func() types.Address {
	var target types.Address
	target[0], target[31] = 0x51, 1
	return target
}()

func generalParams(rekey string) map[string]string {
	var recipient types.Address
	recipient[31] = 7
	params := map[string]string{
		plainhost.ParameterSpendEffects:   "pay,axfer,asset_opt_in",
		plainhost.ParameterRekeyAuthority: rekey,
		plainhost.ParameterRecipients:     recipient.String(),
	}
	if rekey == plainhost.RekeyOnlyThese || rekey == plainhost.RekeyPlusCosigned {
		params[plainhost.ParameterRekeyTo] = listedTarget.String()
	}
	return params
}

func TestGeneralProviderGeneratesFromAReview(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	params := generalParams(plainhost.RekeySpendingKey)
	prepared, err := service.PrepareGenerateKey(boundedHostKeyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if prepared.Fingerprint == "" || prepared.ReviewFingerprint == "" || prepared.Fingerprint == prepared.ReviewFingerprint {
		t.Fatalf("shape %q and grammar %q fingerprints must both exist and differ", prepared.Fingerprint, prepared.ReviewFingerprint)
	}
	if prepared.BoundaryDigest == "" {
		t.Fatal("prepared request has no boundary digest")
	}
	if prepared.Parameters[plainhost.ParameterListEncoding] != plainhost.EncodingInline {
		t.Fatalf("auto encoding was not resolved: %v", prepared.Parameters)
	}
	assertNoKeys(t, service)

	result, err := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	if result.Parameters[plainhost.ParameterRekeyAuthority] != plainhost.RekeySpendingKey {
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
	params := generalParams(plainhost.RekeyOnlyThese)
	prepared, err := service.PrepareGenerateKey(boundedHostKeyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	stale := strings.Repeat("0", 64)
	for name, reviewed := range map[string]ReviewedValues{
		"grammar": {Fingerprint: "1:" + stale, BoundaryDigest: prepared.BoundaryDigest},
		"digest":  {Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: stale},
	} {
		_, err := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, prepared.Parameters, reviewed, nil)
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
	changed[plainhost.ParameterRecipients] = other.String()
	_, err = service.GenerateReviewedKey(context.Background(), boundedHostKeyType, changed,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err == nil || !strings.Contains(err.Message, "changed after this request was reviewed") {
		t.Fatalf("substituted recipient: GenerateReviewedKey() error = %#v", err)
	}
	assertNoKeys(t, service)
}

func TestGenerationRequirements(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	publicKey, _ := importPrepareReference(t, ir, prepareTestReference, 0x61)
	spendingKey := generalParams(plainhost.RekeySpendingKey)
	refused := generalParams(plainhost.RekeyOnlyThese)
	cosigned := generalParams(plainhost.RekeyOnlyThese)
	cosigned[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(publicKey)
	// Cosigned rekeys are not containment either: two online keys can rekey the
	// account anywhere the cosigner's policy allows.
	cosignedSpending := generalParams(plainhost.RekeySpendingKey)
	cosignedSpending[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(publicKey)
	plusCosigned := generalParams(plainhost.RekeyPlusCosigned)
	plusCosigned[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(publicKey)
	// Refusing rekeys is not containment on its own: a limits-only account pays
	// anyone. Nor is a cosigner: it pays anyone the cosigner signs for.
	limitsOnly := generalParams(plainhost.RekeyOnlyThese)
	delete(limitsOnly, plainhost.ParameterRecipients)
	limitsOnly[plainhost.ParameterRecipientScope] = plainhost.RecipientScopeAny
	limitsCosigned := generalParams(plainhost.RekeyOnlyThese)
	delete(limitsCosigned, plainhost.ParameterRecipients)
	limitsCosigned[plainhost.ParameterRecipientScope] = plainhost.RecipientScopeAny
	limitsCosigned[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(publicKey)

	tests := []struct {
		name               string
		requireContained   bool
		requireCosigner    bool
		rejected, accepted []map[string]string
		want               string
	}{
		{"contained", true, false, []map[string]string{spendingKey, limitsOnly, limitsCosigned, cosignedSpending, plusCosigned}, []map[string]string{refused, cosigned}, "require_contained"},
		{"cosigner", false, true, []map[string]string{spendingKey, refused, limitsOnly}, []map[string]string{cosigned, limitsCosigned, cosignedSpending, plusCosigned}, "require_cosigner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ir.Config().SetGenerationRequirements(test.requireContained, test.requireCosigner)
			t.Cleanup(func() { ir.Config().SetGenerationRequirements(false, false) })
			for _, params := range test.rejected {
				if _, err := service.PrepareGenerateKey(boundedHostKeyType, params); err == nil || !strings.Contains(err.Message, test.want) {
					t.Fatalf("PrepareGenerateKey() error = %#v", err)
				}
				if _, err := service.GenerateKey(context.Background(), boundedHostKeyType, params, nil); err == nil || !strings.Contains(err.Message, test.want) {
					t.Fatalf("GenerateKey() error = %#v", err)
				}
			}
			for _, params := range test.accepted {
				if _, err := service.PrepareGenerateKey(boundedHostKeyType, params); err != nil {
					t.Fatalf("PrepareGenerateKey() error = %#v", err)
				}
			}
		})
	}
}

// The framework timelock is gone: a request that names an unlock round is
// refused, with a recipient list or without, and makes no key.
func TestBoundsRefuseAnUnlockRound(t *testing.T) {
	_, service := setupGeneralProvider(t)
	listed := generalParams(plainhost.RekeySpendingKey)
	listed["unlock_round"] = "100"
	alone := generalParams(plainhost.RekeyOnlyThese)
	delete(alone, plainhost.ParameterRecipients)
	alone["unlock_round"] = "100"
	for name, params := range map[string]map[string]string{"allowlist and unlock round": listed, "unlock round alone": alone} {
		if _, err := service.PrepareGenerateKey(boundedHostKeyType, params); err == nil || !strings.Contains(err.Message, "unknown parameter") {
			t.Fatalf("%s: PrepareGenerateKey() error = %#v", name, err)
		}
		if _, err := service.GenerateKey(context.Background(), boundedHostKeyType, params, nil); err == nil || !strings.Contains(err.Message, "unknown parameter") {
			t.Fatalf("%s: GenerateKey() error = %#v", name, err)
		}
	}
	assertNoKeys(t, service)
}

func TestGenerationRequirementIsRecheckedAfterReview(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	prepared, err := service.PrepareGenerateKey(boundedHostKeyType, generalParams(plainhost.RekeySpendingKey))
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	ir.Config().SetGenerationRequirements(true, false)
	t.Cleanup(func() { ir.Config().SetGenerationRequirements(false, false) })
	_, err = service.GenerateReviewedKey(context.Background(), boundedHostKeyType, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err == nil || !strings.Contains(err.Message, "require_contained") {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	assertNoKeys(t, service)
}

func TestGenerationRequirementsDoNotReachExpertTemplates(t *testing.T) {
	const keyType = "test.bounded-expert.v1"
	ir, _, _ := setupPrepareTest(t, keyType, "bounded-expert")
	ir.Config().SetGenerationRequirements(true, true)
	service := Service{Runtime: ir}
	// This template refuses rekeys but is not the general type; the settings must not care.
	if _, err := service.GenerateKey(context.Background(), keyType, map[string]string{cosignerrefs.ParamCosignerName: prepareTestReference}, nil); err != nil {
		t.Fatalf("GenerateKey() error = %#v", err)
	}
}

func TestCosignerReferenceResolvesBeforeTheShapeIsChosen(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	publicKey, keyID := importPrepareReference(t, ir, prepareTestReference, 0x61)
	params := generalParams(plainhost.RekeyPlusCosigned)
	params[cosignerrefs.ParamCosignerName] = prepareTestReference // plus cosigned needs the cosigner
	prepared, err := service.PrepareGenerateKey(boundedHostKeyType, params)
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
	if _, err := service.PrepareGenerateKey(boundedHostKeyType, params); err == nil {
		t.Fatal("an unknown reference fell through")
	}
	params[cosignerrefs.ParamCosignerName] = ""
	if _, err := service.PrepareGenerateKey(boundedHostKeyType, params); err == nil {
		t.Fatal("an explicitly empty reference selected an account with no cosigner")
	}
}

// An "only these" account through review and generation: the review binds the
// listed addresses, generation adds the root from the new spending key, and the
// stored account carries both.
func TestGeneralProviderGeneratesAnOnlyTheseAccount(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	params := generalParams(plainhost.RekeyOnlyThese)
	prepared, err := service.PrepareGenerateKey(boundedHostKeyType, params)
	if err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
	if prepared.Bounded == nil || prepared.Bounded.RekeyList == nil || prepared.Bounded.RekeyList.RootHex != "" {
		t.Fatalf("prepared bounded profile = %+v", prepared.Bounded)
	}
	if _, present := prepared.Parameters[boundedmeta.RekeyListRootParameter]; present {
		t.Fatal("a review carries a root")
	}
	changed := maps.Clone(prepared.Parameters)
	var other types.Address
	other[0], other[31] = 0x52, 1
	changed[plainhost.ParameterRekeyTo] = other.String()
	if _, err := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, changed,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil); err == nil ||
		!strings.Contains(err.Message, "changed after this request was reviewed") {
		t.Fatalf("a substituted rekey-to address: GenerateReviewedKey() error = %#v", err)
	}
	assertNoKeys(t, service)

	result, err := service.GenerateReviewedKey(context.Background(), boundedHostKeyType, prepared.Parameters,
		ReviewedValues{Fingerprint: prepared.ReviewFingerprint, BoundaryDigest: prepared.BoundaryDigest}, nil)
	if err != nil {
		t.Fatalf("GenerateReviewedKey() error = %#v", err)
	}
	details, detailsErr := service.GetKeyDetails(result.Address)
	if detailsErr != nil || details.PolicyLabel != "Allowlist · rekey to listed only" {
		t.Fatalf("details = %+v, %#v", details, detailsErr)
	}
	snapshot, _ := ir.KeySnapshot()
	readErr := ir.WithKeyring(func(mk *crypto.Keyring) error {
		info, err := keymgmt.DetectKeyInfoFromFileWithKeyring(snapshot[result.Address], mk)
		if err != nil {
			return err
		}
		root := info.Parameters[boundedmeta.RekeyListRootParameter]
		if len(root) != 64 || info.BoundedAuthorization.RekeyList == nil || info.BoundedAuthorization.RekeyList.RootHex != root {
			t.Fatalf("stored root %q, metadata %+v", root, info.BoundedAuthorization.RekeyList)
		}
		if info.Parameters[plainhost.ParameterRekeyTo] != listedTarget.String() {
			t.Fatalf("stored entries = %q", info.Parameters[plainhost.ParameterRekeyTo])
		}
		if info.TemplateFingerprint != prepared.Fingerprint {
			t.Fatalf("stored fingerprint %s, reviewed %s", info.TemplateFingerprint, prepared.Fingerprint)
		}
		return nil
	})
	if readErr != nil {
		t.Fatal(readErr)
	}
}

// The list may name any address, even one that can never act on the account,
// such as a cosigner reference's or the account's own cosigner's native address:
// which addresses to list is the user's choice.
func TestRekeyListTakesAnyAddress(t *testing.T) {
	ir, service := setupGeneralProvider(t)
	referenceKey, _ := importPrepareReference(t, ir, prepareTestReference, 0x61)
	_, referenceAddress, err := nativefalcon.CanonicalAddress(referenceKey)
	if err != nil {
		t.Fatal(err)
	}
	ownCosigner := bytes.Repeat([]byte{0x62}, boundedmeta.CosignerPublicKeySizeV1)
	_, ownCosignerAddress, err := nativefalcon.CanonicalAddress(ownCosigner)
	if err != nil {
		t.Fatal(err)
	}
	params := generalParams(plainhost.RekeyPlusCosigned)
	params[composeddsa.BoundedCosignerPublicKeyParameter] = hex.EncodeToString(ownCosigner)
	params[plainhost.ParameterRekeyTo] = listedTarget.String() + "," + referenceAddress.String() + "," + ownCosignerAddress.String()
	if _, err := service.PrepareGenerateKey(boundedHostKeyType, params); err != nil {
		t.Fatalf("PrepareGenerateKey() error = %#v", err)
	}
}
