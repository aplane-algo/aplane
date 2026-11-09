// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/internal/cosigner/cosignerrefs"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
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
