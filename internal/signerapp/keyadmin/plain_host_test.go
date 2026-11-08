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

// A plain host is created only with a cosigner. Without one the request selects
// the plain program, which is the composition base and never an account.
func TestPlainHostNeedsACosigner(t *testing.T) {
	_, service, _ := setupPlainHost(t)
	for name, params := range map[string]map[string]string{
		"no parameters": nil,
		"no cosigner":   {plainhost.ParameterRekeyAuthority: plainhost.RekeySpendingKey},
	} {
		t.Run(name, func(t *testing.T) {
			_, prepareErr := service.PrepareGenerateKey(plainHostKeyType, params)
			if prepareErr == nil || prepareErr.Kind != ErrorInvalidInput || !strings.Contains(prepareErr.Message, "cosigner") {
				t.Fatalf("PrepareGenerateKey() error = %#v", prepareErr)
			}
			_, generateErr := service.GenerateKey(context.Background(), plainHostKeyType, params, nil)
			if generateErr == nil || generateErr.Message != prepareErr.Message {
				t.Fatalf("GenerateKey() error = %#v, want the same as preparation %#v", generateErr, prepareErr)
			}
		})
	}
	assertNoKeys(t, service)
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
