// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestBoundedLabel(t *testing.T) {
	admin := []signerapi.BoundedAdminOperationInfo{{Kind: "rekey", Authorization: boundedmeta.AdminAuthorizationAdmin, PolicyGate: boundedmeta.PolicyGateNone}}
	spending := []signerapi.BoundedAdminOperationInfo{{Kind: "rekey", Authorization: boundedmeta.AdminAuthorizationSpend, PolicyGate: boundedmeta.PolicyGateNone}}
	gated := []signerapi.BoundedAdminOperationInfo{{Kind: "rekey", Authorization: boundedmeta.AdminAuthorizationSpend, PolicyGate: boundedmeta.PolicyGateLayer3}}
	cosigner := &signerapi.BoundedCosignerAuthorizationInfo{}
	for _, test := range []struct {
		name string
		info *signerapi.BoundedAuthorizationInfo
		want string
	}{
		{"not bounded", nil, ""},
		{"merkle admin cosigner", &signerapi.BoundedAuthorizationInfo{Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlist, AdminOperations: admin, Cosigner: cosigner}, "Merkle allowlist · admin rekey · cosigner"},
		{"inline spending", &signerapi.BoundedAuthorizationInfo{Layer3Policy: boundedmeta.Layer3PolicyFixedAllowlist, AdminOperations: spending}, "Allowlist · spending-key rekey"},
		{"custom without rekey", &signerapi.BoundedAuthorizationInfo{Layer3Policy: boundedmeta.Layer3PolicyCustom}, "Custom policy · no rekey"},
		{"allowlist plus custom", &signerapi.BoundedAuthorizationInfo{Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlistCustom, AdminOperations: spending}, "Merkle allowlist plus custom policy · spending-key rekey"},
		{"timelock gate", &signerapi.BoundedAuthorizationInfo{Layer3Policy: boundedmeta.Layer3PolicyFixedAllowlistTimelock, AdminOperations: gated}, "Allowlist timelock · policy-gated rekey"},
		{"unknown policy stays honest", &signerapi.BoundedAuthorizationInfo{Layer3Policy: "future_rule"}, "Policy future_rule · no rekey"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := BoundedLabel(test.info); got != test.want {
				t.Fatalf("BoundedLabel() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestBoundedLabelsAgreeAcrossSources(t *testing.T) {
	metadata := &boundedmeta.Metadata{
		Layer3Policy:    boundedmeta.Layer3PolicyMerkleAllowlist,
		AdminOperations: []boundedmeta.AdminOperation{{Kind: "rekey", Authorization: boundedmeta.AdminAuthorizationAdmin, PolicyGate: boundedmeta.PolicyGateNone}},
		Cosigner:        &boundedmeta.CosignerAuthorization{},
	}
	info := &signerapi.BoundedAuthorizationInfo{
		Layer3Policy:    metadata.Layer3Policy,
		AdminOperations: []signerapi.BoundedAdminOperationInfo{{Kind: "rekey", Authorization: boundedmeta.AdminAuthorizationAdmin, PolicyGate: boundedmeta.PolicyGateNone}},
		Cosigner:        &signerapi.BoundedCosignerAuthorizationInfo{},
	}
	if got, want := BoundedMetadataLabel(metadata), BoundedLabel(info); got != want {
		t.Fatalf("metadata label %q, info label %q", got, want)
	}
	if BoundedMetadataLabel(nil) != "" {
		t.Fatal("no metadata must give no label")
	}
}
