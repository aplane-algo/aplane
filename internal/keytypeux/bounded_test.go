// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestBoundedLabel(t *testing.T) {
	refused := string(boundedmeta.RekeyRefused)
	spending := string(boundedmeta.RekeySpendingKey)
	cosigner := &signerapi.HostCosignerInfo{}
	for _, test := range []struct {
		name string
		info *signerapi.HostInfo
		want string
	}{
		{"not bounded", nil, ""},
		{"merkle refused cosigner", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlist}, Rekey: refused, Cosigner: cosigner}, "Merkle allowlist · no rekey · cosigner"},
		{"unknown setting stays honest", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlist}, Rekey: "admin_key"}, "Merkle allowlist · admin_key rekey"},
		{"inline spending", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyFixedAllowlist}, Rekey: spending}, "Allowlist · spending-key rekey"},
		{"custom without rekey", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyCustom}, Rekey: refused}, "Custom policy · no rekey"},
		{"allowlist plus custom", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlistCustom}, Rekey: spending}, "Merkle allowlist plus custom policy · spending-key rekey"},
		{"limits only", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyNone}, Rekey: refused, Cosigner: cosigner}, "Limits only · no rekey · cosigner"},
		{"only these", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: boundedmeta.Layer3PolicyFixedAllowlist}, Rekey: refused, RekeyList: &signerapi.HostRekeyListInfo{Contract: boundedmeta.RekeyListContractV1, Depth: 4}}, "Allowlist · rekey to listed only"},
		{"unknown policy stays honest", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: "future_rule"}, Rekey: refused}, "Policy future_rule · no rekey"},
		{"plain host", &signerapi.HostInfo{Contract: boundedmeta.PlainContract, Rekey: spending, Cosigner: cosigner}, "Plain host · cosigned rekey · cosigner"},
		{"bounded without bounds claims no limits", &signerapi.HostInfo{Contract: boundedmeta.Contract, Rekey: refused}, "Policy  · no rekey"},
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
		Bounds:   &boundedmeta.Bounds{Layer3Policy: boundedmeta.Layer3PolicyMerkleAllowlist},
		Rekey:    boundedmeta.RekeyRefused,
		Cosigner: &boundedmeta.CosignerAuthorization{},
	}
	info := &signerapi.HostInfo{
		Bounds:   &signerapi.HostBoundsInfo{Layer3Policy: metadata.Layer3Policy()},
		Rekey:    string(metadata.Rekey),
		Cosigner: &signerapi.HostCosignerInfo{},
	}
	if got, want := BoundedMetadataLabel(metadata), BoundedLabel(info); got != want {
		t.Fatalf("metadata label %q, info label %q", got, want)
	}
	// A cosigner requires rekey refused, so the spending-key label is checked without one.
	metadata.Rekey, metadata.Cosigner = boundedmeta.RekeySpendingKey, nil
	info.Rekey, info.Cosigner = string(boundedmeta.RekeySpendingKey), nil
	if got, want := BoundedMetadataLabel(metadata), BoundedLabel(info); got != want {
		t.Fatalf("spending key: metadata label %q, info label %q", got, want)
	}
	if BoundedMetadataLabel(nil) != "" {
		t.Fatal("no metadata must give no label")
	}
}
