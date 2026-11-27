// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/hostmeta"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestHostLabel(t *testing.T) {
	refused := string(hostmeta.RekeyRefused)
	spending := string(hostmeta.RekeySpendingKey)
	cosigner := &signerapi.HostCosignerInfo{}
	for _, test := range []struct {
		name string
		info *signerapi.HostInfo
		want string
	}{
		{"not bounded", nil, ""},
		{"merkle refused cosigner", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyMerkleAllowlist}, Rekey: refused, Cosigner: cosigner}, "Merkle allowlist · no rekey · cosigner"},
		{"unknown setting stays honest", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyMerkleAllowlist}, Rekey: "admin_key"}, "Merkle allowlist · admin_key rekey"},
		{"inline spending", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyFixedAllowlist}, Rekey: spending}, "Allowlist · spending-key rekey"},
		{"custom without rekey", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyCustom}, Rekey: refused}, "Custom policy · no rekey"},
		{"allowlist plus custom", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyMerkleAllowlistCustom}, Rekey: spending}, "Merkle allowlist plus custom policy · spending-key rekey"},
		{"limits only", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyNone}, Rekey: refused, Cosigner: cosigner}, "Limits only · no rekey · cosigner"},
		{"only these", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: hostmeta.Layer3PolicyFixedAllowlist}, Rekey: refused, RekeyList: &signerapi.HostRekeyListInfo{Contract: hostmeta.RekeyListContractV1, Depth: 4}}, "Allowlist · rekey to listed only"},
		{"unknown policy stays honest", &signerapi.HostInfo{Bounds: &signerapi.HostBoundsInfo{Layer3Policy: "future_rule"}, Rekey: refused}, "Policy future_rule · no rekey"},
		{"plain host", &signerapi.HostInfo{Contract: hostmeta.PlainContract, Rekey: spending, Cosigner: cosigner}, "Plain host · cosigned rekey · cosigner"},
		{"bounded without bounds claims no limits", &signerapi.HostInfo{Contract: hostmeta.BoundedContract, Rekey: refused}, "Policy  · no rekey"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HostLabel(test.info); got != test.want {
				t.Fatalf("HostLabel() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestHostLabelsAgreeAcrossSources(t *testing.T) {
	metadata := &hostmeta.Metadata{
		Bounds:   &hostmeta.Bounds{Layer3Policy: hostmeta.Layer3PolicyMerkleAllowlist},
		Rekey:    hostmeta.RekeyRefused,
		Cosigner: &hostmeta.CosignerAuthorization{},
	}
	info := &signerapi.HostInfo{
		Bounds:   &signerapi.HostBoundsInfo{Layer3Policy: metadata.Layer3Policy()},
		Rekey:    string(metadata.Rekey),
		Cosigner: &signerapi.HostCosignerInfo{},
	}
	if got, want := HostMetadataLabel(metadata), HostLabel(info); got != want {
		t.Fatalf("metadata label %q, info label %q", got, want)
	}
	// A cosigner requires rekey refused, so the spending-key label is checked without one.
	metadata.Rekey, metadata.Cosigner = hostmeta.RekeySpendingKey, nil
	info.Rekey, info.Cosigner = string(hostmeta.RekeySpendingKey), nil
	if got, want := HostMetadataLabel(metadata), HostLabel(info); got != want {
		t.Fatalf("spending key: metadata label %q, info label %q", got, want)
	}
	if HostMetadataLabel(nil) != "" {
		t.Fatal("no metadata must give no label")
	}
}
