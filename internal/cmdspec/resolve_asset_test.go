// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cmdspec

import (
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
)

type stubAssetResolver struct {
	ref  string
	meta asa.Metadata
	err  error
}

func (s *stubAssetResolver) ResolveMetadata(ref string) (asa.Metadata, error) {
	s.ref = ref
	if s.err != nil {
		return asa.Metadata{}, s.err
	}
	return s.meta, nil
}

func TestResolveAssetMetadataAlgo(t *testing.T) {
	resolver := &stubAssetResolver{}
	meta, err := ResolveAssetMetadata("testnet", "algo", resolver)
	if err != nil {
		t.Fatalf("ResolveAssetMetadata() error = %v", err)
	}
	if meta.AssetID != 0 || meta.Decimals != 6 || meta.UnitName != "ALGO" {
		t.Fatalf("ResolveAssetMetadata() = %#v", meta)
	}
	if resolver.ref != "" {
		t.Fatalf("resolver should not be called for algo, got %q", resolver.ref)
	}
}

func TestResolveAssetMetadataDelegates(t *testing.T) {
	resolver := &stubAssetResolver{meta: asa.Metadata{AssetID: 31566704, UnitName: "USDC", Decimals: 6}}
	meta, err := ResolveAssetMetadata("testnet", "usdc", resolver)
	if err != nil {
		t.Fatalf("ResolveAssetMetadata() error = %v", err)
	}
	if meta.AssetID != 31566704 {
		t.Fatalf("ResolveAssetMetadata() assetID = %d", meta.AssetID)
	}
	if resolver.ref != "usdc" {
		t.Fatalf("resolver ref = %q, want usdc", resolver.ref)
	}
}

func TestResolveAssetAmount(t *testing.T) {
	resolver := &stubAssetResolver{meta: asa.Metadata{AssetID: 31566704, UnitName: "USDC", Decimals: 6}}
	amount, err := ResolveAssetAmount("testnet", "usdc", "1.25", resolver)
	if err != nil {
		t.Fatalf("ResolveAssetAmount() error = %v", err)
	}
	if amount.Raw != 1250000 {
		t.Fatalf("ResolveAssetAmount() raw = %d, want 1250000", amount.Raw)
	}
	if amount.Meta.AssetID != 31566704 {
		t.Fatalf("ResolveAssetAmount() meta = %#v", amount.Meta)
	}
}

func TestResolveAssetMetadataError(t *testing.T) {
	resolver := &stubAssetResolver{err: errors.New("boom")}
	_, err := ResolveAssetMetadata("testnet", "usdc", resolver)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveForeignAssetIDsRejectsAlgo(t *testing.T) {
	resolver := &stubAssetResolver{meta: asa.Metadata{AssetID: 31566704, UnitName: "USDC", Decimals: 6}}
	_, err := ResolveForeignAssetIDs("testnet", []AssetRef{"algo", "usdc"}, resolver)
	if err == nil || err.Error() != `invalid foreign asset reference "algo": app-call foreign assets must be ASA IDs, not algo` {
		t.Fatalf("ResolveForeignAssetIDs() error = %v", err)
	}
}
