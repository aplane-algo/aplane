// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package registry

import "testing"

func TestBuiltinMetadata(t *testing.T) {
	info, ok := BuiltinMetadata("mainnet", 31566704)
	if !ok {
		t.Fatal("BuiltinMetadata(mainnet, 31566704) = not found, want found")
	}
	if info.UnitName != "USDC" || info.Decimals != 6 {
		t.Fatalf("BuiltinMetadata(mainnet, 31566704) = %+v, want USDC/6", info)
	}
}

func TestResolveReferenceUsesBuiltinsAndAliases(t *testing.T) {
	tests := []struct {
		name    string
		network string
		ref     string
		want    uint64
	}{
		{name: "unit name", network: "mainnet", ref: "gousd", want: 672913181},
		{name: "asset name", network: "mainnet", ref: "AKITA INU", want: 523683256},
		{name: "explicit alias", network: "mainnet", ref: "akita", want: 523683256},
		{name: "alias without metadata", network: "mainnet", ref: "gard", want: 684649988},
		{name: "testnet unit", network: "testnet", ref: "USDC", want: 10458941},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok, err := ResolveReference(tt.network, tt.ref)
			if err != nil || !ok || got != tt.want {
				t.Fatalf("ResolveReference(%s, %s) = (%d, %v, %v), want (%d, true, nil)", tt.network, tt.ref, got, ok, err, tt.want)
			}
		})
	}
}

func TestResolveReferenceUnknown(t *testing.T) {
	if got, ok, err := ResolveReference("mainnet", "not-a-token"); err != nil || ok || got != 0 {
		t.Fatalf("ResolveReference(unknown) = (%d, %v, %v), want (0, false, nil)", got, ok, err)
	}
}
