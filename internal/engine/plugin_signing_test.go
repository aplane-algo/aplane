// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestPluginAppCallInfo(t *testing.T) {
	if got := pluginAppCallInfo(types.Transaction{Type: types.PaymentTx}); got != nil {
		t.Fatalf("pluginAppCallInfo(payment) = %#v, want nil", got)
	}

	got := pluginAppCallInfo(types.Transaction{Type: types.ApplicationCallTx})
	if got == nil || got.Mode != "raw" || got.Method != "" {
		t.Fatalf("pluginAppCallInfo(app call) = %#v, want raw mode metadata", got)
	}
}

func TestZeroLocalSignerKeys(t *testing.T) {
	secretA := []byte{1, 2, 3}
	secretB := []byte{4, 5, 6}

	zeroLocalSignerKeys(map[string][]byte{
		"A": secretA,
		"B": secretB,
	})

	for i, b := range secretA {
		if b != 0 {
			t.Fatalf("secretA[%d] = %d, want 0", i, b)
		}
	}
	for i, b := range secretB {
		if b != 0 {
			t.Fatalf("secretB[%d] = %d, want 0", i, b)
		}
	}
}

func TestBuildPluginAssetContextStructuredAssets(t *testing.T) {
	assets := buildPluginAssetContext(map[uint64]cache.ASAInfo{
		20: {Name: "Second Token", UnitName: "DUP", Decimals: 6},
		10: {Name: "USDC", UnitName: "USDC", Decimals: 6},
		30: {Name: "dup", UnitName: "THIRD", Decimals: 2},
	})

	if len(assets) != 3 {
		t.Fatalf("assets len = %d, want 3", len(assets))
	}
	if assets[0].AssetID != 10 || assets[1].AssetID != 20 || assets[2].AssetID != 30 {
		t.Fatalf("assets sorted by ID = %+v", assets)
	}
	if assets[0].Name != "USDC" || assets[0].UnitName != "USDC" || assets[0].Decimals != 6 {
		t.Fatalf("assets[0] = %+v, want structured USDC metadata", assets[0])
	}
}

func TestDecodeGroupSignResponse(t *testing.T) {
	tests := []struct {
		name    string
		signed  []string
		want    int
		wantErr string
	}{
		{
			name:   "valid response",
			signed: []string{"0102", "ff"},
			want:   2,
		},
		{
			name:    "truncated response",
			signed:  []string{"0102"},
			want:    2,
			wantErr: "signer returned 1 signed transaction(s), want 2",
		},
		{
			name:    "padded response",
			signed:  []string{"0102", "ff", "aa"},
			want:    2,
			wantErr: "signer returned 3 signed transaction(s), want 2",
		},
		{
			name:    "empty position",
			signed:  []string{"0102", ""},
			want:    2,
			wantErr: "signer returned no signature for position 2",
		},
		{
			name:    "invalid hex",
			signed:  []string{"zz"},
			want:    1,
			wantErr: "failed to decode signed transaction 1",
		},
		{
			name:   "empty response for empty request",
			signed: nil,
			want:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := decodeGroupSignResponse(tt.signed, tt.want)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(decoded) != tt.want {
				t.Fatalf("decoded %d transactions, want %d", len(decoded), tt.want)
			}
			for i, txn := range decoded {
				expected, _ := hex.DecodeString(tt.signed[i])
				if !bytes.Equal(txn, expected) {
					t.Fatalf("decoded[%d] = %x, want %x", i, txn, expected)
				}
			}
		})
	}
}
