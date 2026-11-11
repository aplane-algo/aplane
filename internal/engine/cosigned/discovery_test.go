// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cosigned

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// Routing matches a component key on key type and public key together, so a
// public key advertised under two key types is two keys, and only an exact
// repeat collapses.
func TestDiscoverCosignerComponentKeysKeepsEachKeyTypeOfOnePublicKey(t *testing.T) {
	publicKey := strings.Repeat("ab", 32)
	advertise := func(keyType string) signerapi.KeyInfo {
		raw, err := hex.DecodeString(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		return signerapi.KeyInfo{Address: witness.DeriveID(keyType, raw), PublicKeyHex: publicKey, KeyType: keyType, IsWitnessKey: true}
	}
	const otherType = "example.witness-other.v1"
	discovered, err := discoverCosignerComponentKeys([]signerapi.KeyInfo{
		advertise(witness.Falcon1024V1), advertise(otherType), advertise(witness.Falcon1024V1),
	})
	if err != nil {
		t.Fatalf("discoverCosignerComponentKeys() error = %v", err)
	}
	if len(discovered) != 2 {
		t.Fatalf("discovered %d keys, want one per key type: %+v", len(discovered), discovered)
	}
	for _, required := range []cosignerRequestKey{
		{ComponentKeyType: witness.Falcon1024V1, PublicKey: publicKey},
		{ComponentKeyType: otherType, PublicKey: publicKey},
	} {
		if !discoveredCosignerKeysContain(discovered, required) {
			t.Errorf("no route for %+v in %+v", required, discovered)
		}
	}
}

func TestClassifyCosignerDiscoveryQueryErrorUsesWireCodeBeforeStatus(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		code       string
		want       error
	}{
		{
			name:       "locked 403 is locked not auth",
			statusCode: http.StatusForbidden,
			code:       signerapi.ErrCodeLocked,
			want:       ErrCosignerDiscoveryLocked,
		},
		{
			name:       "cache refresh 500 is unavailable",
			statusCode: http.StatusInternalServerError,
			code:       signerapi.ErrCodeCacheRefresh,
			want:       ErrCosignerDiscoveryUnavailable,
		},
		{
			name:       "bad request 500 is config by code",
			statusCode: http.StatusInternalServerError,
			code:       signerapi.ErrCodeBadRequest,
			want:       ErrCosignerDiscoveryConfig,
		},
		{
			name:       "old forbidden response falls back to auth",
			statusCode: http.StatusForbidden,
			want:       ErrCosignerDiscoveryAuth,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := classifyCosignerDiscoveryQueryError(&signerclient.HTTPStatusError{
				StatusCode: tt.statusCode,
				Code:       tt.code,
				Message:    tt.name,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("classifyCosignerDiscoveryQueryError() = %v, want %v", err, tt.want)
			}
		})
	}
}
