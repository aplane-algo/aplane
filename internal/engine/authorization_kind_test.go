// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The client takes a key's authorization kind from the authorization_kind
// the signer lists on /keys. A key it lists with no kind, or with one this
// client does not know, signs nothing here: BuildSigningContext refuses it and
// canSignFor reports it as not signable, whatever its key type.
func TestAuthorizationKindIsTheSignersReport(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     signerapi.KeyInfo
		want    algorithm.AuthorizationKind // "" means refused
		canSign bool
	}{
		{"ed25519", signerapi.KeyInfo{KeyType: "ed25519", AuthorizationKind: "ed25519"}, algorithm.AuthorizationEd25519, true},
		{"native Falcon", signerapi.KeyInfo{KeyType: "falcon1024", AuthorizationKind: "native_pq"}, algorithm.AuthorizationNativePQ, true},
		{"Falcon LogicSig", signerapi.KeyInfo{KeyType: "aplane.falcon1024.v1", AuthorizationKind: "logic_sig"}, algorithm.AuthorizationLogicSig, true},
		{"generic LogicSig", signerapi.KeyInfo{KeyType: "aplane.htlc.v1", AuthorizationKind: "logic_sig", IsGenericLsig: true}, algorithm.AuthorizationLogicSig, true},
		{"an unregistered type the signer reports", signerapi.KeyInfo{KeyType: "example.unregistered.v1", AuthorizationKind: "logic_sig"}, algorithm.AuthorizationLogicSig, true},
		{"a witness key", signerapi.KeyInfo{KeyType: "aplane.witness-falcon1024.v1", IsWitnessKey: true}, "", false},
		{"an unregistered type with no kind", signerapi.KeyInfo{KeyType: "example.unregistered.v1"}, "", false},
		{"a kind this client does not know", signerapi.KeyInfo{KeyType: "ed25519", AuthorizationKind: "quantum_magic"}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := testAddr(1)
			transport := newAccountMockTransport(t)
			transport.addAccount(addr, 1_000_000)
			eng := setupEngineWithMockAlgod(t, transport)
			key := tc.key
			key.Address = addr
			if err := eng.populateSignerCache([]signerapi.KeyInfo{key}); err != nil {
				t.Fatalf("populateSignerCache() error = %v", err)
			}

			signingCtx, err := eng.BuildSigningContext(context.Background(), addr)
			switch {
			case tc.want == "" && !errors.Is(err, ErrNoSigningKey):
				t.Errorf("BuildSigningContext() = %+v, %v; want ErrNoSigningKey", signingCtx, err)
			case tc.want != "" && (err != nil || signingCtx.AuthorizationKind != tc.want):
				t.Errorf("BuildSigningContext() = %+v, %v; want kind %q", signingCtx, err, tc.want)
			}
			if canSign, kind := eng.CanSignForAddressWithKind(addr); canSign != tc.canSign || kind != tc.want {
				t.Errorf("CanSignForAddressWithKind() = %v, %q; want %v, %q", canSign, kind, tc.canSign, tc.want)
			}
		})
	}
}
