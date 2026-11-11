// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestLsigArgsByDeclaredName(t *testing.T) {
	native := testAddress(1).String()
	htlc := testAddress(2).String()
	bounded := testAddress(3).String()
	rekeyed := testAddress(4).String()
	htlcAuthorizer := testAddress(5).String()

	// The rekeyed sender makes signing refresh the key list, so the cache the
	// arguments are matched against is the one /keys gives: this also checks
	// that a bounded account's runtime arguments are kept as declared names.
	keysCalls := 0
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, cache.NewSignerCache(), func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/keys" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		keysCalls++
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
			Count: 4,
			Keys: []signerapi.KeyInfo{
				{Address: native, KeyType: "ed25519"},
				{Address: htlc, KeyType: "aplane.htlc.v1", IsGenericLsig: true,
					SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}}},
				{Address: bounded, KeyType: "example.bounded-hashlock.v1",
					BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
						Contract:    signerapi.BoundedContractBounded2,
						RuntimeArgs: []signerapi.RuntimeArgInfo{{Name: "secret", Type: "bytes", Required: true}},
					}},
				{Address: htlcAuthorizer, KeyType: "aplane.htlc.v1", IsGenericLsig: true,
					SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}}},
			},
		}, req), nil
	})
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	for _, sender := range []string{native, htlc, bounded} {
		eng.AuthCache.AuthAddresses[sender] = ""
	}
	eng.AuthCache.AuthAddresses[rekeyed] = htlcAuthorizer

	// The fourth position is a plugin-signed slot: apsigner does not sign it.
	senders := []string{native, htlc, bounded, "", rekeyed}
	args := map[string][]byte{"preimage": []byte("open"), "secret": []byte("s")}
	perPosition, err := eng.LsigArgsByDeclaredName(context.Background(), senders, args)
	if err != nil {
		t.Fatalf("LsigArgsByDeclaredName() error = %v", err)
	}
	if keysCalls != 1 {
		t.Fatalf("/keys calls = %d, want the one refresh signing makes for a rekeyed sender", keysCalls)
	}
	want := []map[string]string{
		nil,                  // a native key declares no arguments
		{"preimage": "open"}, // only what the template declares
		{"secret": "s"},      // a bounded account's runtime argument
		nil,                  // not signed here
		{"preimage": "open"}, // matched on the effective signer's key
	}
	if len(perPosition) != len(want) {
		t.Fatalf("got %d positions, want %d", len(perPosition), len(want))
	}
	for i := range want {
		if len(perPosition[i]) != len(want[i]) {
			t.Fatalf("position %d = %q, want %q", i, perPosition[i], want[i])
		}
		for name, value := range want[i] {
			if string(perPosition[i][name]) != value {
				t.Fatalf("position %d %s = %q, want %q", i, name, perPosition[i][name], value)
			}
		}
	}

	t.Run("a name no key declares is refused", func(t *testing.T) {
		_, err := eng.LsigArgsByDeclaredName(context.Background(), senders, map[string][]byte{
			"preimage": []byte("open"), "preimge": []byte("typo"), "other": {1},
		})
		if err == nil || !strings.Contains(err.Error(), "arg:other, arg:preimge: no transaction here is signed by a key that declares") {
			t.Fatalf("error = %v, want both undeclared names refused", err)
		}
	})
	t.Run("a native key alone declares nothing", func(t *testing.T) {
		_, err := eng.LsigArgsByDeclaredName(context.Background(), []string{native}, map[string][]byte{"preimage": []byte("open")})
		if err == nil || !strings.Contains(err.Error(), "arg:preimage") {
			t.Fatalf("error = %v, want the argument refused", err)
		}
	})
	t.Run("no arguments needs no signer", func(t *testing.T) {
		disconnected, err := NewEngine("testnet")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := disconnected.LsigArgsByDeclaredName(context.Background(), senders, nil); err != nil || got != nil {
			t.Fatalf("LsigArgsByDeclaredName(nil) = %v, %v; want nil, nil", got, err)
		}
		if _, err := disconnected.LsigArgsByDeclaredName(context.Background(), senders, args); !errors.Is(err, ErrNotConnected) {
			t.Fatalf("error = %v, want ErrNotConnected", err)
		}
	})
}
