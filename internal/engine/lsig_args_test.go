// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
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
		var undeclared *UndeclaredLsigArgsError
		if !errors.As(err, &undeclared) || strings.Join(undeclared.Names, ",") != "other,preimge" {
			t.Fatalf("error = %v, want both undeclared names refused", err)
		}
		if strings.Contains(err.Error(), "arg:") || strings.Contains(err.Error(), "keys refresh") {
			t.Fatalf("error = %q, want no shell syntax in the engine's wording", err)
		}
	})
	t.Run("a native key alone declares nothing", func(t *testing.T) {
		_, err := eng.LsigArgsByDeclaredName(context.Background(), []string{native}, map[string][]byte{"preimage": []byte("open")})
		var undeclared *UndeclaredLsigArgsError
		if !errors.As(err, &undeclared) || len(undeclared.Names) != 1 || undeclared.Names[0] != "preimage" {
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
		// A set command indexes the result by account, arguments or not.
		if shares, err := disconnected.ShareLsigArgsByDeclaredName(context.Background(), senders, nil); err != nil || len(shares) != len(senders) {
			t.Fatalf("ShareLsigArgsByDeclaredName(nil) = %v, %v; want %d empty shares", shares, err, len(senders))
		}
	})
}

// One account's failed lookup fails that account alone: a set command goes
// on with the others, each given what its key declares. A plugin group, which
// is signed as one, fails. A name no key that was looked up declares is still
// refused, so it is never dropped for the accounts that go on.
func TestShareLsigArgsByDeclaredNameKeepsALookupFailureToItsAccount(t *testing.T) {
	htlc := testAddress(1).String()
	unknown := testAddress(2).String() // its auth address cannot be fetched
	rekeyed := testAddress(3).String() // rekeyed to a key the client lacks
	authorizer := testAddress(4).String()
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(htlc, "aplane.htlc.v1")
	signerCache.SetGenericLsig(htlc, true)
	signerCache.SetSigningArgs(htlc, []cache.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}})
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/keys" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtTextResponse(http.StatusServiceUnavailable, "down", req), nil
	})
	// No algod client: an auth address not in the cache cannot be fetched.
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[htlc] = ""
	eng.AuthCache.AuthAddresses[rekeyed] = authorizer

	senders := []string{htlc, unknown, rekeyed}
	args := map[string][]byte{"preimage": []byte("open")}
	shares, err := eng.ShareLsigArgsByDeclaredName(context.Background(), senders, args)
	if err != nil {
		t.Fatalf("ShareLsigArgsByDeclaredName() error = %v, want each failure kept to its account", err)
	}
	if len(shares) != 3 || shares[0].Err != nil || len(shares[0].Args) != 1 || string(shares[0].Args["preimage"]) != "open" {
		t.Fatalf("shares = %+v, want the HTLC given its preimage", shares)
	}
	if shares[1].Err == nil || !strings.Contains(shares[1].Err.Error(), "failed to refresh auth address for "+unknown) || shares[1].Args != nil {
		t.Fatalf("unknown account share = %+v, want its auth address lookup failure and no arguments", shares[1])
	}
	if shares[2].Err == nil || !strings.Contains(shares[2].Err.Error(), "failed to refresh signer keys") || shares[2].Args != nil {
		t.Fatalf("rekeyed account share = %+v, want the key list failure and no arguments", shares[2])
	}

	if _, err := eng.LsigArgsByDeclaredName(context.Background(), senders, args); err == nil ||
		!strings.Contains(err.Error(), "failed to refresh auth address for "+unknown) {
		t.Fatalf("LsigArgsByDeclaredName() error = %v, want the group failed by the first lookup failure", err)
	}

	// "preimge" is declared by no key that could be looked up. The two that
	// could not might declare it, but the HTLC would sign without it, so the
	// whole command is refused, saying a retry may differ.
	typo := map[string][]byte{"preimage": []byte("open"), "preimge": []byte("typo")}
	for name, share := range map[string]func() error{
		"ShareLsigArgsByDeclaredName": func() error {
			_, err := eng.ShareLsigArgsByDeclaredName(context.Background(), senders, typo)
			return err
		},
		"LsigArgsByDeclaredName": func() error {
			_, err := eng.LsigArgsByDeclaredName(context.Background(), senders, typo)
			return err
		},
	} {
		err := share()
		var undeclared *UndeclaredLsigArgsError
		if !errors.As(err, &undeclared) || strings.Join(undeclared.Names, ",") != "preimge" || undeclared.Unresolved != 2 {
			t.Fatalf("%s() error = %#v, want preimge refused with 2 accounts not looked up", name, err)
		}
		want := `none of the signing keys that could be looked up declares the LogicSig argument "preimge", so it would not be sent; 2 accounts could not be looked up`
		if err.Error() != want {
			t.Fatalf("%s() error = %q, want %q", name, err, want)
		}
	}
}

// The client checks a transaction's LogicSig arguments against the key that
// signs it, the effective signer, once the signing state is refreshed: a
// native key takes none, and a rekeyed account takes what its auth address's
// key declares, not what its own does.
func TestValidateSubmitLsigArgsChecksTheEffectiveSignersKey(t *testing.T) {
	nativefalcon.RegisterClient() // as apshell registers it
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatal(err)
	}
	native := testAddress(1).String()
	falcon := testAddress(2).String()
	htlc := testAddress(3).String()
	lsigToNative := testAddress(4).String()
	boundedToHTLC := testAddress(5).String()
	unheld := testAddress(6).String()
	composed := testAddress(7).String()
	bounded := testAddress(8).String()
	eng.SignerCache.AddAddress(native, "ed25519")
	eng.SignerCache.AddAddress(falcon, nativefalcon.KeyType)
	eng.SignerCache.AddAddress(htlc, "aplane.htlc.v1")
	eng.SignerCache.SetGenericLsig(htlc, true)
	eng.SignerCache.SetSigningArgs(htlc, []cache.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}})
	// A generic LogicSig whose own required argument is "secret", rekeyed to
	// the native key.
	eng.SignerCache.AddAddress(lsigToNative, "aplane.htlc.v1")
	eng.SignerCache.SetGenericLsig(lsigToNative, true)
	eng.SignerCache.SetSigningArgs(lsigToNative, []cache.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true}})
	// A bounded account whose own runtime argument is "x", rekeyed to the HTLC.
	eng.SignerCache.AddAddress(boundedToHTLC, "example.bounded-hashlock.v1")
	eng.SignerCache.SetSigningArgs(boundedToHTLC, []cache.SigningArgInfo{{Name: "x", Type: "bytes"}})
	// A composed (DSA) LogicSig, not a generic one, whose template requires
	// "secret".
	eng.SignerCache.AddAddress(composed, "example.composed-hashlock.v1")
	eng.SignerCache.SetSigningArgs(composed, []cache.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true}})
	// A bounded account's runtime arguments are cached as optional.
	eng.SignerCache.AddAddress(bounded, "example.bounded-hashlock.v1")
	eng.SignerCache.SetSigningArgs(bounded, []cache.SigningArgInfo{{Name: "x", Type: "bytes"}})
	eng.AuthCache = cache.NewAuthAddressCache()
	eng.AuthCache.AuthAddresses[lsigToNative] = native
	eng.AuthCache.AuthAddresses[boundedToHTLC] = htlc

	preimage := map[string][]byte{"preimage": []byte("open")}
	for name, tc := range map[string]struct {
		sender string
		args   map[string][]byte
		want   string
	}{
		"ed25519 key with args":                  {native, preimage, "transaction 1: invalid LogicSig arguments: the ed25519 key of " + native + " is not a LogicSig and takes no arguments"},
		"native Falcon key with args":            {falcon, preimage, "the falcon1024 key of " + falcon + " is not a LogicSig"},
		"native key, no args":                    {native, nil, ""},
		"native key, empty args":                 {native, map[string][]byte{}, ""},
		"LogicSig with its argument":             {htlc, preimage, ""},
		"LogicSig missing its argument":          {htlc, nil, "missing required argument: preimage"},
		"LogicSig rekeyed to a native key":       {lsigToNative, nil, ""},
		"LogicSig rekeyed to a native, args":     {lsigToNative, map[string][]byte{"secret": {1}}, "the ed25519 key of " + native + " is not a LogicSig"},
		"bounded rekeyed to a LogicSig":          {boundedToHTLC, preimage, ""},
		"bounded rekeyed, its own argument":      {boundedToHTLC, map[string][]byte{"x": {1}, "preimage": {2}}, "unknown argument 'x'"},
		"bounded rekeyed, the LogicSig missing":  {boundedToHTLC, nil, "missing required argument: preimage"},
		"key the client lacks":                   {unheld, preimage, ""},
		"composed LogicSig missing its argument": {composed, nil, "missing required argument: secret"},
		"composed LogicSig with its argument":    {composed, map[string][]byte{"secret": {1}}, ""},
		"bounded spend, no arguments":            {bounded, nil, ""},
		"bounded spend, its argument":            {bounded, map[string][]byte{"x": {1}}, ""},
	} {
		sender, err := types.DecodeAddress(tc.sender)
		if err != nil {
			t.Fatal(err)
		}
		err = eng.validateSubmitLsigArgs([]types.Transaction{{Header: types.Header{Sender: sender}}}, []map[string][]byte{tc.args})
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: error = %v, want none", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: error = %v, want %q", name, err, tc.want)
		}
	}
}

// Signing a group fetches by the same rule, and fails with the failure of the
// first sender, in transaction order, that has one.
func TestRefreshSubmitSigningStateReturnsTheFirstSendersFailure(t *testing.T) {
	unknown := testAddress(1) // its auth address cannot be fetched
	rekeyed := testAddress(2) // rekeyed to a key the client lacks
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, cache.NewSignerCache(), func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/keys" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtTextResponse(http.StatusServiceUnavailable, "down", req), nil
	})
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[rekeyed.String()] = testAddress(3).String()

	from := func(senders ...types.Address) []types.Transaction {
		txns := make([]types.Transaction, len(senders))
		for i, sender := range senders {
			txns[i].Sender = sender
		}
		return txns
	}
	for _, tc := range []struct {
		txns []types.Transaction
		want string
	}{
		{from(rekeyed, unknown), "failed to refresh signer keys"},
		{from(unknown, rekeyed), "failed to refresh auth address for " + unknown.String()},
	} {
		if err := eng.refreshSubmitSigningState(context.Background(), tc.txns); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Fatalf("refreshSubmitSigningState() error = %v, want %q", err, tc.want)
		}
	}
}
