// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The accounts of the placement table. A rekeyed account's own key, when it
// has one, is not the key that signs for it.
var (
	argNative          = testAddress(1).String() // ed25519
	argNativeFalcon    = testAddress(2).String() // native Falcon
	argHTLC            = testAddress(3).String() // generic LogicSig: preimage, optional, up to 64 bytes
	argComposed        = testAddress(4).String() // composed DSA LogicSig: secret, required, 4 bytes
	argBounded         = testAddress(5).String() // bounded account: runtime argument memo
	argNativeToHTLC    = testAddress(6).String() // an ed25519 account rekeyed to argHTLC2
	argHTLC2           = testAddress(7).String() // a second HTLC account
	argHTLCToNative    = testAddress(8).String() // an HTLC account rekeyed to argNative
	argRotating        = testAddress(9).String() // a rotating account, at a stage address
	argRotatingStage   = testAddress(10).String()
	argNewHTLC         = testAddress(11).String() // an HTLC account the cache does not have yet
	argBoundedNoArgs   = testAddress(12).String() // a bounded account with no runtime arguments
	argPluginPositions = ""                       // a position a plugin signs
)

func htlcKeyInfo(address string) signerapi.KeyInfo {
	return signerapi.KeyInfo{Address: address, KeyType: "aplane.htlc.v1", IsGenericLsig: true,
		SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", MaxSize: 64}}}
}

func placementTableKeys() []signerapi.KeyInfo {
	return []signerapi.KeyInfo{
		{Address: argNative, KeyType: "ed25519"},
		{Address: argNativeFalcon, KeyType: nativefalcon.KeyType},
		htlcKeyInfo(argHTLC),
		{Address: argComposed, KeyType: "example.falcon1024-hashlock.v1",
			SigningArgs: []signerapi.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true, ByteLength: 4}}},
		{Address: argBounded, KeyType: "aplane.falcon1024.v1",
			BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
				Contract: signerapi.BoundedContractBounded2,
				// Required on some path; the client keeps it optional and
				// the signer judges the path.
				RuntimeArgs: []signerapi.RuntimeArgInfo{{Name: "memo", Type: "bytes", Required: true, MaxSize: 32}},
			}},
		{Address: argBoundedNoArgs, KeyType: "aplane.falcon1024.v1",
			BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{Contract: signerapi.BoundedContractBounded2, RuntimeArgs: []signerapi.RuntimeArgInfo{}}},
		htlcKeyInfo(argHTLC2),
		htlcKeyInfo(argHTLCToNative),
		{Address: argRotating, KeyType: rotatingkey.RotatingTripleWotscV1, SigningFlow: signerapi.SigningFlowRotating1},
	}
}

// newPlacementEngine is an engine whose signer cache holds the table's keys,
// as /keys reported them, and whose auth cache knows every table account.
// Its signer answers /keys with refreshed, and counts the fetches.
func newPlacementEngine(t *testing.T, cached, refreshed []signerapi.KeyInfo) (*Engine, *atomic.Int32) {
	t.Helper()
	var keyFetches atomic.Int32
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, cache.NewSignerCache(), func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/keys" {
			t.Fatalf("unexpected signer request: %s %s", req.Method, req.URL.Path)
		}
		keyFetches.Add(1)
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{Count: len(refreshed), Keys: refreshed}, req), nil
	})
	if err := eng.PopulateSignerCache(cached); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	for _, address := range []string{argNative, argNativeFalcon, argHTLC, argComposed, argBounded, argBoundedNoArgs, argHTLC2, argNewHTLC} {
		eng.AuthCache.AuthAddresses[address] = ""
	}
	eng.AuthCache.AuthAddresses[argNativeToHTLC] = argHTLC2
	eng.AuthCache.AuthAddresses[argHTLCToNative] = argNative
	eng.AuthCache.AuthAddresses[argRotating] = argRotatingStage
	return eng, &keyFetches
}

func argValues(pairs ...string) map[string][]byte {
	values := make(map[string][]byte, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		values[pairs[i]] = []byte(pairs[i+1])
	}
	return values
}

// placeLsigArgs is the one placement: each position gets the arguments its
// effective signer's key declares, a native key gets none, a name no
// position declares is refused (after one fetch of the key list, which may be
// stale), and each position is checked against its key's declarations.
func TestPlaceLsigArgs(t *testing.T) {
	stale := func() []signerapi.KeyInfo { return placementTableKeys() }
	withNew := func() []signerapi.KeyInfo { return append(placementTableKeys(), htlcKeyInfo(argNewHTLC)) }
	for _, tc := range []struct {
		name       string
		senders    []string
		values     map[string][]byte
		keysFresh  bool
		refreshed  []signerapi.KeyInfo // what /keys answers; the cache holds the table's keys
		want       []map[string][]byte
		undeclared []string // the names refused, with the names declared
		declared   []string
		wantErr    string // another refusal
		keyFetches int32
	}{
		{
			name: "a native key alone declares nothing", senders: []string{argNative}, values: argValues("preimage", "open"),
			undeclared: []string{"preimage"}, declared: []string{}, keyFetches: 1,
		},
		{
			name: "a native Falcon key alone declares nothing", senders: []string{argNativeFalcon}, values: argValues("preimage", "open"),
			undeclared: []string{"preimage"}, declared: []string{}, keyFetches: 1,
		},
		{
			name: "a native key with no arguments", senders: []string{argNative, argNativeFalcon}, values: nil,
			want: []map[string][]byte{nil, nil},
		},
		{
			name: "a generic LogicSig gets what it declares", senders: []string{argHTLC}, values: argValues("preimage", "open"),
			want: []map[string][]byte{argValues("preimage", "open")},
		},
		{
			name: "a generic LogicSig's optional argument may be left out", senders: []string{argHTLC}, values: nil,
			want: []map[string][]byte{nil},
		},
		{
			name: "a composed LogicSig gets what it declares", senders: []string{argComposed}, values: argValues("secret", "abcd"),
			want: []map[string][]byte{argValues("secret", "abcd")},
		},
		{
			name: "a composed LogicSig's required argument left out", senders: []string{argComposed}, values: nil,
			wantErr: "transaction 1: invalid LogicSig arguments: missing required argument: secret",
		},
		{
			name: "a value of the wrong declared length", senders: []string{argHTLC, argComposed}, values: argValues("secret", "abc"),
			wantErr: "transaction 2: invalid LogicSig arguments: argument 'secret': expected 4 bytes, got 3",
		},
		{
			name: "a bounded account gets its runtime argument", senders: []string{argBounded}, values: argValues("memo", "m"),
			want: []map[string][]byte{argValues("memo", "m")},
		},
		{
			name: "a bounded account's runtime argument is optional on the client", senders: []string{argBounded}, values: nil,
			want: []map[string][]byte{nil},
		},
		{
			name: "a bounded account with no runtime arguments declares nothing", senders: []string{argBoundedNoArgs}, values: argValues("memo", "m"),
			undeclared: []string{"memo"}, declared: []string{}, keyFetches: 1,
		},
		{
			name: "an account rekeyed to a LogicSig gets its authorizer's", senders: []string{argNativeToHTLC}, values: argValues("preimage", "open"),
			want: []map[string][]byte{argValues("preimage", "open")},
		},
		{
			name: "a LogicSig account rekeyed to a native key gets none", senders: []string{argHTLCToNative, argHTLC}, values: argValues("preimage", "open"),
			want: []map[string][]byte{nil, argValues("preimage", "open")},
		},
		{
			name: "a LogicSig account rekeyed to a native key, alone", senders: []string{argHTLCToNative}, values: argValues("preimage", "open"),
			undeclared: []string{"preimage"}, declared: []string{}, keyFetches: 1,
		},
		{
			name:    "a mixed group: each position gets its own",
			senders: []string{argNative, argHTLC, argComposed, argBounded, argNativeFalcon, argPluginPositions, argNativeToHTLC},
			values:  argValues("preimage", "open", "secret", "abcd", "memo", "m"),
			want: []map[string][]byte{
				nil, argValues("preimage", "open"), argValues("secret", "abcd"), argValues("memo", "m"), nil, nil, argValues("preimage", "open"),
			},
		},
		{
			name: "a position a plugin signs declares nothing", senders: []string{argPluginPositions, argNative}, values: argValues("preimage", "open"),
			undeclared: []string{"preimage"}, declared: []string{}, keyFetches: 1,
		},
		{
			name: "a typo is refused, naming what is declared", senders: []string{argNative, argHTLC, argBounded}, values: argValues("premage", "open"),
			undeclared: []string{"premage"}, declared: []string{"memo", "preimage"}, keyFetches: 1,
		},
		{
			name: "a typo beside a good name is refused", senders: []string{argHTLC}, values: argValues("preimage", "open", "premage", "open"),
			undeclared: []string{"premage"}, declared: []string{"preimage"}, keyFetches: 1,
		},
		{
			name: "a rotating account declares nothing", senders: []string{argRotating}, values: argValues("x", "1"),
			undeclared: []string{"x"}, declared: []string{}, keyFetches: 1,
		},
		{
			name: "a stale cache: fetched again, then accepted", senders: []string{argNewHTLC}, values: argValues("preimage", "open"),
			refreshed: withNew(), want: []map[string][]byte{argValues("preimage", "open")}, keyFetches: 1,
		},
		{
			name: "a stale cache: fetched again, then refused", senders: []string{argNewHTLC}, values: argValues("preimage", "open"),
			refreshed: stale(), undeclared: []string{"preimage"}, declared: []string{}, keyFetches: 1,
		},
		{
			name: "a key list fetched for this submission is not fetched again", senders: []string{argNewHTLC}, values: argValues("preimage", "open"),
			keysFresh: true, refreshed: withNew(), undeclared: []string{"preimage"}, declared: []string{}, keyFetches: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refreshed := tc.refreshed
			if refreshed == nil {
				refreshed = placementTableKeys()
			}
			eng, keyFetches := newPlacementEngine(t, placementTableKeys(), refreshed)
			placed, err := eng.placeLsigArgs(context.Background(), tc.senders, NewLsigArgs(tc.values), tc.keysFresh)
			if got := keyFetches.Load(); got != tc.keyFetches {
				t.Fatalf("/keys fetches = %d, want %d", got, tc.keyFetches)
			}
			switch {
			case tc.undeclared != nil:
				var undeclared *UndeclaredLsigArgsError
				if !errors.As(err, &undeclared) {
					t.Fatalf("error = %v, want the names refused", err)
				}
				if !reflect.DeepEqual(undeclared.Names, tc.undeclared) || !reflect.DeepEqual(append([]string{}, undeclared.Declared...), tc.declared) {
					t.Fatalf("refused %q (declared %q), want %q (declared %q)", undeclared.Names, undeclared.Declared, tc.undeclared, tc.declared)
				}
			case tc.wantErr != "":
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("placeLsigArgs() error = %v", err)
				}
				if !reflect.DeepEqual(placed, tc.want) {
					t.Fatalf("placed = %q, want %q", placed, tc.want)
				}
			}
		})
	}
}

func TestUndeclaredLsigArgsErrorWording(t *testing.T) {
	for _, tc := range []struct {
		err  UndeclaredLsigArgsError
		want string
	}{
		{UndeclaredLsigArgsError{Names: []string{"premage"}, Declared: []string{"preimage"}},
			`no signing key here declares the LogicSig argument "premage"; they declare "preimage"`},
		{UndeclaredLsigArgsError{Names: []string{"a", "b"}},
			`no signing key here declares the LogicSig arguments "a", "b"; they declare no arguments`},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Fatalf("Error() = %q, want %q", got, tc.want)
		}
	}
}

// A refusal that needed the key list fetched again says so when the fetch
// failed, and keeps the refusal's type.
func TestPlaceLsigArgsReportsAFailedFetch(t *testing.T) {
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, cache.NewSignerCache(), func(req *http.Request) (*http.Response, error) {
		return keyMgmtTextResponse(http.StatusServiceUnavailable, "down", req), nil
	})
	if err := eng.PopulateSignerCache(placementTableKeys()); err != nil {
		t.Fatal(err)
	}
	_, err := eng.placeLsigArgs(context.Background(), []string{argNative}, NewLsigArgs(argValues("preimage", "x")), false)
	var undeclared *UndeclaredLsigArgsError
	if !errors.As(err, &undeclared) || !strings.Contains(err.Error(), "fetching the signer's key list to look again failed") {
		t.Fatalf("error = %v, want the refusal and the failed fetch", err)
	}
}

// A command that makes one submission per item checks the names once against
// every item's account. Each item's submission then takes what its own key
// declares and refuses nothing; a single item is one submission, and refuses
// at its own signing.
func TestLsigArgsForItems(t *testing.T) {
	eng, keyFetches := newPlacementEngine(t, placementTableKeys(), placementTableKeys())
	ctx := context.Background()

	args, err := eng.LsigArgsForItems(ctx, []string{argNative, argHTLC, argNativeFalcon}, argValues("preimage", "open"))
	if err != nil {
		t.Fatalf("LsigArgsForItems() error = %v", err)
	}
	for _, tc := range []struct {
		sender string
		want   []map[string][]byte
	}{
		{argNative, []map[string][]byte{nil}},
		{argHTLC, []map[string][]byte{argValues("preimage", "open")}},
		{argNativeFalcon, []map[string][]byte{nil}},
	} {
		placed, err := eng.placeLsigArgs(ctx, []string{tc.sender}, args, false)
		if err != nil || !reflect.DeepEqual(placed, tc.want) {
			t.Fatalf("item %s: placed = %q, %v; want %q", tc.sender, placed, err, tc.want)
		}
	}
	if got := keyFetches.Load(); got != 0 {
		t.Fatalf("/keys fetches = %d, want none: every name was declared", got)
	}

	// A name no item's account declares is refused up front, after one fetch.
	_, err = eng.LsigArgsForItems(ctx, []string{argNative, argHTLC}, argValues("premage", "open"))
	var undeclared *UndeclaredLsigArgsError
	if !errors.As(err, &undeclared) || !reflect.DeepEqual(undeclared.Names, []string{"premage"}) {
		t.Fatalf("LsigArgsForItems(typo) error = %v, want it refused", err)
	}
	if got := keyFetches.Load(); got != 1 {
		t.Fatalf("/keys fetches = %d, want 1", got)
	}

	// One item: no check here, and its submission refuses.
	single, err := eng.LsigArgsForItems(ctx, []string{argNative}, argValues("preimage", "open"))
	if err != nil {
		t.Fatalf("LsigArgsForItems(one item) error = %v", err)
	}
	if _, err := eng.placeLsigArgs(ctx, []string{argNative}, single, false); !errors.As(err, &undeclared) {
		t.Fatalf("one item's submission: error = %v, want the name refused", err)
	}
	// No arguments: nothing to check.
	if none, err := eng.LsigArgsForItems(ctx, []string{argNative, argHTLC}, nil); err != nil || none.Len() != 0 {
		t.Fatalf("LsigArgsForItems(nil) = %+v, %v", none, err)
	}
}
