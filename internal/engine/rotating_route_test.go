// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestRotatingSlotRoutesOnSendersOwnFlow(t *testing.T) {
	rotating := testAddress(1)
	plain := testAddress(2)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleWotsV1)
	signerCache.SetSigningFlowForAddress(rotating.String(), signerapi.SigningFlowRotating1)
	signerCache.AddAddress(plain.String(), "ed25519")
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})
	// The rotating account's authorizer is a stage address the signer never
	// lists; routing must still find the rotating flow.
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[rotating.String()] = testAddress(9).String()

	spend := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: rotating}}
	other := types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: plain}}

	if index, err := eng.rotatingSlot([]types.Transaction{spend}, clientsign.SubmitOptions{}); err != nil || index != 0 {
		t.Fatalf("rotating spend: index=%d err=%v", index, err)
	}
	if index, err := eng.rotatingSlot([]types.Transaction{other}, clientsign.SubmitOptions{}); err != nil || index != -1 {
		t.Fatalf("plain spend routed as rotating: index=%d err=%v", index, err)
	}
	if index, err := eng.rotatingSlot([]types.Transaction{other, spend}, clientsign.SubmitOptions{}); err != nil || index != 1 {
		t.Fatalf("rotating spend grouped with a held account: index=%d err=%v", index, err)
	}
	args := clientsign.SubmitOptions{LsigArgsMap: []map[string][]byte{{"x": {1}}}}
	if _, err := eng.rotatingSlot([]types.Transaction{spend}, args); err == nil {
		t.Fatal("LogicSig arguments accepted for a rotating account")
	}
}

func TestRotatingSlotJudgesOwnedSlotsOnEffectiveAuthority(t *testing.T) {
	rotating := testAddress(1)
	held := testAddress(2)
	rekeyedSender := testAddress(3)
	unheld := testAddress(4)
	otherRotating := testAddress(5)
	bounded := testAddress(6)
	guarded := testAddress(7)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleWotsV1)
	signerCache.SetSigningFlowForAddress(rotating.String(), signerapi.SigningFlowRotating1)
	signerCache.AddAddress(otherRotating.String(), rotatingkey.RotatingTripleXmssV1)
	signerCache.SetSigningFlowForAddress(otherRotating.String(), signerapi.SigningFlowRotating1)
	signerCache.AddAddress(held.String(), "ed25519")
	signerCache.AddAddress(bounded.String(), "ed25519")
	signerCache.SetBoundedMaxFeeForAddress(bounded.String(), 5000)
	signerCache.AddAddress(guarded.String(), keytypes.GuardedFalcon1024Cosigner1024V1)
	signerCache.SetSigningFlowForAddress(guarded.String(), signerapi.SigningFlowCosigner1)
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[rotating.String()] = testAddress(9).String()
	// rekeyedSender has no credential of its own; its authorizer is held.
	eng.AuthCache.AuthAddresses[rekeyedSender.String()] = held.String()

	from := func(a types.Address) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: a}}
	}
	spend := from(rotating)
	if index, err := eng.rotatingSlot([]types.Transaction{from(rekeyedSender), spend}, clientsign.SubmitOptions{}); err != nil || index != 1 {
		t.Fatalf("sender rekeyed to a held key: index=%d err=%v", index, err)
	}
	for name, tc := range map[string]struct {
		txns []types.Transaction
		want string
	}{
		"unheld authority":       {[]types.Transaction{from(unheld), spend}, "not held"},
		"second rotating sender": {[]types.Transaction{spend, from(otherRotating)}, "both from rotating"},
		"bounded authority":      {[]types.Transaction{from(bounded), spend}, "bounded"},
		"guarded authority":      {[]types.Transaction{spend, from(guarded)}, "guarded"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := eng.rotatingSlot(tc.txns, clientsign.SubmitOptions{}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBuildSigningContextSignsRotatingAccountAtAnyStage(t *testing.T) {
	rotating := testAddress(1)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleWotsV1)
	signerCache.SetSigningFlowForAddress(rotating.String(), signerapi.SigningFlowRotating1)
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})
	algodClient, err := algod.MakeClient("http://127.0.0.1:1", "")
	if err != nil {
		t.Fatal(err)
	}
	eng.AlgodClient = algodClient
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	// The chain shows a stage address the signer never lists.
	eng.AuthCache.AuthAddresses[rotating.String()] = testAddress(9).String()

	sc, err := eng.BuildSigningContext(context.Background(), rotating.String())
	if err != nil {
		t.Fatalf("BuildSigningContext: %v", err)
	}
	if sc.SigningAddr != rotating.String() {
		t.Fatalf("signing address = %s, want the rotating account", sc.SigningAddr)
	}
}

func TestRotatingAccountIsSignableAtAnyStage(t *testing.T) {
	rotating := testAddress(1)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleWotsV1)
	signerCache.SetSigningFlowForAddress(rotating.String(), signerapi.SigningFlowRotating1)
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		return nil, nil
	})
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	// The chain shows a stage address the signer never lists; the account
	// must still be listed as signable and as a rotating account.
	eng.AuthCache.AuthAddresses[rotating.String()] = testAddress(9).String()
	if !eng.isSignable(rotating.String()) {
		t.Fatal("rotating account at a later stage reported as not signable")
	}
	accounts := eng.RotatingAccounts()
	if len(accounts) != 1 || accounts[0] != rotating.String() {
		t.Fatalf("RotatingAccounts() = %v, want the rotating account", accounts)
	}
}
