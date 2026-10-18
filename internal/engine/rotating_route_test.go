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
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestRotatingSenderRoutesOnSendersOwnFlow(t *testing.T) {
	rotating := testAddress(1)
	plain := testAddress(2)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleHybridV1)
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

	if ok, err := eng.rotatingSender([]types.Transaction{spend}, clientsign.SubmitOptions{}); err != nil || !ok {
		t.Fatalf("rotating spend: ok=%v err=%v", ok, err)
	}
	if ok, err := eng.rotatingSender([]types.Transaction{other}, clientsign.SubmitOptions{}); err != nil || ok {
		t.Fatalf("plain spend routed as rotating: ok=%v err=%v", ok, err)
	}
	if _, err := eng.rotatingSender([]types.Transaction{other, spend}, clientsign.SubmitOptions{}); err == nil || !strings.Contains(err.Error(), "alone") {
		t.Fatalf("grouped rotating spend: err=%v", err)
	}
	args := clientsign.SubmitOptions{LsigArgsMap: []map[string][]byte{{"x": {1}}}}
	if _, err := eng.rotatingSender([]types.Transaction{spend}, args); err == nil {
		t.Fatal("LogicSig arguments accepted for a rotating account")
	}
}

func TestBuildSigningContextSignsRotatingAccountAtAnyStage(t *testing.T) {
	rotating := testAddress(1)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleHybridV1)
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
	signerCache.AddAddress(rotating.String(), rotatingkey.RotatingTripleHybridV1)
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
