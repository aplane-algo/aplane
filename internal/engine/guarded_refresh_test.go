// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Engine-side guarded wiring tests: refreshSubmitSigningState must bring the
// auth and signer caches current before guarded route selection. The guarded
// choreography itself is tested in internal/engine/guarded.
package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

func testSentryPublicKeyHex(prefix byte) string {
	var publicKey [ed25519.PublicKeySize]byte
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey[:])
}

func TestRefreshSubmitSigningStateDiscoversGuardedAuthorizer(t *testing.T) {
	sender := testAddress(1).String()
	guarded := testAddress(3).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		AuthAddr:   guarded,
		Status:     "Offline",
	})
	transport.addAccount(guarded, 1_000_000)

	staleSignerCache := cache.NewSignerCache()
	staleSignerCache.AddAddress(sender, "ed25519")
	staleSignerCache.AddAddress(guarded, "ed25519")
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, staleSignerCache, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/keys" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
			Count: 2,
			Keys: []signerapi.KeyInfo{{
				Address: sender,
				KeyType: "ed25519",
			}, {
				Address:                guarded,
				KeyType:                keytypes.GuardedFalcon1024SentryEd25519V1,
				SigningFlow:            signerapi.SigningFlowSentry1,
				SentryComponentKeyType: keytypes.SentryComponentEd25519V1,
				LsigSize:               1500,
				Parameters: map[string]string{
					keytypes.ParameterSentryPublicKey: sentryHex,
				},
			}},
		}, req), nil
	})
	eng.AlgodClient = newAccountMockAlgodClient(t, transport)
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded-authorizer", nil).Transaction
	if got := eng.signerCacheKeyType(guarded); got != "ed25519" {
		t.Fatalf("precondition signer cache key type for guarded authorizer = %q, want stale ed25519", got)
	}
	if eng.guardedSigner().HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() before refresh = true, want false with stale caches")
	}

	if err := eng.refreshSubmitSigningState(context.Background(), []types.Transaction{txn}); err != nil {
		t.Fatalf("refreshSubmitSigningState() error = %v", err)
	}

	if auth, ok := eng.AuthCache.GetAuthAddress(sender); !ok || auth != guarded {
		t.Fatalf("auth cache for sender = %q/%v, want %s/true", auth, ok, guarded)
	}
	if got := eng.signerCacheKeyType(guarded); got != keytypes.GuardedFalcon1024SentryEd25519V1 {
		t.Fatalf("signer cache key type for guarded authorizer = %q, want guarded", got)
	}
	if got, ok := eng.signerCacheSentryPublicKey(guarded); !ok || got != sentryHex {
		t.Fatalf("sentry public key for guarded authorizer = %q/%v, want %s/true", got, ok, sentryHex)
	}
	if !eng.guardedSigner().HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() after refresh = false, want true")
	}
}

func TestRefreshSubmitSigningStateRefreshesGuardedKeyMissingFlowMetadata(t *testing.T) {
	sender := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	staleSignerCache := cache.NewSignerCache()
	staleSignerCache.AddAddress(sender, keytypes.GuardedFalcon1024SentryEd25519V1)
	staleSignerCache.SetLsigSize(sender, 1500)

	refreshes := 0
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, staleSignerCache, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/keys" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		refreshes++
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:                sender,
				KeyType:                keytypes.GuardedFalcon1024SentryEd25519V1,
				SigningFlow:            signerapi.SigningFlowSentry1,
				SentryComponentKeyType: keytypes.SentryComponentEd25519V1,
				LsigSize:               1500,
				Parameters: map[string]string{
					keytypes.ParameterSentryPublicKey: sentryHex,
				},
			}},
		}, req), nil
	})
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[sender] = ""

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction
	if eng.guardedSigner().HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() before refresh = true, want false with missing flow metadata")
	}

	if err := eng.refreshSubmitSigningState(context.Background(), []types.Transaction{txn}); err != nil {
		t.Fatalf("refreshSubmitSigningState() error = %v", err)
	}

	if refreshes != 1 {
		t.Fatalf("/keys refreshes = %d, want 1", refreshes)
	}
	if got := eng.signerCacheSigningFlow(sender); got != signerapi.SigningFlowSentry1 {
		t.Fatalf("signing flow = %q, want %q", got, signerapi.SigningFlowSentry1)
	}
	if got, ok := eng.signerCacheSentryPublicKey(sender); !ok || got != sentryHex {
		t.Fatalf("sentry public key = %q/%v, want %s/true", got, ok, sentryHex)
	}
	if !eng.guardedSigner().HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() after refresh = false, want true")
	}
}

func TestRefreshSubmitSigningStateDoesNotRefreshCachedAuthAddress(t *testing.T) {
	sender := testAddress(1).String()
	guarded := testAddress(3).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	transport := newAccountMockTransport(t)
	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, cache.NewSignerCache(), func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/keys" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
			Count: 2,
			Keys: []signerapi.KeyInfo{{
				Address: sender,
				KeyType: "ed25519",
			}, {
				Address:                guarded,
				KeyType:                keytypes.GuardedFalcon1024SentryEd25519V1,
				SigningFlow:            signerapi.SigningFlowSentry1,
				SentryComponentKeyType: keytypes.SentryComponentEd25519V1,
				LsigSize:               1500,
				Parameters: map[string]string{
					keytypes.ParameterSentryPublicKey: sentryHex,
				},
			}},
		}, req), nil
	})
	eng.AlgodClient = newAccountMockAlgodClient(t, transport)
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[sender] = guarded

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "guarded-authorizer", nil).Transaction
	if err := eng.refreshSubmitSigningState(context.Background(), []types.Transaction{txn}); err != nil {
		t.Fatalf("refreshSubmitSigningState() error = %v", err)
	}

	if auth, ok := eng.AuthCache.GetAuthAddress(sender); !ok || auth != guarded {
		t.Fatalf("auth cache for sender = %q/%v, want cached %s/true", auth, ok, guarded)
	}
	if !eng.guardedSigner().HasGuardedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasGuardedEffectiveSigner() after refresh = false, want true")
	}
}
