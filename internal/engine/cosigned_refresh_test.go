// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Engine-side cosigned wiring tests: refreshSubmitSigningState must bring the
// auth and signer caches current before cosigned route selection. The cosigned
// choreography itself is tested in internal/engine/cosigned.
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
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func testCosignerPublicKeyHex(prefix byte) string {
	var publicKey [ed25519.PublicKeySize]byte
	publicKey[0] = prefix
	return hex.EncodeToString(publicKey[:])
}

func TestRefreshSubmitSigningStateDiscoversCosignedAuthorizer(t *testing.T) {
	sender := testAddress(1).String()
	cosigned := testAddress(3).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		AuthAddr:   cosigned,
		Status:     "Offline",
	})
	transport.addAccount(cosigned, 1_000_000)

	staleSignerCache := cache.NewSignerCache()
	staleSignerCache.AddAddress(sender, "ed25519")
	staleSignerCache.AddAddress(cosigned, "ed25519")
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
				Address:                  cosigned,
				KeyType:                  "aplane.falcon1024.v1",
				SigningFlow:              signerapi.SigningFlowCosigned1,
				CosignerComponentKeyType: witness.Falcon1024V1,
				LogicSigResources:        testPublicLogicSigProfile(1_500),
				BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
					Contract: signerapi.BoundedContractPlain1,
					Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: cosignerHex},
				},
			}},
		}, req), nil
	})
	eng.AlgodClient = newAccountMockAlgodClient(t, transport)
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "cosigned-authorizer", nil).Transaction
	if got := eng.signerCacheKeyType(cosigned); got != "ed25519" {
		t.Fatalf("precondition signer cache key type for cosigned authorizer = %q, want stale ed25519", got)
	}
	if eng.cosignedSigner().HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() before refresh = true, want false with stale caches")
	}

	if err := eng.refreshSubmitSigningState(context.Background(), []types.Transaction{txn}); err != nil {
		t.Fatalf("refreshSubmitSigningState() error = %v", err)
	}

	if auth, ok := eng.AuthCache.GetAuthAddress(sender); !ok || auth != cosigned {
		t.Fatalf("auth cache for sender = %q/%v, want %s/true", auth, ok, cosigned)
	}
	if got := eng.signerCacheKeyType(cosigned); got != "aplane.falcon1024.v1" {
		t.Fatalf("signer cache key type for cosigned authorizer = %q, want the plain host", got)
	}
	if got, ok := eng.signerCacheCosignerPublicKey(cosigned); !ok || got != cosignerHex {
		t.Fatalf("cosigner public key for cosigned authorizer = %q/%v, want %s/true", got, ok, cosignerHex)
	}
	if got, ok := eng.signerCacheCosignerComponentKeyType(cosigned); !ok || got != witness.Falcon1024V1 {
		t.Fatalf("cosigner component key type for cosigned authorizer = %q/%v, want %s/true", got, ok, witness.Falcon1024V1)
	}
	if profile, ok := eng.signerCacheLogicSigResourceProfile(cosigned); !ok || profile.ProgramBytes != 1_500 {
		t.Fatalf("LogicSig resources for cosigned authorizer = %+v/%v, want structured profile", profile, ok)
	}
	if !eng.cosignedSigner().HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() after refresh = false, want true")
	}
}

func testPublicLogicSigProfile(programBytes uint64) *signerapi.LogicSigResourceProfile {
	return &signerapi.LogicSigResourceProfile{
		Default: &signerapi.LogicSigResourceUsage{ProgramBytes: programBytes, MaxOpcodeCost: 1},
	}
}

func TestRefreshSubmitSigningStateDoesNotRefreshCachedAuthAddress(t *testing.T) {
	sender := testAddress(1).String()
	cosigned := testAddress(3).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

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
				Address:                  cosigned,
				KeyType:                  "aplane.falcon1024.v1",
				SigningFlow:              signerapi.SigningFlowCosigned1,
				CosignerComponentKeyType: witness.Falcon1024V1,
				LogicSigResources:        testPublicLogicSigProfile(1_500),
				BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
					Contract: signerapi.BoundedContractPlain1,
					Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: cosignerHex},
				},
			}},
		}, req), nil
	})
	eng.AlgodClient = newAccountMockAlgodClient(t, transport)
	eng.AuthCache = cache.NewAuthAddressCacheForStore(eng.CacheStore)
	eng.AuthCache.AuthAddresses[sender] = cosigned

	txn := testPreparedTxn(t, testAddress(1), testAddress(2), "cosigned-authorizer", nil).Transaction
	if err := eng.refreshSubmitSigningState(context.Background(), []types.Transaction{txn}); err != nil {
		t.Fatalf("refreshSubmitSigningState() error = %v", err)
	}

	if auth, ok := eng.AuthCache.GetAuthAddress(sender); !ok || auth != cosigned {
		t.Fatalf("auth cache for sender = %q/%v, want cached %s/true", auth, ok, cosigned)
	}
	if !eng.cosignedSigner().HasCosignedEffectiveSigner([]types.Transaction{txn}) {
		t.Fatal("hasCosignedEffectiveSigner() after refresh = false, want true")
	}
}
