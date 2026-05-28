// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"net/http"
	"testing"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

func TestSyncSignerStatusRefreshesCacheOnFirstReadyMismatch(t *testing.T) {
	addr := testAddr(31)
	keysCalls := 0
	eng := newConnectedEngineForKeyMgmtTest(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/status":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.StatusResponse{
				IdentityID:      "default",
				State:           "unlocked",
				ReadyForSigning: true,
				KeyCount:        1,
				KeysetRevision:  4,
			}, req), nil
		case "/keys":
			keysCalls++
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.KeysResponse{
				Count: 1,
				Keys:  []signerapi.KeyInfo{{Address: addr, KeyType: "ed25519"}},
			}, req), nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})

	result, err := eng.SyncSignerStatus()
	if err != nil {
		t.Fatalf("SyncSignerStatus() error = %v", err)
	}
	if !result.FirstSync || !result.CacheRefreshed {
		t.Fatalf("result = %+v, want first sync with refresh", result)
	}
	if keysCalls != 1 {
		t.Fatalf("/keys calls = %d, want 1", keysCalls)
	}
	if got := eng.SignerCache.GetKeyType(addr); got != "ed25519" {
		t.Fatalf("SignerCache key type = %q, want ed25519", got)
	}
}

func TestSyncSignerStatusSkipsRefreshWhenRevisionAndCountMatch(t *testing.T) {
	addr := testAddr(32)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(addr, "ed25519")

	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/status":
			return keyMgmtJSONResponse(t, http.StatusOK, signerapi.StatusResponse{
				IdentityID:      "default",
				State:           "unlocked",
				ReadyForSigning: true,
				KeyCount:        1,
				KeysetRevision:  7,
			}, req), nil
		case "/keys":
			t.Fatal("/keys should not be called when revision and count match")
			return nil, nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
			return nil, nil
		}
	})
	eng.signerStatusRevisionSeen = true
	eng.signerStatusKeysetRevSeen = 7

	result, err := eng.SyncSignerStatus()
	if err != nil {
		t.Fatalf("SyncSignerStatus() error = %v", err)
	}
	if result.FirstSync || result.RevisionChanged || result.CacheRefreshed {
		t.Fatalf("result = %+v, want no refresh", result)
	}
}

func TestSyncSignerStatusClearsCacheWhenSignerLocks(t *testing.T) {
	addr := testAddr(33)
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(addr, "ed25519")

	eng := newConnectedEngineForKeyMgmtTestWithSignerCache(t, signerCache, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/status" {
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		return keyMgmtJSONResponse(t, http.StatusOK, signerapi.StatusResponse{
			IdentityID:      "default",
			State:           "locked",
			SignerLocked:    true,
			ReadyForSigning: false,
			KeyCount:        0,
			KeysetRevision:  8,
		}, req), nil
	})
	eng.signerStatusRevisionSeen = true
	eng.signerStatusKeysetRevSeen = 7

	result, err := eng.SyncSignerStatus()
	if err != nil {
		t.Fatalf("SyncSignerStatus() error = %v", err)
	}
	if !result.RevisionChanged || !result.CacheCleared {
		t.Fatalf("result = %+v, want changed with cache clear", result)
	}
	if eng.SignerCache.Count() != 0 || !eng.SignerCache.Locked {
		t.Fatalf("SignerCache count/locked = %d/%v, want 0/true", eng.SignerCache.Count(), eng.SignerCache.Locked)
	}
}
