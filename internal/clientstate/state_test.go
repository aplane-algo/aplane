// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/tokenfile"
)

func newTestState(t *testing.T) *State {
	t.Helper()
	dataDir := t.TempDir()
	state := New("testnet")
	state.DataDir = dataDir
	state.CacheStore = cache.NewStore(dataDir)
	state.AliasCache = cache.LoadAliasCacheFromStore(state.CacheStore)
	state.SetCache = cache.LoadSetCacheFromStore(state.CacheStore)
	state.AuthCache = cache.LoadAuthCacheFromStore(state.CacheStore, state.Network)
	return state
}

func TestConcurrentAddAliasPersistsAllEntries(t *testing.T) {
	state := newTestState(t)

	addresses := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"7777777777777777777777777777777777777777777777777774MSJUVU",
	}

	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Different aliases may race for the same backing address; that is acceptable.
			_, _ = state.AddAlias(fmt.Sprintf("name%d", i), addresses[i%len(addresses)])
		}(i)
	}
	wg.Wait()

	state.ReloadAliasCache()
	if len(state.AliasCache.Aliases) == 0 {
		t.Fatal("expected persisted aliases after concurrent mutation")
	}
}

func TestConcurrentSetMutationsRemainUsable(t *testing.T) {
	state := newTestState(t)
	resolve := func(input string) (string, error) { return input, nil }

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = state.AddSet(fmt.Sprintf("set%d", i), []string{fmt.Sprintf("ADDR%d", i)}, resolve)
		}(i)
	}
	wg.Wait()

	state.ReloadSetCache()
	if len(state.SetCache.Sets) != 8 {
		t.Fatalf("set count = %d, want 8", len(state.SetCache.Sets))
	}
}

func TestAddAliasRefreshesAndPersistsAuthCacheFromAlgod(t *testing.T) {
	state := newTestState(t)

	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	authAddr := "7777777777777777777777777777777777777777777777777774MSJUVU"
	state.AlgodClient = newAuthCacheTestAlgodClient(t, map[string]string{
		address: authAddr,
	})

	result, err := state.AddAlias("alice", address)
	if err != nil {
		t.Fatalf("AddAlias() error = %v", err)
	}
	if result.Address != address {
		t.Fatalf("result.Address = %q, want %q", result.Address, address)
	}

	gotAuth, ok := state.AuthCache.GetAuthAddress(address)
	if !ok {
		t.Fatal("expected auth cache entry to be present after alias add")
	}
	if gotAuth != authAddr {
		t.Fatalf("auth cache value = %q, want %q", gotAuth, authAddr)
	}

	reloaded := cache.LoadAuthCacheFromStore(state.CacheStore, state.Network)
	gotAuth, ok = reloaded.GetAuthAddress(address)
	if !ok {
		t.Fatal("expected persisted auth cache entry after alias add")
	}
	if gotAuth != authAddr {
		t.Fatalf("persisted auth cache value = %q, want %q", gotAuth, authAddr)
	}
}

func TestAddAliasRollsBackAliasWhenAuthCacheRefreshPersistenceFails(t *testing.T) {
	state := newTestState(t)

	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	authAddr := "7777777777777777777777777777777777777777777777777774MSJUVU"
	state.AlgodClient = newAuthCacheTestAlgodClient(t, map[string]string{
		address: authAddr,
	})

	authCachePath := cache.GetAuthCacheFilenameForStore(state.CacheStore, state.Network)
	if err := os.MkdirAll(authCachePath, 0o755); err != nil {
		t.Fatalf("failed to block auth cache path with directory: %v", err)
	}

	if _, err := state.AddAlias("alice", address); err == nil {
		t.Fatal("AddAlias() error = nil, want auth cache persistence failure")
	} else if got := err.Error(); got == "" || !containsAll(got, []string{"failed to update auth cache"}) {
		t.Fatalf("AddAlias() error = %q, want auth cache update failure", got)
	}

	if got, exists := state.AliasCache.Aliases["alice"]; exists {
		t.Fatalf("in-memory alias alice = %q, want rollback removal", got)
	}

	state.ReloadAliasCache()
	if got, exists := state.AliasCache.Aliases["alice"]; exists {
		t.Fatalf("persisted alias alice = %q, want rollback removal", got)
	}
}

func TestAddAliasUpdatePrunesStaleOldAuthCacheEntry(t *testing.T) {
	state := newTestState(t)

	oldAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	newAddr := "7777777777777777777777777777777777777777777777777774MSJUVU"
	oldAuth := "YRVK3QXQ3ZP3K6Y7QJ5XW7W5WGBZ5XAGMQQQ5L4AM2T6M2JQKJ5W4A3Y7U"
	newAuth := "R3J7R2B3PKPZYTSFEGZ4KJ4YQ6D4Y4THP6O5A5XQWTMW5EZVCCU3Q7R5FI"
	state.AlgodClient = newAuthCacheTestAlgodClient(t, map[string]string{
		oldAddr: oldAuth,
		newAddr: newAuth,
	})

	if _, err := state.AddAlias("alice", oldAddr); err != nil {
		t.Fatalf("AddAlias(old) error = %v", err)
	}
	if _, err := state.AddAlias("alice", newAddr); err != nil {
		t.Fatalf("AddAlias(new) error = %v", err)
	}

	if got, ok := state.AuthCache.GetAuthAddress(oldAddr); ok {
		t.Fatalf("stale old auth cache entry = %q, want pruned", got)
	}
	gotAuth, ok := state.AuthCache.GetAuthAddress(newAddr)
	if !ok {
		t.Fatal("expected new auth cache entry after alias update")
	}
	if gotAuth != newAuth {
		t.Fatalf("new auth cache value = %q, want %q", gotAuth, newAuth)
	}

	reloaded := cache.LoadAuthCacheFromStore(state.CacheStore, state.Network)
	if got, ok := reloaded.GetAuthAddress(oldAddr); ok {
		t.Fatalf("persisted stale old auth cache entry = %q, want pruned", got)
	}
	gotAuth, ok = reloaded.GetAuthAddress(newAddr)
	if !ok {
		t.Fatal("expected persisted new auth cache entry after alias update")
	}
	if gotAuth != newAuth {
		t.Fatalf("persisted new auth cache value = %q, want %q", gotAuth, newAuth)
	}
}

func TestNewInitializedLoadsPersistedAuthCacheWithoutAlgodRefresh(t *testing.T) {
	cache.InitLogger()

	dataDir := t.TempDir()
	store := cache.NewStore(dataDir)

	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	authAddr := "7777777777777777777777777777777777777777777777777774MSJUVU"

	state := New("testnet")
	state.DataDir = dataDir
	state.CacheStore = store
	state.SignerCache = cache.NewSignerCache()
	state.SignerCache.AddAddress(address, "ed25519")
	if err := state.SaveSignerCache(); err != nil {
		t.Fatalf("SaveSignerCache() error = %v", err)
	}

	authCache := cache.NewAuthAddressCacheForStore(store)
	authCache.AuthAddresses[address] = authAddr
	if err := authCache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	var accountInfoCalls int
	algodClient := newCountingAuthCacheTestAlgodClient(t, &accountInfoCalls)
	initialized := NewInitialized("testnet", dataDir, algodClient)

	if got := initialized.SignerCache.Count(); got != 1 {
		t.Fatalf("SignerCache.Count() = %d, want 1", got)
	}
	gotAuth, ok := initialized.AuthCache.GetAuthAddress(address)
	if !ok {
		t.Fatal("expected persisted auth cache entry to load at startup")
	}
	if gotAuth != authAddr {
		t.Fatalf("auth cache value = %q, want %q", gotAuth, authAddr)
	}
	if accountInfoCalls != 0 {
		t.Fatalf("startup made %d algod account-info call(s), want 0", accountInfoCalls)
	}
}

func TestPopulateSignerCachePreservesExistingPointer(t *testing.T) {
	state := New("testnet")
	original := &state.SignerCache

	state.PopulateSignerCache([]signerapi.KeyInfo{{
		Address: "ADDR1",
		KeyType: "aplane.falcon1024-sentry-ed25519.v1",
		Parameters: map[string]string{
			"sentry_public_key": "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a",
		},
	}})
	if &state.SignerCache != original {
		t.Fatal("PopulateSignerCache replaced SignerCache storage; existing completer pointers would go stale")
	}
	if got := original.GetKeyType("ADDR1"); got != "aplane.falcon1024-sentry-ed25519.v1" {
		t.Fatalf("original pointer key type = %q, want guarded key type", got)
	}
	if got, ok := original.SentryPublicKeyForAddress("ADDR1"); !ok || got != "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a" {
		t.Fatalf("sentry public key = %q/%v, want cached value", got, ok)
	}

	state.PopulateSignerCache(nil)
	if original.Count() != 0 {
		t.Fatalf("original pointer count after empty populate = %d, want 0", original.Count())
	}
	if got, ok := original.SentryPublicKeyForAddress("ADDR1"); ok || got != "" {
		t.Fatalf("sentry public key after empty populate = %q/%v, want empty false", got, ok)
	}
}

func TestApplyCacheChangesReloadsOnlyCurrentNetworkCaches(t *testing.T) {
	dataDir := t.TempDir()
	store := cache.NewStore(dataDir)

	testnetASA := cache.LoadASACacheFromStore(store, "testnet")
	testnetASA.Assets[1] = cache.ASAInfo{Name: "One", UnitName: "ONE", Decimals: 1}
	if err := testnetASA.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache(testnet ASA) error = %v", err)
	}
	mainnetASA := cache.LoadASACacheFromStore(store, "mainnet")
	mainnetASA.Assets[2] = cache.ASAInfo{Name: "Two", UnitName: "TWO", Decimals: 2}
	if err := mainnetASA.SaveCache("mainnet"); err != nil {
		t.Fatalf("SaveCache(mainnet ASA) error = %v", err)
	}

	testnetAuth := cache.NewAuthAddressCacheForStore(store)
	testnetAuth.AuthAddresses["ADDR_TEST"] = "AUTH_TEST"
	if err := testnetAuth.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache(testnet auth) error = %v", err)
	}
	mainnetAuth := cache.NewAuthAddressCacheForStore(store)
	mainnetAuth.AuthAddresses["ADDR_MAIN"] = "AUTH_MAIN"
	if err := mainnetAuth.SaveCache("mainnet"); err != nil {
		t.Fatalf("SaveCache(mainnet auth) error = %v", err)
	}

	state := NewInitialized("testnet", dataDir, nil)
	state.AsaCache = cache.LoadASACacheFromStore(store, "customnet")
	state.AuthCache = cache.NewAuthAddressCacheForStore(store)
	state.ApplyCacheChanges(CacheChanges{
		ASA:  map[string]bool{"mainnet": true},
		Auth: map[string]bool{"mainnet": true},
	})
	if _, ok := state.AsaCache.Assets[2]; ok {
		t.Fatal("mainnet ASA cache loaded while state network is testnet")
	}
	if _, ok := state.AuthCache.GetAuthAddress("ADDR_MAIN"); ok {
		t.Fatal("mainnet auth cache loaded while state network is testnet")
	}

	state.ApplyCacheChanges(CacheChanges{
		ASA:  map[string]bool{"testnet": true},
		Auth: map[string]bool{"testnet": true},
	})
	if got := state.AsaCache.Assets[1]; got.UnitName != "ONE" {
		t.Fatalf("testnet ASA = %+v, want ONE", got)
	}
	if got, ok := state.AuthCache.GetAuthAddress("ADDR_TEST"); !ok || got != "AUTH_TEST" {
		t.Fatalf("testnet auth = (%q,%v), want (AUTH_TEST,true)", got, ok)
	}
}

func TestSaveApshellTokenPersistsTokenFile(t *testing.T) {
	state := newTestState(t)

	tokenPath, err := state.SaveApshellToken("deadbeef")
	if err != nil {
		t.Fatalf("SaveApshellToken() error = %v", err)
	}

	wantPath := filepath.Join(state.DataDir, tokenfile.APlaneTokenFile)
	if tokenPath != wantPath {
		t.Fatalf("token path = %q, want %q", tokenPath, wantPath)
	}

	got, err := tokenfile.LoadApshellTokenFromDataDir(state.DataDir)
	if err != nil {
		t.Fatalf("LoadApshellTokenFromDataDir() error = %v", err)
	}
	if got != "deadbeef" {
		t.Fatalf("persisted token = %q, want %q", got, "deadbeef")
	}
}

func TestSaveApshellTokenToPathCreatesEndpointTokenDirectory(t *testing.T) {
	state := newTestState(t)
	tokenPath := filepath.Join(state.DataDir, "tokens", "sentry-local.token")

	gotPath, err := state.SaveApshellTokenToPath(tokenPath, "sentry-token")
	if err != nil {
		t.Fatalf("SaveApshellTokenToPath() error = %v", err)
	}
	if gotPath != tokenPath {
		t.Fatalf("token path = %q, want %q", gotPath, tokenPath)
	}
	got, err := tokenfile.ReadToken(tokenPath)
	if err != nil {
		t.Fatalf("ReadToken() error = %v", err)
	}
	if got != "sentry-token" {
		t.Fatalf("persisted token = %q, want sentry-token", got)
	}
}

func newAuthCacheTestAlgodClient(t *testing.T, authAddrs map[string]string) *algod.Client {
	t.Helper()

	client, err := algod.MakeClientWithTransport(
		"http://mock-algod",
		"",
		nil,
		&authCacheTestTransport{t: t, authAddrs: authAddrs},
	)
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

func newCountingAuthCacheTestAlgodClient(t *testing.T, calls *int) *algod.Client {
	t.Helper()

	client, err := algod.MakeClientWithTransport(
		"http://mock-algod",
		"",
		nil,
		&countingAuthCacheTestTransport{calls: calls},
	)
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

type authCacheTestTransport struct {
	t         *testing.T
	authAddrs map[string]string
}

type countingAuthCacheTestTransport struct {
	calls *int
}

func (m *countingAuthCacheTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	(*m.calls)++
	body := []byte(
		`{"address":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",` +
			`"amount":1000000,"min-balance":100000,"status":"Offline"}`,
	)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func (m *authCacheTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	m.t.Helper()

	if req.Method != http.MethodGet || len(req.URL.Path) <= len("/v2/accounts/") || req.URL.Path[:13] != "/v2/accounts/" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"message":"unexpected request"}`))),
			Request:    req,
		}, nil
	}

	address := req.URL.Path[len("/v2/accounts/"):]
	authAddr, ok := m.authAddrs[address]
	if !ok {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"message":"account not found"}`))),
			Request:    req,
		}, nil
	}

	body, err := json.Marshal(models.Account{
		Address:                     address,
		AuthAddr:                    authAddr,
		Amount:                      1_000_000,
		AmountWithoutPendingRewards: 1_000_000,
		MinBalance:                  100_000,
		PendingRewards:              0,
		Rewards:                     0,
		Round:                       1,
		Status:                      "Offline",
	})
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func containsAll(haystack string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && !bytes.Contains([]byte(haystack), []byte(needle)) {
			return false
		}
	}
	return true
}
