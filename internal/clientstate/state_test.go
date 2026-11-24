// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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
			_, _ = state.AddAliasWithContext(context.Background(), fmt.Sprintf("name%d", i), addresses[i%len(addresses)])
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

	result, err := state.AddAliasWithContext(context.Background(), "alice", address)
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

	if _, err := state.AddAliasWithContext(context.Background(), "alice", address); err == nil {
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

	if _, err := state.AddAliasWithContext(context.Background(), "alice", oldAddr); err != nil {
		t.Fatalf("AddAlias(old) error = %v", err)
	}
	if _, err := state.AddAliasWithContext(context.Background(), "alice", newAddr); err != nil {
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

	dataDir := t.TempDir()
	store := cache.NewStore(dataDir)

	address := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	authAddr := "7777777777777777777777777777777777777777777777777774MSJUVU"

	state := New("testnet")
	state.DataDir = dataDir
	state.CacheStore = store
	if err := state.PopulateAndSaveSignerCacheLocked([]signerapi.KeyInfo{
		{Address: address, KeyType: "ed25519", AuthorizationKind: "ed25519"},
	}); err != nil {
		t.Fatalf("PopulateAndSaveSignerCacheLocked() error = %v", err)
	}

	authCache := cache.NewAuthAddressCacheForStore(store)
	authCache.AuthAddresses[address] = authAddr
	if err := authCache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	var accountInfoCalls int
	algodClient := newCountingAuthCacheTestAlgodClient(t, &accountInfoCalls)
	initialized := NewInitialized("testnet", dataDir, algodClient)

	if got := initialized.SignerCacheCount(); got != 1 {
		t.Fatalf("SignerCacheCount() = %d, want 1", got)
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

func TestPopulateSignerCacheUpdatesMetadataAndSnapshotIsIsolated(t *testing.T) {
	state := New("testnet")

	if err := state.PopulateSignerCache([]signerapi.KeyInfo{{
		Address:                  "ADDR1",
		KeyType:                  "aplane.falcon1024.v1",
		CosignerComponentKeyType: "aplane.witness-falcon1024.v1",
		LogicSigResources: &signerapi.LogicSigResourceProfile{
			Spend:         &signerapi.LogicSigResourceUsage{ProgramBytes: 77, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000},
			SpendingRekey: &signerapi.LogicSigResourceUsage{ProgramBytes: 77, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000},
			ListedRekey:   &signerapi.LogicSigResourceUsage{ProgramBytes: 77, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000},
		},
		BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
			Contract: "plain1",
			Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a"},
		},
	}}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	snap := state.SignerCacheSnapshot()
	if got := snap.GetKeyType("ADDR1"); got != "aplane.falcon1024.v1" {
		t.Fatalf("snapshot key type = %q, want cosigned key type", got)
	}
	if got, ok := snap.CosignerPublicKeyForAddress("ADDR1"); !ok || got != "d6fb74e10151ac3b0eaa7431b9b92c772c2a4a600c10b88cfd30169ea1ab4d0a" {
		t.Fatalf("cosigner public key = %q/%v, want cached value", got, ok)
	}
	if got, ok := snap.CosignerComponentKeyTypeForAddress("ADDR1"); !ok || got != "aplane.witness-falcon1024.v1" {
		t.Fatalf("cosigner component key type = %q/%v, want cached value", got, ok)
	}
	if profile, ok := snap.LogicSigResourceProfile("ADDR1"); !ok || profile.Spend == nil || profile.Spend.ArgumentBytes != 1_423 {
		t.Fatalf("LogicSig resources = %+v/%v, want cached spend profile", profile, ok)
	}

	// Mutating a snapshot must not mutate State's cache.
	snap.Keys["ADDR1"] = "mutated"
	if got := state.SignerCacheKeyType("ADDR1"); got != "aplane.falcon1024.v1" {
		t.Fatalf("mutating snapshot affected State cache: key type = %q", got)
	}

	if err := state.PopulateSignerCache(nil); err != nil {
		t.Fatalf("PopulateSignerCache(nil) error = %v", err)
	}
	if state.SignerCacheCount() != 0 {
		t.Fatalf("count after empty populate = %d, want 0", state.SignerCacheCount())
	}
	if got, ok := state.SignerCacheCosignerPublicKey("ADDR1"); ok || got != "" {
		t.Fatalf("cosigner public key after empty populate = %q/%v, want empty false", got, ok)
	}
}

func TestPopulateSignerCacheReadsBoundedCosignerMetadata(t *testing.T) {
	state := New("testnet")
	if err := state.PopulateSignerCache([]signerapi.KeyInfo{{
		Address: "BOUNDED", KeyType: "aplane.custom-bounded-cosigner.v1",
		SigningFlow:              signerapi.SigningFlowCosigned1,
		CosignerComponentKeyType: "aplane.witness-falcon1024.v1",
		BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
			Contract: "bounded2",
			MaxFee:   new(uint64(10_000)),
			Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: "abcd"},
		},
	}, {
		Address: "PLAIN", KeyType: "aplane.falcon1024.v1",
		SigningFlow: signerapi.SigningFlowCosigned1,
		BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
			Contract: "plain1",
			Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: "ef01"},
		},
	}}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	if got, ok := state.SignerCacheCosignerPublicKey("BOUNDED"); !ok || got != "abcd" {
		t.Fatalf("bounded cosigner public key = %q/%v", got, ok)
	}
	if got := state.SignerCacheSigningFlow("BOUNDED"); got != signerapi.SigningFlowCosigned1 {
		t.Fatalf("bounded cosigner flow = %q", got)
	}
	if got, ok := state.SignerCacheBoundedMaxFee("BOUNDED"); !ok || got != 10_000 {
		t.Fatalf("bounded max fee = %d/%v", got, ok)
	}
	if got, ok := state.SignerCacheBoundedContract("BOUNDED"); !ok || got != "bounded2" {
		t.Fatalf("bounded contract = %q/%v", got, ok)
	}
	// A plain host records its contract and no ceiling, not a zero one.
	if got, ok := state.SignerCacheBoundedContract("PLAIN"); !ok || got != "plain1" {
		t.Fatalf("plain host contract = %q/%v", got, ok)
	}
	if got, ok := state.SignerCacheBoundedMaxFee("PLAIN"); ok {
		t.Fatalf("plain host max fee = %d, want none", got)
	}
}

func TestPopulateSignerCacheRejectsMalformedLogicSigResourcesWithoutMutation(t *testing.T) {
	state := New("testnet")
	if err := state.PopulateSignerCache([]signerapi.KeyInfo{{Address: "GOOD", KeyType: "ed25519"}}); err != nil {
		t.Fatal(err)
	}

	err := state.PopulateSignerCache([]signerapi.KeyInfo{{
		Address: "BAD", KeyType: "aplane.falcon1024.v1",
		LogicSigResources: &signerapi.LogicSigResourceProfile{
			Default: &signerapi.LogicSigResourceUsage{ProgramBytes: 0, MaxOpcodeCost: 20_000},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "program_bytes must be greater than zero") {
		t.Fatalf("PopulateSignerCache() error = %v, want invalid program_bytes", err)
	}
	if !state.SignerCacheHasAddress("GOOD") || state.SignerCacheHasAddress("BAD") {
		t.Fatalf("signer cache mutated after invalid inventory: %+v", state.SignerCacheKeysSnapshot())
	}
}

func TestPopulateSignerCacheRejectsInconsistentLogicSigProgramBytes(t *testing.T) {
	state := New("testnet")
	err := state.PopulateSignerCache([]signerapi.KeyInfo{{
		Address: "BAD", KeyType: "test.bounded.v1",
		LogicSigResources: &signerapi.LogicSigResourceProfile{
			Spend:         &signerapi.LogicSigResourceUsage{ProgramBytes: 100, MaxOpcodeCost: 20_000},
			SpendingRekey: &signerapi.LogicSigResourceUsage{ProgramBytes: 101, MaxOpcodeCost: 20_000},
			ListedRekey:   &signerapi.LogicSigResourceUsage{ProgramBytes: 101, MaxOpcodeCost: 20_000},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("PopulateSignerCache() error = %v, want inconsistent program_bytes", err)
	}
}

func TestPopulateSignerCacheRequiresBothBoundedPaths(t *testing.T) {
	state := New("testnet")
	err := state.PopulateSignerCache([]signerapi.KeyInfo{{
		Address: "BAD", KeyType: "test.bounded.v1",
		LogicSigResources: &signerapi.LogicSigResourceProfile{
			Spend: &signerapi.LogicSigResourceUsage{ProgramBytes: 100, MaxOpcodeCost: 20_000},
		},
	}})
	if err == nil || !strings.Contains(err.Error(), "must contain spend, spending_rekey and listed_rekey paths") {
		t.Fatalf("PopulateSignerCache() error = %v, want missing spending_rekey path", err)
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

// The signer API's /keys contract fixtures are what the SDKs test against, so
// each must be an inventory this client accepts: a fixture no signer would send
// pins the SDKs to a shape they never meet.
func TestSignerCacheAcceptsTheKeysContractFixtures(t *testing.T) {
	const dir = "../../test/contracts/signerapi"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "keys_response_") || !strings.HasSuffix(name, ".json") {
			continue
		}
		found++
		data, err := os.ReadFile(dir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		var response signerapi.KeysResponse
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := newTestState(t).PopulateSignerCache(response.Keys); err != nil {
			t.Errorf("%s: PopulateSignerCache() error = %v", name, err)
		}
	}
	if found == 0 {
		t.Fatal("no /keys contract fixtures found")
	}
}

// PopulateAndSaveSignerCacheLocked replaces every per-address entry the cache
// held and clears Locked, keeping the store it is bound to.
func TestPopulateSignerCacheReplacesEveryEntry(t *testing.T) {
	state := newTestState(t)
	seed := cache.NewSignerCache()
	seed.Keys = map[string]string{"OLD": "ed25519"}
	seed.AuthorizationKinds = map[string]string{"OLD": "ed25519"}
	seed.GenericLsigs = map[string]bool{"OLD": true}
	seed.LogicSigResources = map[string]lsigresource.Profile{"OLD": {ProgramBytes: 1}}
	seed.SigningArgs = map[string][]cache.SigningArgInfo{"OLD": {{Name: "x"}}}
	seed.SigningFlows = map[string]string{"OLD": "cosigned1"}
	seed.CosignerComponentKeyTypes = map[string]string{"OLD": "t"}
	seed.CosignerPublicKeys = map[string]string{"OLD": "ab"}
	seed.BoundedMaxFees = map[string]uint64{"OLD": 7}
	seed.BoundedContracts = map[string]string{"OLD": "plain1"}
	seed.Locked = true
	state.SetSignerCache(seed)

	maxFee := uint64(5000)
	if err := state.PopulateAndSaveSignerCacheLocked([]signerapi.KeyInfo{{
		Address:           "NEW",
		KeyType:           "aplane.falcon1024.v1",
		AuthorizationKind: "logic_sig",
		IsGenericLsig:     true,
		SigningFlow:       "cosigned1",
		SigningArgs:       []signerapi.RuntimeArgInfo{{Name: "secret", Type: "bytes", Required: true}},
		BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
			Contract: "bounded2",
			MaxFee:   &maxFee,
		},
	}}); err != nil {
		t.Fatalf("PopulateAndSaveSignerCacheLocked() error = %v", err)
	}
	if state.SignerCacheLocked() {
		t.Fatal("Locked = true after populate, want false")
	}
	got, err := json.Marshal(state.SignerCacheSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":4,"keys":{"NEW":"aplane.falcon1024.v1"},"authorization_kinds":{"NEW":"logic_sig"},"generic_lsigs":{"NEW":true},"signing_args":{"NEW":[{"name":"secret","type":"bytes","required":true}]},"signing_flows":{"NEW":"cosigned1"},"bounded_max_fees":{"NEW":5000},"bounded_contracts":{"NEW":"bounded2"}}`
	if string(got) != want {
		t.Fatalf("signer cache after populate\n got: %s\nwant: %s", got, want)
	}

	if reloaded := cache.LoadSignerCacheFromStore(state.CacheStore); reloaded.GetKeyType("NEW") != "aplane.falcon1024.v1" || reloaded.HasAddress("OLD") {
		t.Fatalf("reloaded keys = %v, want only NEW", reloaded.Keys)
	}
}

func TestAddAliasRefusesAnAddressAsAName(t *testing.T) {
	state := newTestState(t)
	name := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	target := "7777777777777777777777777777777777777777777777777774MSJUVU"
	for _, input := range []string{name, strings.ToLower(name)} {
		_, err := state.AddAliasWithContext(context.Background(), input, target)
		if err == nil || !strings.Contains(err.Error(), "is an Algorand address") {
			t.Fatalf("AddAliasWithContext(%q) error = %v, want the address-name refusal", input, err)
		}
	}
	state.ReloadAliasCache()
	if len(state.AliasCache.Aliases) != 0 {
		t.Fatalf("aliases = %v, want none", state.AliasCache.Aliases)
	}
}

// The cosigner key comes from bounded_authorization, the structured field
// the signer always sends for a cosigned account. The creation parameter of
// the same name is not read.
func TestPopulateSignerCacheReadsTheCosignerKeyFromBoundedAuthorization(t *testing.T) {
	state := New("testnet")
	if err := state.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: "PARAMS", KeyType: "k", Parameters: map[string]string{"cosigner_public_key": "aa"}},
		{Address: "BOTH", KeyType: "k", Parameters: map[string]string{"cosigner_public_key": "aa"},
			BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{Contract: "plain1", Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: "bb"}}},
		{Address: "STRUCT", KeyType: "k",
			BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{Contract: "plain1", Cosigner: &signerapi.BoundedCosignerAuthorizationInfo{PublicKeyHex: "cc"}}},
	}); err != nil {
		t.Fatal(err)
	}
	for address, want := range map[string]string{"PARAMS": "", "BOTH": "bb", "STRUCT": "cc"} {
		if got, ok := state.SignerCacheCosignerPublicKey(address); ok != (want != "") || got != want {
			t.Fatalf("%s cosigner key = %q/%v, want %q", address, got, ok, want)
		}
	}
}

func TestAliasMutationsRaceSafeWithConcurrentSignerCacheUpdates(t *testing.T) {
	state := newTestState(t)
	var accountInfoCalls int
	state.AlgodClient = newCountingAuthCacheTestAlgodClient(t, &accountInfoCalls)

	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "7777777777777777777777777777777777777777777777777774MSJUVU"
	keys := []signerapi.KeyInfo{
		{Address: addr1, KeyType: "ed25519", AuthorizationKind: "ed25519"},
		{Address: addr2, KeyType: "aplane.falcon1024.v1", AuthorizationKind: "logic_sig"},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			switch i % 3 {
			case 0:
				_ = state.PopulateSignerCache(keys)
			case 1:
				state.ResetSignerCache(false)
			case 2:
				state.ReloadSignerCache()
			}
		}
	}()

	// Alias mutations stay on the command goroutine (per State's concurrency
	// contract) while the background goroutine simulates tunnel disconnect and
	// signer-cache updates reading/writing signerCache under signerCacheMu.
	for i := 0; i < 40; i++ {
		if _, err := state.AddAliasWithContext(context.Background(), "alice", addr1); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("AddAliasWithContext() error = %v", err)
		}
		if _, _, err := state.RemoveAlias("alice"); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("RemoveAlias() error = %v", err)
		}
	}

	close(stop)
	wg.Wait()
}
