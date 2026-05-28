// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/aplane-algo/aplane/internal/cache"
)

func TestGetASAInfoRequiresAlgodClient(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	_, err = eng.GetASAInfoWithContext(context.Background(), 10458941)
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("GetASAInfoWithContext() error = %v, want ErrNoAlgodClient", err)
	}
}

func TestCacheASAInitializesMap(t *testing.T) {
	eng, err := NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	eng.cacheASA(&ASAInfo{
		AssetID:  42,
		UnitName: "UNIT",
		Name:     "Asset",
		Decimals: 6,
	})

	got, ok := eng.AsaCache.Assets[42]
	if !ok {
		t.Fatal("asset 42 not present in cache")
	}
	if got.UnitName != "UNIT" || got.Name != "Asset" || got.Decimals != 6 {
		t.Fatalf("cached asset = %+v, want UNIT/Asset/6", got)
	}
}

func TestSaveASACachePersistsCurrentNetwork(t *testing.T) {
	store := cache.NewStore(t.TempDir())
	eng, err := NewEngine("testnet",
		WithCacheStore(store),
		WithASACache(cache.LoadASACacheFromStore(store, "testnet")),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	eng.AsaCache.Assets[900001] = cache.ASAInfo{Name: "Persisted", UnitName: "PST", Decimals: 3}
	if err := eng.SaveASACache(); err != nil {
		t.Fatalf("SaveASACache() error = %v", err)
	}

	reloaded := cache.LoadASACacheFromStore(store, "testnet")
	got, ok := reloaded.Assets[900001]
	if !ok {
		t.Fatal("persisted asset missing after reload")
	}
	if got.Name != "Persisted" || got.UnitName != "PST" || got.Decimals != 3 {
		t.Fatalf("reloaded asset = %+v, want Persisted/PST/3", got)
	}
}

func TestRemoveASAFromCachePersistsDeletion(t *testing.T) {
	store := cache.NewStore(t.TempDir())
	asaCache := cache.LoadASACacheFromStore(store, "testnet")
	asaCache.Assets[900002] = cache.ASAInfo{Name: "ToDelete", UnitName: "DEL", Decimals: 2}
	if err := asaCache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	eng, err := NewEngine("testnet", WithCacheStore(store), WithASACache(cache.LoadASACacheFromStore(store, "testnet")))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if err := eng.RemoveASAFromCache(900002); err != nil {
		t.Fatalf("RemoveASAFromCache() error = %v", err)
	}
	if _, exists := eng.AsaCache.Assets[900002]; exists {
		t.Fatal("asset still present in in-memory cache after removal")
	}

	reloaded := cache.LoadASACacheFromStore(store, "testnet")
	if _, exists := reloaded.Assets[900002]; exists {
		t.Fatal("asset still present after persisted removal")
	}
}

func TestRemoveASAFromCacheRejectsMissingAsset(t *testing.T) {
	eng, err := NewEngine("testnet", WithASACache(cache.ASACache{Assets: map[uint64]cache.ASAInfo{}}))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	err = eng.RemoveASAFromCache(999999)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrInvalidAssetID) {
		t.Fatalf("error = %v, want ErrInvalidAssetID", err)
	}
}

func TestListCachedASAsReturnsAllEntries(t *testing.T) {
	eng, err := NewEngine("testnet", WithASACache(cache.ASACache{
		Assets: map[uint64]cache.ASAInfo{
			2: {Name: "Two", UnitName: "TWO", Decimals: 2},
			1: {Name: "One", UnitName: "ONE", Decimals: 1},
		},
	}))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	got := eng.ListCachedASAs()
	if len(got) != 2 {
		t.Fatalf("len(ListCachedASAs()) = %d, want 2", len(got))
	}
	sort.Slice(got, func(i, j int) bool { return got[i].AssetID < got[j].AssetID })
	if got[0].AssetID != 1 || got[0].UnitName != "ONE" || got[1].AssetID != 2 || got[1].UnitName != "TWO" {
		t.Fatalf("ListCachedASAs() = %#v, want assets 1/ONE and 2/TWO", got)
	}
}

func TestClearASACachePersistsEmptyState(t *testing.T) {
	store := cache.NewStore(t.TempDir())
	asaCache := cache.LoadASACacheFromStore(store, "testnet")
	asaCache.Assets[900003] = cache.ASAInfo{Name: "ClearMe", UnitName: "CLR", Decimals: 0}
	if err := asaCache.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}

	eng, err := NewEngine("testnet", WithCacheStore(store), WithASACache(cache.LoadASACacheFromStore(store, "testnet")))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	count, err := eng.ClearASACache()
	if err != nil {
		t.Fatalf("ClearASACache() error = %v", err)
	}
	if count == 0 {
		t.Fatal("ClearASACache() count = 0, want > 0")
	}
	if len(eng.AsaCache.Assets) != 0 {
		t.Fatalf("len(AsaCache.Assets) = %d, want 0", len(eng.AsaCache.Assets))
	}

	reloaded := cache.LoadASACacheFromStore(store, "testnet")
	if _, exists := reloaded.Assets[900003]; exists {
		t.Fatal("cleared asset still present after reload")
	}
}

func TestGetASAInfoForceRefreshFetchesFullMetadataAndCachesIt(t *testing.T) {
	store := cache.NewStore(t.TempDir())
	transport := &assetByIDMockTransport{
		t: t,
		assets: map[uint64]models.Asset{
			12345: {
				Index: 12345,
				Params: models.AssetParams{
					UnitName:      "TOK",
					Name:          "Token",
					Decimals:      6,
					Total:         1000,
					Creator:       "CREATOR",
					Manager:       "MANAGER",
					Reserve:       "RESERVE",
					Freeze:        "FREEZE",
					Clawback:      "CLAWBACK",
					DefaultFrozen: true,
					Url:           "https://example.test/token",
				},
			},
		},
	}
	client := newAssetByIDMockAlgodClient(t, transport)

	eng, err := NewEngine("testnet",
		WithAlgodClient(client),
		WithCacheStore(store),
		WithASACache(cache.LoadASACacheFromStore(store, "testnet")),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	info, err := eng.GetASAInfoWithContext(context.Background(), 12345, true)
	if err != nil {
		t.Fatalf("GetASAInfoWithContext(forceRefresh) error = %v", err)
	}
	if info.AssetID != 12345 || info.UnitName != "TOK" || info.Name != "Token" || info.Decimals != 6 {
		t.Fatalf("info = %+v, want fetched metadata", info)
	}
	if info.Manager != "MANAGER" || info.URL != "https://example.test/token" || !info.DefaultFrozen {
		t.Fatalf("full metadata = %+v, want manager/url/default_frozen from network", info)
	}
	if cached, ok := eng.AsaCache.Assets[12345]; !ok || cached.UnitName != "TOK" || cached.Name != "Token" || cached.Decimals != 6 {
		t.Fatalf("cache entry = %+v, want TOK/Token/6", cached)
	}
}

func TestGetASAInfoForceRefreshWrapsAlgodErrors(t *testing.T) {
	transport := &assetByIDMockTransport{t: t, err: errors.New("algod boom")}
	client := newAssetByIDMockAlgodClient(t, transport)

	eng, err := NewEngine("testnet", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	_, err = eng.GetASAInfoWithContext(context.Background(), 99, true)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get asset 99") || !strings.Contains(err.Error(), "algod boom") {
		t.Fatalf("error = %q, want wrapped algod error", err.Error())
	}
}

type assetByIDMockTransport struct {
	t      *testing.T
	assets map[uint64]models.Asset
	err    error
}

func (m *assetByIDMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || !strings.HasPrefix(req.URL.Path, "/v2/assets/") {
		return assetJSONResp(http.StatusNotFound, map[string]string{"message": fmt.Sprintf("unexpected request: %s %s", req.Method, req.URL.Path)}, req), nil
	}
	if m.err != nil {
		return nil, m.err
	}

	var assetID uint64
	if _, err := fmt.Sscanf(req.URL.Path, "/v2/assets/%d", &assetID); err != nil {
		m.t.Fatalf("failed to parse asset id from path %q: %v", req.URL.Path, err)
	}
	asset, ok := m.assets[assetID]
	if !ok {
		return assetJSONResp(http.StatusNotFound, map[string]string{"message": "asset not found"}, req), nil
	}
	return assetJSONResp(http.StatusOK, asset, req), nil
}

func newAssetByIDMockAlgodClient(t *testing.T, transport http.RoundTripper) *algod.Client {
	t.Helper()
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, transport)
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	return client
}

func assetJSONResp(status int, body interface{}, req *http.Request) *http.Response {
	data, _ := json.Marshal(body)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(data)),
		Request:    req,
	}
}
