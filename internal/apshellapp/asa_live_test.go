// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

// liveAssetID is an asset that is not built in, so the ASA cache is the only
// local record of it.
const liveAssetID = 900100

var (
	liveFrom = types.Address{11}.String()
	liveTo   = types.Address{12}.String()
)

// liveAssetNetwork is an algod whose asset liveAssetID may differ from what
// the client cached, as after a LocalNet reset. It counts what it is asked.
type liveAssetNetwork struct {
	asset    models.AssetParams
	fail     bool   // asset reads answer 500
	holdings uint64 // each account's balance of liveAssetID

	mu       sync.Mutex
	requests map[string]int // by kind: "asset", "account", "params"
}

func (n *liveAssetNetwork) count(kind string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.requests[kind]
}

func (n *liveAssetNetwork) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	kind := ""
	switch {
	case strings.HasPrefix(r.URL.Path, "/v2/assets/"):
		kind = "asset"
	case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
		kind = "account"
	case r.URL.Path == "/v2/transactions/params":
		kind = "params"
	}
	n.mu.Lock()
	n.requests[kind]++
	n.mu.Unlock()

	switch kind {
	case "asset":
		if n.fail {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "algod is down"})
			return
		}
		if r.URL.Path != "/v2/assets/900100" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(models.Asset{Index: liveAssetID, Params: n.asset})
	case "account":
		address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
		_ = json.NewEncoder(w).Encode(models.Account{
			Address: address, Amount: 5_000_000, MinBalance: 200_000, Status: "Offline",
			Assets: []models.AssetHolding{{AssetId: liveAssetID, Amount: n.holdings}},
		})
	case "params":
		_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
			ConsensusVersion: string(protocol.ConsensusV43), Fee: 0, MinFee: 1000, LastRound: 100,
			GenesisId: "testnet-v1.0", GenesisHash: make([]byte, 32),
		})
	default:
		http.NotFound(w, r)
	}
}

// liveAssetApp returns an app whose ASA cache, in memory and on disk, holds
// cached for liveAssetID, and whose algod is network. No signer is
// connected: a transaction is prepared and then fails to sign.
func liveAssetApp(t *testing.T, network *liveAssetNetwork, cached cache.ASAInfo) (*App, *cache.Store) {
	t.Helper()
	if _, builtin := asa.BuiltinMetadata("testnet", liveAssetID); builtin {
		t.Fatalf("asset %d is built in on testnet; the test needs one that is not", liveAssetID)
	}
	network.requests = map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(network.handler))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}

	store := cache.NewStore(t.TempDir())
	onDisk := cache.LoadASACacheFromStore(store, "testnet")
	onDisk.Assets[liveAssetID] = cached
	if err := onDisk.SaveCache("testnet"); err != nil {
		t.Fatalf("SaveCache() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet",
		engine.WithAlgodClient(client),
		engine.WithCacheStore(store),
		engine.WithASACache(cache.LoadASACacheFromStore(store, "testnet")),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.SignerCache.Keys = map[string]string{liveFrom: "ed25519", liveTo: "ed25519"}
	return New(eng, config.DefaultConfig(), t.TempDir()), store
}

// assertCachedASA checks the entry for liveAssetID in memory and on disk.
func assertCachedASA(t *testing.T, app *App, store *cache.Store, want cache.ASAInfo) {
	t.Helper()
	if got := app.eng.AsaCache.Assets[liveAssetID]; got != want {
		t.Fatalf("in-memory cache entry = %+v, want %+v", got, want)
	}
	if got := cache.LoadASACacheFromStore(store, "testnet").Assets[liveAssetID]; got != want {
		t.Fatalf("cache entry on disk = %+v, want %+v", got, want)
	}
}

var (
	staleOld = cache.ASAInfo{Name: "Old Token", UnitName: "OLD", Decimals: 6}
	liveNew  = models.AssetParams{Name: "New Thing", UnitName: "NEW", Decimals: 2, Total: 1_000_000, Creator: liveFrom}
)

// A cached entry whose decimals are stale converts nothing: send reads the
// asset and converts with its live decimals, once for the whole send.
func TestSendConvertsWithLiveDecimals(t *testing.T) {
	network := &liveAssetNetwork{
		asset:    models.AssetParams{Name: "Old Token", UnitName: "OLD", Decimals: 0, Total: 1_000_000, Creator: liveFrom},
		holdings: 1_000,
	}
	app, store := liveAssetApp(t, network, staleOld)

	result, err := app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "5", AssetRef: "OLD", FromRaw: []string{liveFrom}, ToRaw: []string{liveTo},
	})
	if err != nil {
		t.Fatalf("ExecuteSend() error = %v", err)
	}
	if result.Amount.Raw != 5 || result.Amount.Meta.Decimals != 0 || result.Amount.Meta.Source != asa.SourceLive {
		t.Fatalf("amount = %+v, want 5 base units converted with the live 0 decimals", result.Amount)
	}
	if len(result.NonAtomic.Items) != 1 || !strings.Contains(result.NonAtomic.Items[0].Error, "transaction failed") {
		t.Fatalf("items = %+v, want one prepared transaction that failed to sign", result.NonAtomic.Items)
	}
	if got := network.count("asset"); got != 1 {
		t.Fatalf("algod asset reads = %d, want 1", got)
	}
	assertCachedASA(t, app, store, cache.ASAInfo{Name: "Old Token", UnitName: "OLD", Decimals: 0})
}

// A name that stood for another asset is refused before anything is
// prepared, and the cache entry is corrected.
func TestSendRefusesAStaleCachedName(t *testing.T) {
	network := &liveAssetNetwork{asset: liveNew, holdings: 1_000}
	app, store := liveAssetApp(t, network, staleOld)

	result, err := app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "5", AssetRef: "old", FromRaw: []string{liveFrom}, ToRaw: []string{liveTo},
	})
	if err == nil {
		t.Fatalf("ExecuteSend() = %+v, want the stale name refused", result)
	}
	for _, want := range []string{`the cached name "old" no longer matches asset 900100 on testnet`, "the cache entry has been corrected", "run the command again"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err, want)
		}
	}
	if result != nil {
		t.Fatalf("ExecuteSend() result = %+v, want none", result)
	}
	if got := network.count("params") + network.count("account"); got != 0 {
		t.Fatalf("network saw %d account/params reads: a transaction was being prepared", got)
	}
	assertCachedASA(t, app, store, cache.ASAInfo{Name: "New Thing", UnitName: "NEW", Decimals: 2})
}

// An asset named by its ID is the asset the user meant, whatever the cache
// called it: send proceeds with the live metadata.
func TestSendByIDUsesLiveMetadataOverAStaleName(t *testing.T) {
	network := &liveAssetNetwork{asset: liveNew, holdings: 1_000}
	app, store := liveAssetApp(t, network, staleOld)

	plan, err := app.PrepareSend(context.Background(), SendRequest{
		AmountText: "5", AssetRef: "900100", FromRaw: []string{liveFrom}, ToRaw: []string{liveTo},
	})
	if err != nil {
		t.Fatalf("PrepareSend() error = %v", err)
	}
	if plan.Amount.Raw != 500 || plan.Amount.Meta.UnitName != "NEW" {
		t.Fatalf("amount = %+v, want 500 base units of NEW", plan.Amount)
	}
	assertCachedASA(t, app, store, cache.ASAInfo{Name: "New Thing", UnitName: "NEW", Decimals: 2})
}

// A built-in asset comes from the reviewed table: no algod read.
func TestSendOfABuiltinAssetReadsNothing(t *testing.T) {
	network := &liveAssetNetwork{asset: liveNew}
	app, _ := liveAssetApp(t, network, staleOld)

	plan, err := app.PrepareSend(context.Background(), SendRequest{
		AmountText: "5", AssetRef: "usdc", FromRaw: []string{liveFrom}, ToRaw: []string{liveTo},
	})
	if err != nil {
		t.Fatalf("PrepareSend() error = %v", err)
	}
	if plan.Amount.Meta.Source != asa.SourceBuiltin || plan.Amount.Raw != 5_000_000 {
		t.Fatalf("amount = %+v, want the built-in USDC with 6 decimals", plan.Amount)
	}
	if got := network.count("asset"); got != 0 {
		t.Fatalf("algod asset reads = %d, want 0 for a built-in asset", got)
	}
}

// When algod cannot be read the command fails with algod's error and the
// cache is left as it was.
func TestSendFailsWhenTheAssetCannotBeRead(t *testing.T) {
	for _, ref := range []string{"OLD", "900100"} {
		t.Run(ref, func(t *testing.T) {
			network := &liveAssetNetwork{asset: liveNew, fail: true}
			app, store := liveAssetApp(t, network, staleOld)

			_, err := app.PrepareSend(context.Background(), SendRequest{
				AmountText: "5", AssetRef: ref, FromRaw: []string{liveFrom}, ToRaw: []string{liveTo},
			})
			if err == nil || !strings.Contains(err.Error(), "failed to get asset 900100") || !strings.Contains(err.Error(), "algod is down") {
				t.Fatalf("PrepareSend() error = %v, want the algod error", err)
			}
			assertCachedASA(t, app, store, staleOld)
		})
	}
}

// sweep converts its leaving amount with the live decimals and reads the
// asset once for the asset and the amount together.
func TestSweepConvertsLeavingWithLiveDecimals(t *testing.T) {
	network := &liveAssetNetwork{
		asset:    models.AssetParams{Name: "Old Token", UnitName: "OLD", Decimals: 0, Total: 1_000_000, Creator: liveFrom},
		holdings: 10_000,
	}
	app, store := liveAssetApp(t, network, cache.ASAInfo{Name: "Old Token", UnitName: "OLD", Decimals: 2})

	result, err := app.Sweep(context.Background(), SweepRequest{
		AssetRef: "OLD", FromRaw: []string{liveFrom}, ToRaw: liveTo, LeavingText: "5",
	})
	if result == nil {
		t.Fatalf("Sweep() error = %v, want a result", err)
	}
	if result.Leaving.Raw != 5 || result.Asset.Decimals != 0 {
		t.Fatalf("leaving = %+v, want 5 base units with the live 0 decimals", result.Leaving)
	}
	if len(result.Items) != 1 || result.Items[0].Amount.Raw != 9_995 {
		t.Fatalf("items = %+v, want one transfer of 9995 base units", result.Items)
	}
	if got := network.count("asset"); got != 1 {
		t.Fatalf("algod asset reads = %d, want 1", got)
	}
	assertCachedASA(t, app, store, cache.ASAInfo{Name: "Old Token", UnitName: "OLD", Decimals: 0})
}

func TestSweepRefusesAStaleCachedName(t *testing.T) {
	network := &liveAssetNetwork{asset: liveNew, holdings: 10_000}
	app, store := liveAssetApp(t, network, staleOld)

	result, err := app.Sweep(context.Background(), SweepRequest{
		AssetRef: "OLD", FromRaw: []string{liveFrom}, ToRaw: liveTo,
	})
	if err == nil || !strings.Contains(err.Error(), "no longer matches asset 900100") {
		t.Fatalf("Sweep() = %+v, %v; want the stale name refused", result, err)
	}
	if got := network.count("account") + network.count("params"); got != 0 {
		t.Fatalf("network saw %d account/params reads: the sweep went on", got)
	}
	assertCachedASA(t, app, store, cache.ASAInfo{Name: "New Thing", UnitName: "NEW", Decimals: 2})
}

// The other commands that build a transaction for an asset refuse a stale
// name the same way, before anything is prepared.
func TestOtherTransactionCommandsRefuseAStaleCachedName(t *testing.T) {
	commands := map[string]func(*App) error{
		"optin": func(app *App) error {
			_, err := app.OptIn(context.Background(), OptInRequest{Account: liveFrom, AssetRef: "OLD"})
			return err
		},
		"optout": func(app *App) error {
			_, err := app.OptOut(context.Background(), OptOutRequest{Account: liveFrom, AssetRef: "OLD"})
			return err
		},
		"appcall foreign asset": func(app *App) error {
			_, err := app.AppCallRaw(context.Background(), AppCallRawRequest{AppID: 1, From: liveFrom, AssetRefs: []cmdspec.AssetRef{"OLD"}})
			return err
		},
	}
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			network := &liveAssetNetwork{asset: liveNew, holdings: 1_000}
			app, store := liveAssetApp(t, network, staleOld)
			if err := run(app); err == nil || !strings.Contains(err.Error(), "no longer matches asset 900100") {
				t.Fatalf("error = %v, want the stale name refused", err)
			}
			if got := network.count("account") + network.count("params"); got != 0 {
				t.Fatalf("network saw %d account/params reads: a transaction was being prepared", got)
			}
			assertCachedASA(t, app, store, cache.ASAInfo{Name: "New Thing", UnitName: "NEW", Decimals: 2})
		})
	}
}

// Display keeps using the cache as it is: balance and asa list make no
// asset read and show the cached metadata.
func TestDisplayPathsUseTheCache(t *testing.T) {
	network := &liveAssetNetwork{asset: liveNew, holdings: 1_000}
	app, store := liveAssetApp(t, network, staleOld)
	ctx := context.Background()

	balance, err := app.Balance(ctx, BalanceRequest{Args: []string{liveFrom}})
	if err != nil {
		t.Fatalf("Balance() error = %v", err)
	}
	if len(balance.Single.Assets) != 1 || balance.Single.Assets[0].UnitName != "OLD" || balance.Single.Assets[0].Decimals != 6 {
		t.Fatalf("balance assets = %+v, want the cached OLD with 6 decimals", balance.Single.Assets)
	}
	if meta, err := app.ResolveAssetMetadata("OLD"); err != nil || meta.Decimals != 6 {
		t.Fatalf("ResolveAssetMetadata(OLD) = %+v, %v; want the cached entry", meta, err)
	}
	list, err := app.ASACacheList(ctx)
	if err != nil {
		t.Fatalf("ASACacheList() error = %v", err)
	}
	found := false
	for _, item := range list.ASAs {
		if item.AssetID == liveAssetID {
			found = item.UnitName == "OLD" && item.Decimals == 6
		}
	}
	if !found {
		t.Fatalf("asa list = %+v, want the cached OLD with 6 decimals", list.ASAs)
	}
	if got := network.count("asset"); got != 0 {
		t.Fatalf("algod asset reads = %d, want 0 on display paths", got)
	}
	assertCachedASA(t, app, store, staleOld)
}
