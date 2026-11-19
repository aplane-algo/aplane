// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientdata"
)

var testCacheStore *cache.Store

func TestMain(m *testing.M) {

	// Use a temp directory for cache files so tests don't create
	// a "cache/" directory inside the source tree.
	tmpDir, err := os.MkdirTemp("", "engine-test-cache-*")
	if err != nil {
		panic("failed to create temp cache dir: " + err.Error())
	}
	testCacheStore = cache.NewStore(tmpDir)
	// Some engine tests still exercise cwd-relative cache paths. Keep those
	// writes in the same temp cache root used by store-backed helpers.
	if err := os.Chdir(tmpDir); err != nil {
		panic("failed to chdir to temp engine test dir: " + err.Error())
	}
	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name    string
		network string
		opts    []EngineOption
		wantErr bool
	}{
		{
			name:    "create with mainnet",
			network: "mainnet",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "create with testnet",
			network: "testnet",
			opts:    nil,
			wantErr: false,
		},
		{
			name:    "create with betanet",
			network: "betanet",
			opts:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng, err := NewEngine(tt.network, tt.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if eng.Network != tt.network {
					t.Errorf("NewEngine() network = %v, want %v", eng.Network, tt.network)
				}
			}
		})
	}
}

func TestEngineWithOptions(t *testing.T) {
	// Test with alias cache
	aliasCache := cache.AliasCache{
		Aliases: map[string]string{"alice": "ABC123"},
	}

	eng, err := NewEngine("testnet", WithAliasCache(aliasCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if eng.AliasCache.Aliases["alice"] != "ABC123" {
		t.Error("AliasCache not set correctly")
	}

	// Test with signer cache
	signerCache := cache.SignerCache{
		Keys: map[string]string{"ABC123": "ed25519"},
	}

	eng, err = NewEngine("testnet", WithSignerCache(signerCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if eng.SignerCache.Keys["ABC123"] != "ed25519" {
		t.Error("SignerCache not set correctly")
	}

	// Test with set cache
	setCache := cache.SetCache{
		Sets: map[string][]string{"validators": {"ADDR1", "ADDR2"}},
	}

	eng, err = NewEngine("testnet", WithSetCache(setCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if len(eng.SetCache.Sets["validators"]) != 2 {
		t.Error("SetCache not set correctly")
	}
}

func TestSetNetwork(t *testing.T) {
	eng, _ := NewEngine("testnet")

	tests := []struct {
		name    string
		network string
		wantErr bool
	}{
		{"switch to mainnet", "mainnet", false},
		{"switch to testnet", "testnet", false},
		{"switch to betanet", "betanet", false},
		{"switch to custom network", "voi_mainnet", false},
		{"invalid network", "InvalidNet", true},
		{"empty network", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eng.SetNetwork(context.Background(), tt.network, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetNetwork() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && eng.Network != tt.network {
				t.Errorf("SetNetwork() network = %v, want %v", eng.Network, tt.network)
			}
		})
	}
}

func TestSetNetworkLoadsPerNetworkCachesWithoutBleedThrough(t *testing.T) {
	tmpDir := t.TempDir()
	store := cache.NewStore(tmpDir)

	testnetASACache := cache.LoadASACacheFromStore(store, "testnet")
	testnetASACache.Assets[999001] = cache.ASAInfo{Name: "Testnet Token", UnitName: "TST", Decimals: 3}
	if err := testnetASACache.SaveCache("testnet"); err != nil {
		t.Fatalf("failed to save testnet ASA cache: %v", err)
	}
	testnetAuthCache := cache.NewAuthAddressCacheForStore(store)
	testnetAuthCache.AuthAddresses["ADDR_TEST"] = "AUTH_TEST"
	if err := testnetAuthCache.SaveCache("testnet"); err != nil {
		t.Fatalf("failed to save testnet auth cache: %v", err)
	}

	mainnetASACache := cache.LoadASACacheFromStore(store, "mainnet")
	mainnetASACache.Assets[999002] = cache.ASAInfo{Name: "Mainnet Token", UnitName: "MNT", Decimals: 6}
	if err := mainnetASACache.SaveCache("mainnet"); err != nil {
		t.Fatalf("failed to save mainnet ASA cache: %v", err)
	}
	mainnetAuthCache := cache.NewAuthAddressCacheForStore(store)
	mainnetAuthCache.AuthAddresses["ADDR_MAIN"] = "AUTH_MAIN"
	if err := mainnetAuthCache.SaveCache("mainnet"); err != nil {
		t.Fatalf("failed to save mainnet auth cache: %v", err)
	}

	eng, err := NewEngine("testnet",
		WithCacheStore(store),
		WithASACache(cache.LoadASACacheFromStore(store, "testnet")),
		WithAuthCache(cache.LoadAuthCacheFromStore(store, "testnet")),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	if _, ok := eng.AsaCache.Assets[999001]; !ok {
		t.Fatal("expected testnet-specific ASA cache entry at startup")
	}
	if _, ok := eng.AsaCache.Assets[999002]; ok {
		t.Fatal("unexpected mainnet ASA entry present in testnet cache")
	}
	if got, ok := eng.AuthCache.GetAuthAddress("ADDR_TEST"); !ok || got != "AUTH_TEST" {
		t.Fatalf("testnet auth cache = (%q, %v), want (AUTH_TEST, true)", got, ok)
	}
	if _, ok := eng.AuthCache.GetAuthAddress("ADDR_MAIN"); ok {
		t.Fatal("unexpected mainnet auth entry present in testnet cache")
	}

	if err := eng.SetNetwork(context.Background(), "mainnet", nil); err != nil {
		t.Fatalf("SetNetwork(mainnet) error = %v", err)
	}
	if _, ok := eng.AsaCache.Assets[999002]; !ok {
		t.Fatal("expected mainnet-specific ASA cache entry after switch")
	}
	if _, ok := eng.AsaCache.Assets[999001]; ok {
		t.Fatal("unexpected testnet ASA entry present after switching to mainnet")
	}
	if got, ok := eng.AuthCache.GetAuthAddress("ADDR_MAIN"); !ok || got != "AUTH_MAIN" {
		t.Fatalf("mainnet auth cache = (%q, %v), want (AUTH_MAIN, true)", got, ok)
	}
	if _, ok := eng.AuthCache.GetAuthAddress("ADDR_TEST"); ok {
		t.Fatal("unexpected testnet auth entry present after switching to mainnet")
	}

	if err := eng.SetNetwork(context.Background(), "testnet", nil); err != nil {
		t.Fatalf("SetNetwork(testnet) error = %v", err)
	}
	if _, ok := eng.AsaCache.Assets[999001]; !ok {
		t.Fatal("expected testnet-specific ASA cache entry after switching back")
	}
	if _, ok := eng.AsaCache.Assets[999002]; ok {
		t.Fatal("unexpected mainnet ASA entry present after switching back to testnet")
	}
	if got, ok := eng.AuthCache.GetAuthAddress("ADDR_TEST"); !ok || got != "AUTH_TEST" {
		t.Fatalf("reloaded testnet auth cache = (%q, %v), want (AUTH_TEST, true)", got, ok)
	}
	if _, ok := eng.AuthCache.GetAuthAddress("ADDR_MAIN"); ok {
		t.Fatal("unexpected mainnet auth entry present after switching back to testnet")
	}
}

// authRebuildNode is an algod whose account queries report authAddr for
// every account. When gate is set, each query first signals queried and then
// waits for gate to close.
type authRebuildNode struct {
	authAddr string
	queried  chan struct{}
	gate     chan struct{}
	queries  atomic.Int32
}

func (n *authRebuildNode) serve(t *testing.T) *algod.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v2/accounts/") {
			http.NotFound(w, r)
			return
		}
		n.queries.Add(1)
		if n.gate != nil {
			select {
			case n.queried <- struct{}{}:
			default:
			}
			<-n.gate
		}
		address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Account{Address: address, AuthAddr: n.authAddr})
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client
}

func authRebuildEngine(t *testing.T, dataDir, address string, client *algod.Client) *Engine {
	t.Helper()
	signerCache := cache.NewSignerCache()
	signerCache.AddAddress(address, "ed25519")
	eng, err := NewEngine("testnet",
		WithDataDir(dataDir),
		WithCacheStore(cache.NewStore(dataDir)),
		WithAlgodClient(client),
		WithSignerCache(signerCache),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return eng
}

// A network switch saves the rebuilt auth cache under the client-data lock,
// as every other auth-cache write does: while another holder has the lock,
// the switch waits, so it cannot save over a write the holder makes.
func TestSetNetworkRebuildsTheAuthCacheUnderTheClientDataLock(t *testing.T) {
	dataDir := t.TempDir()
	account, authorizer := testAddress(70).String(), testAddress(71).String()
	node := &authRebuildNode{authAddr: authorizer}
	client := node.serve(t)
	eng := authRebuildEngine(t, dataDir, account, client)

	held, release := make(chan struct{}), make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- clientdata.WithExclusiveLock(dataDir, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	switched := make(chan error, 1)
	go func() { switched <- eng.SetNetwork(context.Background(), "testnet", client) }()
	select {
	case err := <-switched:
		close(release)
		t.Fatalf("SetNetwork() returned (%v) while another holder had the client-data lock", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("lock holder error = %v", err)
	}
	select {
	case err := <-switched:
		if err != nil {
			t.Fatalf("SetNetwork() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetNetwork() did not finish after the lock was released")
	}
	if got, ok := eng.AuthCache.GetAuthAddress(account); !ok || got != authorizer {
		t.Fatalf("auth cache entry = (%q, %v), want (%q, true)", got, ok, authorizer)
	}
	saved := cache.LoadAuthCacheFromStore(cache.NewStore(dataDir), "testnet")
	if got, ok := saved.GetAuthAddress(account); !ok || got != authorizer {
		t.Fatalf("saved auth cache entry = (%q, %v), want (%q, true)", got, ok, authorizer)
	}
}

// The auth-cache rebuild queries algod before it takes the client-data lock,
// so another apshell process on the same data directory can write while the
// queries run. The merge under the lock reloads the alias book and the auth
// cache, so what that process wrote is kept: here an alias and its auth
// entry, which the rebuild did not query. Both entry points share the
// rebuild.
func TestAuthCacheRebuildQueriesAlgodOutsideTheClientDataLock(t *testing.T) {
	for name, rebuild := range map[string]func(*Engine, *algod.Client) error{
		"SetNetwork": func(eng *Engine, client *algod.Client) error {
			return eng.SetNetwork(context.Background(), "testnet", client)
		},
		"RefreshAuthCache": func(eng *Engine, _ *algod.Client) error {
			return eng.RefreshAuthCache(context.Background())
		},
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			account, authorizer := testAddress(74).String(), testAddress(75).String()
			carol, carolAuth := testAddress(76).String(), testAddress(77).String()
			node := &authRebuildNode{authAddr: authorizer, queried: make(chan struct{}, 1), gate: make(chan struct{})}
			client := node.serve(t)
			eng := authRebuildEngine(t, dataDir, account, client)
			var once atomic.Bool
			open := func() {
				if once.CompareAndSwap(false, true) {
					close(node.gate)
				}
			}
			defer open()

			rebuilt := make(chan error, 1)
			go func() { rebuilt <- rebuild(eng, client) }()
			select {
			case <-node.queried:
			case <-time.After(5 * time.Second):
				t.Fatal("the rebuild never queried algod")
			}

			// Another process adds an alias and its auth entry while the
			// rebuild's query is still out.
			wrote := make(chan error, 1)
			go func() {
				wrote <- clientdata.WithExclusiveLock(dataDir, func() error {
					store := cache.NewStore(dataDir)
					aliases := cache.LoadAliasCacheFromStore(store)
					if aliases.Aliases == nil {
						aliases.Aliases = map[string]string{}
					}
					aliases.Aliases["carol"] = carol
					if err := aliases.SaveCacheLocked(); err != nil {
						return err
					}
					auth := cache.LoadAuthCacheFromStore(store, "testnet")
					auth.AuthAddresses[carol] = carolAuth
					return auth.SaveCache("testnet")
				})
			}()
			select {
			case err := <-wrote:
				if err != nil {
					t.Fatalf("other process's write error = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("another process could not take the client-data lock while the rebuild queried algod")
				open()
				if err := <-wrote; err != nil {
					t.Fatalf("other process's write error = %v", err)
				}
			}
			open()
			if err := <-rebuilt; err != nil {
				t.Fatalf("rebuild error = %v", err)
			}
			if got, ok := eng.AuthCache.GetAuthAddress(account); !ok || got != authorizer {
				t.Fatalf("auth cache entry = (%q, %v), want (%q, true)", got, ok, authorizer)
			}
			if got, ok := eng.AuthCache.GetAuthAddress(carol); !ok || got != carolAuth {
				t.Fatalf("other process's auth entry = (%q, %v), want (%q, true) kept", got, ok, carolAuth)
			}
		})
	}
}

// While a rebuild's queries are out, another apshell process confirms a
// rekey of one of the accounts, or an unrekey, and its refresh writes the new
// authorizer. The rebuild's answer for that account was read before and is
// older, so the merge keeps the other process's entry: a later signing names
// the authorizer that now signs.
func TestAuthCacheRebuildKeepsAnEntryAnotherProcessWroteMeanwhile(t *testing.T) {
	account, newAuth := testAddress(78).String(), testAddress(79).String()
	for _, tc := range []struct {
		name                         string
		onDisk, answered, otherWrote string
	}{
		{"a rekey another process confirmed", "", "", newAuth},
		{"an unrekey another process confirmed", newAuth, newAuth, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			store := cache.NewStore(dataDir)
			seed := cache.NewAuthAddressCacheForStore(store)
			seed.AuthAddresses[account] = tc.onDisk
			if err := seed.SaveCache("testnet"); err != nil {
				t.Fatal(err)
			}
			node := &authRebuildNode{authAddr: tc.answered, queried: make(chan struct{}, 1), gate: make(chan struct{})}
			client := node.serve(t)
			eng := authRebuildEngine(t, dataDir, account, client)
			var once atomic.Bool
			open := func() {
				if once.CompareAndSwap(false, true) {
					close(node.gate)
				}
			}
			defer open()

			rebuilt := make(chan error, 1)
			go func() { rebuilt <- eng.SetNetwork(context.Background(), "testnet", client) }()
			select {
			case <-node.queried:
			case <-time.After(5 * time.Second):
				t.Fatal("the rebuild never queried algod")
			}
			if err := clientdata.WithExclusiveLock(dataDir, func() error {
				auth := cache.LoadAuthCacheFromStore(store, "testnet")
				auth.AuthAddresses[account] = tc.otherWrote
				return auth.SaveCache("testnet")
			}); err != nil {
				t.Fatalf("other process's write error = %v", err)
			}
			open()
			if err := <-rebuilt; err != nil {
				t.Fatalf("SetNetwork() error = %v", err)
			}
			if got, ok := eng.AuthCache.GetAuthAddress(account); !ok || got != tc.otherWrote {
				t.Fatalf("auth cache entry = (%q, %v), want the other process's (%q, true)", got, ok, tc.otherWrote)
			}
			saved := cache.LoadAuthCacheFromStore(store, "testnet")
			if got, ok := saved.GetAuthAddress(account); !ok || got != tc.otherWrote {
				t.Fatalf("saved auth cache entry = (%q, %v), want the other process's (%q, true)", got, ok, tc.otherWrote)
			}
		})
	}
}

// The auth-cache rebuild copies the signer's addresses and lets go of the
// signer cache before it queries algod, so a tunnel disconnect, which resets
// the signer cache from the tunnel's monitor goroutine, does not wait for the
// queries to finish. Both entry points share the rebuild.
func TestAuthCacheRebuildLeavesTheSignerCacheFreeDuringQueries(t *testing.T) {
	for name, rebuild := range map[string]func(*Engine, *algod.Client) error{
		"SetNetwork": func(eng *Engine, client *algod.Client) error {
			return eng.SetNetwork(context.Background(), "testnet", client)
		},
		"RefreshAuthCache": func(eng *Engine, _ *algod.Client) error {
			return eng.RefreshAuthCache(context.Background())
		},
	} {
		t.Run(name, func(t *testing.T) {
			node := &authRebuildNode{queried: make(chan struct{}, 1), gate: make(chan struct{})}
			client := node.serve(t)
			eng := authRebuildEngine(t, t.TempDir(), testAddress(72).String(), client)
			var once atomic.Bool
			open := func() {
				if once.CompareAndSwap(false, true) {
					close(node.gate)
				}
			}
			defer open()

			rebuilt := make(chan error, 1)
			go func() { rebuilt <- rebuild(eng, client) }()
			select {
			case <-node.queried:
			case <-time.After(5 * time.Second):
				t.Fatal("the rebuild never queried algod")
			}

			reset := make(chan struct{})
			go func() {
				eng.resetSignerCache(false)
				close(reset)
			}()
			select {
			case <-reset:
			case <-time.After(2 * time.Second):
				t.Error("a signer-cache reset waited on the rebuild's algod queries")
			}
			open()
			if err := <-rebuilt; err != nil {
				t.Fatalf("rebuild error = %v", err)
			}
			<-reset
		})
	}
}

// The rebuild queries algod with the caller's context: a cancelled one sends
// no query, and the switch still completes.
func TestSetNetworkQueriesAlgodWithTheCallersContext(t *testing.T) {
	node := &authRebuildNode{}
	client := node.serve(t)
	eng := authRebuildEngine(t, t.TempDir(), testAddress(73).String(), client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := eng.SetNetwork(ctx, "testnet", client); err != nil {
		t.Fatalf("SetNetwork() error = %v", err)
	}
	if got := node.queries.Load(); got != 0 {
		t.Fatalf("algod account queries with a cancelled context = %d, want 0", got)
	}
}

func TestWriteMode(t *testing.T) {
	eng, _ := NewEngine("testnet")

	// Default should be false
	if eng.GetWriteMode() {
		t.Error("Default write mode should be false")
	}

	// Enable write mode
	eng.SetWriteMode(true)
	if !eng.GetWriteMode() {
		t.Error("Write mode should be true after SetWriteMode(true)")
	}

	// Disable write mode
	eng.SetWriteMode(false)
	if eng.GetWriteMode() {
		t.Error("Write mode should be false after SetWriteMode(false)")
	}
}

func TestGetNetwork(t *testing.T) {
	eng, _ := NewEngine("testnet")

	if eng.GetNetwork() != "testnet" {
		t.Errorf("GetNetwork() = %v, want testnet", eng.GetNetwork())
	}

	eng.Network = "mainnet"
	if eng.GetNetwork() != "mainnet" {
		t.Errorf("GetNetwork() = %v, want mainnet", eng.GetNetwork())
	}
}
