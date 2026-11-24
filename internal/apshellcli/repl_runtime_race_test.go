// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// TestAutocompleteAndAliasLookupsRaceSafeWithSignerCacheUpdates exercises the
// full REPL autocomplete path (discoverCompleter -> CompleterDeps -> shellrepl
// -> EnsureSignerCache), display formatting (FormatAddress /
// FormatKeyTypeForDisplay), and alias mutations (AddAliasWithContext /
// RemoveAlias -> ownedAuthAddresses) while a background goroutine resets and
// repopulates the signer cache as the SSH tunnel disconnect monitor does.
func TestAutocompleteAndAliasLookupsRaceSafeWithSignerCacheUpdates(t *testing.T) {
	addr1 := types.Address{11}.String()
	addr2 := types.Address{12}.String()
	keys := []signerapi.KeyInfo{
		{Address: addr1, KeyType: "ed25519", AuthorizationKind: "ed25519"},
		{Address: addr2, KeyType: "aplane.falcon1024.v1", AuthorizationKind: "logic_sig"},
	}

	signerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: keys})
	}))
	defer signerSrv.Close()

	algodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(models.Account{Address: addr1})
	}))
	defer algodSrv.Close()

	algodClient, err := algod.MakeClient(algodSrv.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}

	dataDir := t.TempDir()
	store := cache.NewStore(dataDir)
	eng := engine.NewEngine("testnet",
		engine.WithDataDir(dataDir),
		engine.WithCacheStore(store),
		engine.WithAlgodClient(algodClient),
		engine.WithAliasCache(cache.LoadAliasCacheFromStore(store)),
		engine.WithASACache(cache.LoadASACacheFromStore(store, "testnet")),
		engine.WithSetCache(cache.LoadSetCacheFromStore(store)),
		engine.WithAuthCache(cache.LoadAuthCacheFromStore(store, "testnet")),
	)
	eng.Connection.SignerClient = signerclient.NewSignerClient(signerSrv.URL)

	cfg := config.DefaultConfig()
	app := apshellapp.New(eng, cfg, dataDir)
	repl := &REPLState{App: app}

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
			if i%2 == 0 {
				_ = eng.PopulateSignerCache(keys)
			} else {
				eng.ResetSignerCache(false)
			}
		}
	}()

	// All command-goroutine readers/writers (Tab autocomplete, address/keytype
	// display, alias mutations) run on the main test goroutine, matching the
	// REPL's runtimeMu serialization, while the background goroutine simulates
	// asynchronous tunnel disconnects and signer cache refreshes.
	deletePrefix := []rune("delete " + addr1[:3])
	balancePrefix := []rune("balance " + addr2[:3])
	for i := 0; i < 40; i++ {
		completer := repl.discoverCompleter()
		_, _ = completer.Do(deletePrefix, len(deletePrefix))
		_, _ = completer.Do(balancePrefix, len(balancePrefix))
		_ = app.FormatAddress(addr1)
		_ = app.FormatKeyTypeForDisplay(addr2, "aplane.falcon1024.v1")
		if _, err := eng.AddAliasWithContext(context.Background(), "alice", addr1); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("AddAliasWithContext() error = %v", err)
		}
		if _, err := eng.RemoveAlias("alice"); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("RemoveAlias() error = %v", err)
		}
	}

	close(stop)
	wg.Wait()
}
