// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	util "github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnreview"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestGetStatus(t *testing.T) {
	eng := setupTestEngine(t)

	// Test disconnected state
	result := eng.GetStatus()

	if result.Network != "testnet" {
		t.Errorf("GetStatus() network = %v, want testnet", result.Network)
	}
	if result.IsConnected {
		t.Error("GetStatus() should not be connected initially")
	}
	if result.SigningMode != "disconnected" {
		t.Errorf("GetStatus() SigningMode = %v, want 'disconnected'", result.SigningMode)
	}

	eng.Connection.SignerClient = &util.Client{}
	eng.Connection.ConnectionTarget = "ssh://signer"
	result = eng.GetStatus()

	if !result.IsConnected {
		t.Error("GetStatus() should be connected with SignerClient")
	}
	if result.SigningMode != "remote" {
		t.Errorf("GetStatus() SigningMode = %v, want 'remote'", result.SigningMode)
	}
	if result.ConnectionTarget != "ssh://signer" {
		t.Errorf("GetStatus() ConnectionTarget = %q, want ssh://signer", result.ConnectionTarget)
	}
}

// A status read while the tunnel drops shows the connection and its target
// from the same moment: never connected with no target, or a target while
// disconnected. The goroutine sets and clears them under Mu, as
// ConnectWithTunnel and the disconnect callback do.
func TestGetStatusConnectionSnapshotIsConsistent(t *testing.T) {
	eng := setupTestEngine(t)
	client := &util.Client{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		state := eng.Connection
		for {
			select {
			case <-stop:
				return
			default:
			}
			state.Mu.Lock()
			state.SignerClient, state.ConnectionTarget = client, "signer (ssh:1127)"
			state.Mu.Unlock()
			state.Mu.Lock()
			state.SignerClient, state.ConnectionTarget = nil, ""
			state.Mu.Unlock()
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
	}()

	for i := 0; i < 20000; i++ {
		status := eng.GetStatus()
		if status.IsConnected != (status.ConnectionTarget != "") || status.IsConnected != (status.SigningMode == "remote") {
			t.Fatalf("snapshot %d: connected = %v, target = %q, mode = %q; want one moment's connection", i, status.IsConnected, status.ConnectionTarget, status.SigningMode)
		}
	}
}

func TestGetStatusWithCaches(t *testing.T) {
	eng := setupTestEngine(t)

	// Add entries to caches
	eng.AsaCache.Assets = map[uint64]cache.ASAInfo{
		12345: {UnitName: "TEST", Name: "Test Token", Decimals: 6},
		67890: {UnitName: "USDC", Name: "USD Coin", Decimals: 6},
	}
	eng.AliasCache.Aliases = map[string]string{
		"alice": "ADDR1",
		"bob":   "ADDR2",
		"carol": "ADDR3",
	}
	eng.SetCache.Sets = map[string][]string{
		"team": {"ADDR1", "ADDR2"},
	}
	eng.SignerCache.Keys = map[string]string{
		"ADDR1": "ed25519",
	}

	result := eng.GetStatus()

	if result.ASACacheCount != 2 {
		t.Errorf("GetStatus() ASACacheCount = %d, want 2", result.ASACacheCount)
	}
	if result.AliasCacheCount != 3 {
		t.Errorf("GetStatus() AliasCacheCount = %d, want 3", result.AliasCacheCount)
	}
	if result.SetCacheCount != 1 {
		t.Errorf("GetStatus() SetCacheCount = %d, want 1", result.SetCacheCount)
	}
	if result.SignerCacheCount != 1 {
		t.Errorf("GetStatus() SignerCacheCount = %d, want 1", result.SignerCacheCount)
	}
}

func TestDisconnectClearsSignerCacheAndConnectedStatus(t *testing.T) {
	eng := setupTestEngine(t)
	eng.Connection.SignerClient = &util.Client{}
	eng.Connection.ConnectionTarget = "ssh://signer"
	eng.SignerCache.Keys = map[string]string{
		"ADDR1": "ed25519",
		"ADDR2": "aplane.falcon1024.v1",
	}

	eng.Disconnect()
	if eng.IsConnected() {
		t.Fatal("engine should report disconnected after Disconnect()")
	}
	if got := eng.GetConnectionTarget(); got != "" {
		t.Fatalf("GetConnectionTarget() = %q, want empty", got)
	}
	if got := eng.SignerCache.Count(); got != 0 {
		t.Fatalf("SignerCache.Count() = %d, want 0 after disconnect cleanup", got)
	}

	status := eng.GetStatus()
	if status.IsConnected {
		t.Fatal("GetStatus().IsConnected = true, want false after disconnect")
	}
	if status.SignerCacheCount != 0 {
		t.Fatalf("GetStatus().SignerCacheCount = %d, want 0 after disconnect", status.SignerCacheCount)
	}
}

func TestListAccounts(t *testing.T) {
	eng := setupTestEngine(t)

	// Empty state
	accounts, err := eng.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("ListAccounts() should return empty list initially, got %d", len(accounts))
	}

	// Add aliases and signers
	eng.AliasCache.Aliases["alice"] = "ADDR_ALICE"
	eng.AliasCache.Aliases["bob"] = "ADDR_BOB"
	eng.SignerCache.AddAddress("ADDR_ALICE", "ed25519", "ed25519")
	eng.SignerCache.AddAddress("ADDR_SIGNER", "falcon1024", "native_pq")

	accounts, err = eng.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}

	// Should have 3 unique addresses (ADDR_ALICE, ADDR_BOB, ADDR_SIGNER)
	if len(accounts) != 3 {
		t.Errorf("ListAccounts() count = %d, want 3", len(accounts))
	}

	// Find alice's account
	var aliceAccount *AccountInfo
	for i := range accounts {
		if accounts[i].Address == "ADDR_ALICE" {
			aliceAccount = &accounts[i]
			break
		}
	}

	switch {
	case aliceAccount == nil:
		t.Fatal("ListAccounts() should include ADDR_ALICE")
	case aliceAccount.Alias != "alice":
		t.Errorf("ListAccounts() alice alias = %v, want 'alice'", aliceAccount.Alias)
	case !aliceAccount.IsSignable:
		t.Error("ListAccounts() alice should be signable")
	case aliceAccount.KeyType != "ed25519":
		t.Errorf("ListAccounts() alice keyType = %v, want 'ed25519'", aliceAccount.KeyType)
	}
}

func TestGetSignableAddresses(t *testing.T) {
	eng := setupTestEngine(t)

	// Empty state
	addrs := eng.GetSignableAddresses()
	if len(addrs) != 0 {
		t.Errorf("GetSignableAddresses() should return empty list initially, got %d", len(addrs))
	}

	// Add signer keys
	eng.SignerCache.AddAddress("ADDR1", "ed25519", "ed25519")
	eng.SignerCache.AddAddress("ADDR2", "falcon1024", "native_pq")

	addrs = eng.GetSignableAddresses()
	if len(addrs) != 2 {
		t.Errorf("GetSignableAddresses() count = %d, want 2", len(addrs))
	}

	// Should be sorted
	if len(addrs) >= 2 && addrs[0] > addrs[1] {
		t.Error("GetSignableAddresses() should return sorted addresses")
	}
}

func TestResolveAddress(t *testing.T) {
	eng := setupTestEngine(t)

	// Valid address format (58 chars with valid checksum)
	validAddr := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	// Add alias
	eng.AliasCache.Aliases["alice"] = validAddr

	tests := []struct {
		name      string
		input     string
		wantAddr  string
		wantAlias string
		wantErr   bool
	}{
		{
			name:      "resolve alias",
			input:     "alice",
			wantAddr:  validAddr,
			wantAlias: "alice",
			wantErr:   false,
		},
		{
			name:      "resolve raw address",
			input:     validAddr,
			wantAddr:  validAddr,
			wantAlias: "alice", // Should find the alias
			wantErr:   false,
		},
		{
			name:    "unknown alias",
			input:   "unknown",
			wantErr: true,
		},
		{
			name:    "invalid address",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, alias, err := eng.ResolveAddress(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if addr != tt.wantAddr {
					t.Errorf("ResolveAddress() addr = %v, want %v", addr, tt.wantAddr)
				}
				if alias != tt.wantAlias {
					t.Errorf("ResolveAddress() alias = %v, want %v", alias, tt.wantAlias)
				}
			}
		})
	}
}

func TestIsSignable(t *testing.T) {
	eng := setupTestEngine(t)

	// Not signable initially
	if eng.isSignable("ADDR1") {
		t.Error("isSignable() should return false for unknown address")
	}

	// Add to signer cache
	eng.SignerCache.AddAddress("ADDR1", "ed25519", "ed25519")

	if !eng.isSignable("ADDR1") {
		t.Error("isSignable() should return true for address in signer cache")
	}

	// Test with rekey
	eng.AuthCache.AuthAddresses = map[string]string{
		"REKEYED_ADDR": "ADDR1", // REKEYED_ADDR is controlled by ADDR1
	}

	if !eng.isSignable("REKEYED_ADDR") {
		t.Error("isSignable() should return true for rekeyed address when auth addr is signable")
	}
}

func TestGetAlgorithm(t *testing.T) {
	eng := setupTestEngine(t)

	// Unknown address
	algo := eng.getAlgorithm("UNKNOWN")
	if algo != "unknown" {
		t.Errorf("getAlgorithm() = %v, want 'unknown'", algo)
	}

	// Direct signer
	eng.SignerCache.Keys = map[string]string{
		"ADDR1": "ed25519",
		"ADDR2": "falcon1024",
	}

	if eng.getAlgorithm("ADDR1") != "ed25519" {
		t.Errorf("getAlgorithm(ADDR1) = %v, want 'ed25519'", eng.getAlgorithm("ADDR1"))
	}
	if eng.getAlgorithm("ADDR2") != "falcon1024" {
		t.Errorf("getAlgorithm(ADDR2) = %v, want 'falcon1024'", eng.getAlgorithm("ADDR2"))
	}

	// Rekeyed account
	eng.AuthCache.AuthAddresses = map[string]string{
		"REKEYED": "ADDR2",
	}

	if eng.getAlgorithm("REKEYED") != "falcon1024" {
		t.Errorf("getAlgorithm(REKEYED) = %v, want 'falcon1024' (from auth addr)", eng.getAlgorithm("REKEYED"))
	}
}

// CurrentKeys returns the signer's list of the moment and leaves the signer
// cache as it was: it neither reads nor rewrites it. No signer client is
// ErrNotConnected and a locked signer is ErrSignerLocked, never an empty list.
func TestCurrentKeysReturnsTheSignersListWithoutTouchingTheCache(t *testing.T) {
	locked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if locked {
			http.Error(w, `{"error":"signer is locked","code":"locked"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{
			{Address: "NATIVE", KeyType: "ed25519", ValidRekeyTarget: true},
			{Address: "HTLC", KeyType: "aplane.htlc.v1", IsGenericLsig: true},
		}})
	}))
	defer server.Close()
	eng := setupTestEngine(t)
	eng.SignerCache.AddAddress("CACHED", "ed25519", "ed25519")

	if _, err := eng.CurrentKeys(context.Background()); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("CurrentKeys() with no signer client error = %v, want ErrNotConnected", err)
	}

	eng.Connection.SignerClient = util.NewSignerClient(server.URL)
	keys, err := eng.CurrentKeys(context.Background())
	if err != nil {
		t.Fatalf("CurrentKeys() error = %v", err)
	}
	want := []KeyInfo{
		{Address: "NATIVE", KeyType: "ed25519", ValidRekeyTarget: true},
		{Address: "HTLC", KeyType: "aplane.htlc.v1", IsGenericLsig: true},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("CurrentKeys() = %+v, want %+v", keys, want)
	}
	if got := eng.SignerCache.Keys; !reflect.DeepEqual(got, map[string]string{"CACHED": "ed25519"}) {
		t.Fatalf("CurrentKeys() changed the signer cache: %v", got)
	}

	locked = true
	if _, err := eng.CurrentKeys(context.Background()); !errors.Is(err, ErrSignerLocked) {
		t.Fatalf("CurrentKeys() on a locked signer error = %v, want ErrSignerLocked", err)
	}
}

// RekeyTargetsFromKeys holds every listed address, a generic LogicSig
// included, and lists as not valid each one whose record does not say it is a
// valid rekey target. It knows no rekey-to lists or protocol targets.
func TestRekeyTargetsFromKeys(t *testing.T) {
	got := RekeyTargetsFromKeys([]KeyInfo{
		{Address: "NATIVE", KeyType: "ed25519", ValidRekeyTarget: true},
		{Address: "ROTATING", KeyType: "aplane.rotating-triple-wotsc.v1"},
		// A rotating account is never a valid rekey target, whatever its
		// record says.
		{Address: "ROTATING-TRUE", KeyType: rotatingkey.RotatingTripleXmssV1, ValidRekeyTarget: true},
		{Address: "HTLC", KeyType: "aplane.htlc.v1", IsGenericLsig: true},
		{Address: "VAULT", KeyType: "example.vault.v1", IsGenericLsig: true, ValidRekeyTarget: true},
	})
	wantHeld := map[string]bool{"NATIVE": true, "ROTATING": true, "ROTATING-TRUE": true, "HTLC": true, "VAULT": true}
	if !reflect.DeepEqual(got.KnownAddresses, wantHeld) {
		t.Errorf("KnownAddresses = %v, want %v", got.KnownAddresses, wantHeld)
	}
	wantInvalid := map[string]txnreview.InvalidRekeyTarget{
		"ROTATING":      {KeyType: "aplane.rotating-triple-wotsc.v1"},
		"ROTATING-TRUE": {KeyType: rotatingkey.RotatingTripleXmssV1},
		"HTLC":          {KeyType: "aplane.htlc.v1", GenericLogicSig: true},
	}
	if !reflect.DeepEqual(got.InvalidRekeyTargets, wantInvalid) {
		t.Errorf("InvalidRekeyTargets = %v, want %v", got.InvalidRekeyTargets, wantInvalid)
	}
	if got.ListedRekeyTargets != nil || got.ProtocolRekeyTargets != nil {
		t.Errorf("a key list knows no rekey-to lists or protocol targets: %+v", got)
	}
}

// A key list that disagrees with itself is an error, never a list: a count
// other than its number of records, a record with no address, or an address
// listed twice. A complete empty list is still an empty list.
func TestCurrentKeysRefusesAnInconsistentList(t *testing.T) {
	var mu sync.Mutex
	var answer signerapi.KeysResponse
	setAnswer := func(a signerapi.KeysResponse) {
		mu.Lock()
		defer mu.Unlock()
		answer = a
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(answer)
	}))
	defer server.Close()
	eng := setupTestEngine(t)
	eng.Connection.SignerClient = util.NewSignerClient(server.URL)

	for name, tc := range map[string]struct {
		answer signerapi.KeysResponse
		want   string
	}{
		"a record with no address": {answer: signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{KeyType: "ed25519"}}},
			want: "signer's key list is inconsistent: record 0 has no address"},
		"an address listed twice": {answer: signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A", KeyType: "ed25519"}, {Address: "A", KeyType: "aplane.htlc.v1"}}},
			want: "signer's key list is inconsistent: A is listed twice"},
	} {
		setAnswer(tc.answer)
		if _, err := eng.CurrentKeys(context.Background()); err == nil || err.Error() != tc.want {
			t.Errorf("%s: CurrentKeys() error = %v, want %q", name, err, tc.want)
		}
	}

	setAnswer(signerapi.KeysResponse{Keys: []signerapi.KeyInfo{}})
	if keys, err := eng.CurrentKeys(context.Background()); err != nil || len(keys) != 0 {
		t.Fatalf("CurrentKeys(empty) = %v, %v; want an empty list", keys, err)
	}
}

// GetBalance is an account's balance from algod, as GetAccountBalanceRaw
// reads it, for an address or an alias, with the account's alias. A missing
// algod client is reported before a bad address.
func TestGetBalanceIsTheRawBalanceWithTheAlias(t *testing.T) {
	sender, unreachable := types.Address{9}.String(), types.Address{10}.String()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address, isAccount := strings.CutPrefix(r.URL.Path, "/v2/accounts/")
		if !isAccount || address == unreachable {
			http.Error(w, "test node", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.Account{Address: address, Amount: 7_000_000, MinBalance: 200_000, AuthAddr: unreachable,
			Assets: []models.AssetHolding{{AssetId: 10458941, Amount: 55, IsFrozen: true}, {AssetId: 999, Amount: 3}}})
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngine("testnet", WithAlgodClient(client))
	eng.AliasCache.Aliases = map[string]string{"me": sender}
	eng.AsaCache.Assets = map[uint64]cache.ASAInfo{}

	want := &BalanceResult{
		Address: sender, Alias: "me", AlgoBalance: 7_000_000, MinBalance: 200_000, AuthAddr: unreachable,
		Assets: []AssetBalance{
			{AssetID: 10458941, Amount: 55, UnitName: "USDC", Decimals: 6, IsFrozen: true, IsOptedIn: true},
			{AssetID: 999, Amount: 3, IsOptedIn: true},
		},
	}
	for _, ref := range []string{"me", sender} {
		got, err := eng.GetBalance(context.Background(), ref)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("GetBalance(%s) = %+v, %v; want %+v", ref, got, err, want)
		}
	}
	if _, err := eng.GetBalance(context.Background(), "nobody"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("GetBalance(nobody) error = %v, want ErrInvalidAddress", err)
	}
	if _, err := eng.GetBalance(context.Background(), unreachable); err == nil || !strings.HasPrefix(err.Error(), "failed to get account info: ") {
		t.Fatalf("GetBalance(unreachable) error = %v, want the account info failure", err)
	}
	if _, err := NewEngine("testnet").GetBalance(context.Background(), "nobody"); !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("GetBalance() without a client error = %v, want ErrNoAlgodClient", err)
	}
}
