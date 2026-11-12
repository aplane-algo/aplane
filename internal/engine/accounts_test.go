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
	"sync"
	"testing"

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

	// Test with APlane client (local mode)
	eng.Connection.SignerClient = &util.Client{}
	result = eng.GetStatus()

	if !result.IsConnected {
		t.Error("GetStatus() should be connected with SignerClient")
	}
	if result.SigningMode != "local" {
		t.Errorf("GetStatus() SigningMode = %v, want 'local'", result.SigningMode)
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

	if err := eng.Disconnect(); err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}
	if eng.IsConnected() {
		t.Fatal("engine should report disconnected after Disconnect()")
	}
	if eng.IsTunnelConnected() {
		t.Fatal("engine should report tunnel disconnected after Disconnect()")
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
	eng.SignerCache.Keys = map[string]string{
		"ADDR_ALICE":  "ed25519",
		"ADDR_SIGNER": "falcon1024",
	}

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
	eng.SignerCache.Keys = map[string]string{
		"ADDR1": "ed25519",
		"ADDR2": "falcon1024",
	}

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
	eng.SignerCache.Keys = map[string]string{
		"ADDR1": "ed25519",
	}

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
			http.Error(w, "signer is locked", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: 2, Keys: []signerapi.KeyInfo{
			{Address: "NATIVE", KeyType: "ed25519", ValidRekeyTarget: true},
			{Address: "HTLC", KeyType: "aplane.htlc.v1", IsGenericLsig: true},
		}})
	}))
	defer server.Close()
	eng := setupTestEngine(t)
	eng.SignerCache.AddAddress("CACHED", "ed25519")

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
		"count larger than the records": {answer: signerapi.KeysResponse{Count: 2, Keys: []signerapi.KeyInfo{{Address: "A", KeyType: "ed25519"}}},
			want: "signer's key list is inconsistent: count 2, 1 record(s)"},
		"records but a count of 0": {answer: signerapi.KeysResponse{Keys: []signerapi.KeyInfo{{Address: "A", KeyType: "ed25519"}}},
			want: "signer's key list is inconsistent: count 0, 1 record(s)"},
		"a record with no address": {answer: signerapi.KeysResponse{Count: 1, Keys: []signerapi.KeyInfo{{KeyType: "ed25519"}}},
			want: "signer's key list is inconsistent: record 0 has no address"},
		"an address listed twice": {answer: signerapi.KeysResponse{Count: 2, Keys: []signerapi.KeyInfo{{Address: "A", KeyType: "ed25519"}, {Address: "A", KeyType: "aplane.htlc.v1"}}},
			want: "signer's key list is inconsistent: A is listed twice"},
	} {
		setAnswer(tc.answer)
		if _, err := eng.CurrentKeys(context.Background()); err == nil || err.Error() != tc.want {
			t.Errorf("%s: CurrentKeys() error = %v, want %q", name, err, tc.want)
		}
	}

	setAnswer(signerapi.KeysResponse{Count: 0, Keys: []signerapi.KeyInfo{}})
	if keys, err := eng.CurrentKeys(context.Background()); err != nil || len(keys) != 0 {
		t.Fatalf("CurrentKeys(empty) = %v, %v; want an empty list", keys, err)
	}
}
