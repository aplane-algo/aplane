// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/util"
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

	// Test with aPlane client (local mode)
	eng.SignerClient = &util.SignerClient{}
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
	eng.AsaCache.Assets = map[uint64]util.ASAInfo{
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

	if aliceAccount == nil {
		t.Fatal("ListAccounts() should include ADDR_ALICE")
	}
	if aliceAccount.Alias != "alice" {
		t.Errorf("ListAccounts() alice alias = %v, want 'alice'", aliceAccount.Alias)
	}
	if !aliceAccount.IsSignable {
		t.Error("ListAccounts() alice should be signable")
	}
	if aliceAccount.KeyType != "ed25519" {
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
