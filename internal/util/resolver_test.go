// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Helper to create a valid Algorand address for testing
func testAddress(index int) string {
	var pk [32]byte
	pk[0] = byte(index)
	pk[1] = byte(index >> 8)
	return types.Address(pk).String()
}

// createTestAliasCache creates an AliasCache with predefined aliases
func createTestAliasCache(aliases map[string]string) *AliasCache {
	return &AliasCache{Aliases: aliases}
}

// createTestSetCache creates a SetCache with predefined sets
func createTestSetCache(sets map[string][]string) *SetCache {
	return &SetCache{Sets: sets}
}

// TestIsReservedSetName tests reserved set name detection
func TestIsReservedSetName(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"signers", true},
		{"all", true},
		{"mySet", false},
		{"custom", false},
		{"", false},
		{"SIGNERS", false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsReservedSetName(tt.name)
			if result != tt.expected {
				t.Errorf("IsReservedSetName(%q) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// TestNewAddressResolver tests resolver creation
func TestNewAddressResolver(t *testing.T) {
	aliasCache := &AliasCache{Aliases: map[string]string{}}
	setCache := &SetCache{Sets: map[string][]string{}}

	resolver := NewAddressResolver(aliasCache, setCache)

	if resolver == nil {
		t.Fatal("NewAddressResolver returned nil")
	}
	if resolver.AliasCache != aliasCache {
		t.Error("AliasCache not set correctly")
	}
	if resolver.SetCache != setCache {
		t.Error("SetCache not set correctly")
	}
}

// TestAddressResolver_WithProviders tests provider chaining
func TestAddressResolver_WithProviders(t *testing.T) {
	resolver := NewAddressResolver(&AliasCache{Aliases: map[string]string{}}, &SetCache{Sets: map[string][]string{}})

	signerProvider := func() []string { return []string{"signer1"} }
	allProvider := func() []string { return []string{"addr1", "addr2"} }
	holdersProvider := func(asset string) ([]string, error) { return []string{"holder1"}, nil }

	resolver = resolver.WithSignerProvider(signerProvider)
	if resolver.SignerProvider == nil {
		t.Error("SignerProvider not set")
	}

	resolver = resolver.WithAllProvider(allProvider)
	if resolver.AllProvider == nil {
		t.Error("AllProvider not set")
	}

	resolver = resolver.WithHoldersProvider(holdersProvider)
	if resolver.HoldersProvider == nil {
		t.Error("HoldersProvider not set")
	}
}

// TestResolveList_SingleAddress tests resolving a single address
func TestResolveList_SingleAddress(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveList([]string{addr})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 address, got %d", len(result))
	}

	if result[0] != addr {
		t.Errorf("Address = %s, want %s", result[0], addr)
	}
}

// TestResolveList_Alias tests resolving an alias
func TestResolveList_Alias(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{"alice": addr})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveList([]string{"alice"})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 1 || result[0] != addr {
		t.Errorf("Expected [%s], got %v", addr, result)
	}
}

// TestResolveList_Set tests resolving a @setname
func TestResolveList_Set(t *testing.T) {
	addr1 := testAddress(1)
	addr2 := testAddress(2)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{
		"team": {addr1, addr2},
	})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveList([]string{"@team"})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("Expected 2 addresses, got %d", len(result))
	}

	if result[0] != addr1 || result[1] != addr2 {
		t.Errorf("Expected [%s, %s], got %v", addr1, addr2, result)
	}
}

// TestResolveList_Signers tests resolving @signers dynamic set
func TestResolveList_Signers(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithSignerProvider(func() []string {
		return []string{addr}
	})

	result, err := resolver.ResolveList([]string{"@signers"})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 1 || result[0] != addr {
		t.Errorf("Expected [%s], got %v", addr, result)
	}
}

// TestResolveList_SignersNoProvider tests @signers without provider
func TestResolveList_SignersNoProvider(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	_, err := resolver.ResolveList([]string{"@signers"})
	if err == nil {
		t.Fatal("Expected error for @signers without provider")
	}

	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("Error should mention 'not available': %v", err)
	}
}

// TestResolveList_SignersEmpty tests @signers when empty
func TestResolveList_SignersEmpty(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithSignerProvider(func() []string {
		return []string{} // Empty
	})

	_, err := resolver.ResolveList([]string{"@signers"})
	if err == nil {
		t.Fatal("Expected error for empty @signers")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("Error should mention 'empty': %v", err)
	}
}

// TestResolveList_All tests resolving @all dynamic set
func TestResolveList_All(t *testing.T) {
	addr1 := testAddress(1)
	addr2 := testAddress(2)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithAllProvider(func() []string {
		return []string{addr1, addr2}
	})

	result, err := resolver.ResolveList([]string{"@all"})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 addresses, got %d", len(result))
	}
}

// TestResolveList_HoldersAsset tests resolving @holders(asset) dynamic set
func TestResolveList_HoldersAsset(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithHoldersProvider(func(assetRef string) ([]string, error) {
		if assetRef == "USDC" {
			return []string{addr}, nil
		}
		return nil, fmt.Errorf("unknown asset: %s", assetRef)
	})

	result, err := resolver.ResolveList([]string{"@holders(USDC)"})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 1 || result[0] != addr {
		t.Errorf("Expected [%s], got %v", addr, result)
	}
}

// TestResolveList_HoldersError tests @holders with error
func TestResolveList_HoldersError(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithHoldersProvider(func(assetRef string) ([]string, error) {
		return nil, fmt.Errorf("asset not found")
	})

	_, err := resolver.ResolveList([]string{"@holders(FAKE)"})
	if err == nil {
		t.Fatal("Expected error for holders error")
	}

	if !strings.Contains(err.Error(), "asset not found") {
		t.Errorf("Error should contain provider error: %v", err)
	}
}

// TestResolveList_Mixed tests resolving mixed inputs
func TestResolveList_Mixed(t *testing.T) {
	addr1 := testAddress(1)
	addr2 := testAddress(2)
	addr3 := testAddress(3)

	aliasCache := createTestAliasCache(map[string]string{"bob": addr2})
	setCache := createTestSetCache(map[string][]string{
		"team": {addr3},
	})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveList([]string{addr1, "bob", "@team"})
	if err != nil {
		t.Fatalf("ResolveList failed: %v", err)
	}

	if len(result) != 3 {
		t.Fatalf("Expected 3 addresses, got %d", len(result))
	}

	if result[0] != addr1 || result[1] != addr2 || result[2] != addr3 {
		t.Errorf("Expected [%s, %s, %s], got %v", addr1, addr2, addr3, result)
	}
}

// TestResolveList_EmptyInput tests empty and nil inputs
func TestResolveList_EmptyInput(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	// Empty slice
	result, err := resolver.ResolveList([]string{})
	if err != nil {
		t.Fatalf("ResolveList failed on empty slice: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected empty result, got %v", result)
	}

	// Slice with empty string
	result, err = resolver.ResolveList([]string{""})
	if err != nil {
		t.Fatalf("ResolveList failed on empty string: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected empty result for empty string, got %v", result)
	}
}

// TestResolveList_NonexistentSet tests error for unknown set
func TestResolveList_NonexistentSet(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	_, err := resolver.ResolveList([]string{"@nonexistent"})
	if err == nil {
		t.Fatal("Expected error for nonexistent set")
	}

	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("Error should mention set doesn't exist: %v", err)
	}
}

// TestResolveList_InvalidAddress tests error for invalid address/alias
func TestResolveList_InvalidAddress(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	_, err := resolver.ResolveList([]string{"not-an-address-or-alias"})
	if err == nil {
		t.Fatal("Expected error for invalid address")
	}
}

// TestResolveSingle_Address tests resolving a single address
func TestResolveSingle_Address(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveSingle(addr)
	if err != nil {
		t.Fatalf("ResolveSingle failed: %v", err)
	}

	if result != addr {
		t.Errorf("Result = %s, want %s", result, addr)
	}
}

// TestResolveSingle_Alias tests resolving alias to single address
func TestResolveSingle_Alias(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{"alice": addr})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveSingle("alice")
	if err != nil {
		t.Fatalf("ResolveSingle failed: %v", err)
	}

	if result != addr {
		t.Errorf("Result = %s, want %s", result, addr)
	}
}

// TestResolveSingle_SetWithOneAddress tests set with exactly one address
func TestResolveSingle_SetWithOneAddress(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{
		"single": {addr},
	})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveSingle("@single")
	if err != nil {
		t.Fatalf("ResolveSingle failed: %v", err)
	}

	if result != addr {
		t.Errorf("Result = %s, want %s", result, addr)
	}
}

// TestResolveSingle_SetWithMultipleAddresses tests error for multi-address set
func TestResolveSingle_SetWithMultipleAddresses(t *testing.T) {
	addr1 := testAddress(1)
	addr2 := testAddress(2)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{
		"team": {addr1, addr2},
	})

	resolver := NewAddressResolver(aliasCache, setCache)

	_, err := resolver.ResolveSingle("@team")
	if err == nil {
		t.Fatal("Expected error for set with multiple addresses")
	}

	// Check it's a MultipleAddressError
	_, ok := err.(*MultipleAddressError)
	if !ok {
		t.Errorf("Expected MultipleAddressError, got %T: %v", err, err)
	}
}

// TestResolveSingle_SignersWithOne tests @signers with single signer
func TestResolveSingle_SignersWithOne(t *testing.T) {
	addr := testAddress(1)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithSignerProvider(func() []string {
		return []string{addr}
	})

	result, err := resolver.ResolveSingle("@signers")
	if err != nil {
		t.Fatalf("ResolveSingle failed: %v", err)
	}

	if result != addr {
		t.Errorf("Result = %s, want %s", result, addr)
	}
}

// TestResolveSingle_SignersWithMultiple tests error for multiple signers
func TestResolveSingle_SignersWithMultiple(t *testing.T) {
	addr1 := testAddress(1)
	addr2 := testAddress(2)
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)
	resolver = resolver.WithSignerProvider(func() []string {
		return []string{addr1, addr2}
	})

	_, err := resolver.ResolveSingle("@signers")
	if err == nil {
		t.Fatal("Expected error for multiple signers")
	}

	_, ok := err.(*MultipleAddressError)
	if !ok {
		t.Errorf("Expected MultipleAddressError, got %T", err)
	}
}

// TestResolveSingle_Empty tests empty input
func TestResolveSingle_Empty(t *testing.T) {
	aliasCache := createTestAliasCache(map[string]string{})
	setCache := createTestSetCache(map[string][]string{})

	resolver := NewAddressResolver(aliasCache, setCache)

	result, err := resolver.ResolveSingle("")
	if err != nil {
		t.Fatalf("ResolveSingle failed on empty: %v", err)
	}

	if result != "" {
		t.Errorf("Expected empty result, got %s", result)
	}
}

// TestMultipleAddressError_Error tests error message format
func TestMultipleAddressError_Error(t *testing.T) {
	err := &MultipleAddressError{
		SetName: "@team",
		Count:   5,
	}

	msg := err.Error()
	if !strings.Contains(msg, "@team") || !strings.Contains(msg, "5") {
		t.Errorf("Error message should contain set name and count: %s", msg)
	}
}
