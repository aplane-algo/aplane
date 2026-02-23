// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/util"
)

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
	aliasCache := util.AliasCache{
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
	signerCache := util.SignerCache{
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
	setCache := util.SetCache{
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
		{"invalid network", "invalidnet", true},
		{"empty network", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eng.SetNetwork(tt.network, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetNetwork() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && eng.Network != tt.network {
				t.Errorf("SetNetwork() network = %v, want %v", eng.Network, tt.network)
			}
		})
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
