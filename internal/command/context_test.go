// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/util"
)

func TestContext_Algod(t *testing.T) {
	// Test with nil Internal
	ctx := &Context{}
	if ctx.Algod() != nil {
		t.Error("Algod() should return nil when Internal is nil")
	}

	// Test with nil PluginAPI
	ctx.Internal = &InternalContext{}
	if ctx.Algod() != nil {
		t.Error("Algod() should return nil when PluginAPI is nil")
	}
}

func TestContext_NetworkName(t *testing.T) {
	// Test fallback to serializable field
	ctx := &Context{Network: "testnet"}
	if ctx.NetworkName() != "testnet" {
		t.Errorf("NetworkName() = %v, want testnet", ctx.NetworkName())
	}

	// Test with nil Internal
	if ctx.NetworkName() != "testnet" {
		t.Errorf("NetworkName() should fallback to Network field")
	}
}

func TestContext_GetCaches(t *testing.T) {
	// Test with nil Internal
	ctx := &Context{}
	if ctx.GetCaches() != nil {
		t.Error("GetCaches() should return nil when Internal is nil")
	}

	// Test with nil PluginAPI
	ctx.Internal = &InternalContext{}
	if ctx.GetCaches() != nil {
		t.Error("GetCaches() should return nil when PluginAPI is nil")
	}
}

func TestContext_Signer(t *testing.T) {
	// Test with nil Internal
	ctx := &Context{}
	if ctx.Signer() != nil {
		t.Error("Signer() should return nil when Internal is nil")
	}

	// Test with nil PluginAPI
	ctx.Internal = &InternalContext{}
	if ctx.Signer() != nil {
		t.Error("Signer() should return nil when PluginAPI is nil")
	}
}

func TestNewPluginAPI(t *testing.T) {
	asaCache := &util.ASACache{}
	signerCache := &util.SignerCache{}
	authCache := &util.AuthAddressCache{}
	aliasCache := &util.AliasCache{}

	api := NewPluginAPI(nil, "testnet", asaCache, signerCache, authCache, aliasCache, nil, nil)

	if api == nil {
		t.Fatal("NewPluginAPI() returned nil")
	}
	if api.network != "testnet" {
		t.Errorf("NewPluginAPI() network = %v, want testnet", api.network)
	}
	if api.caches == nil {
		t.Error("NewPluginAPI() caches should not be nil")
	}
	if api.caches.ASA != asaCache {
		t.Error("NewPluginAPI() ASA cache not set correctly")
	}
	if api.caches.Signer != signerCache {
		t.Error("NewPluginAPI() Signer cache not set correctly")
	}
	if api.caches.Auth != authCache {
		t.Error("NewPluginAPI() Auth cache not set correctly")
	}
	if api.caches.Alias != aliasCache {
		t.Error("NewPluginAPI() Alias cache not set correctly")
	}
}

func TestCaches_Struct(t *testing.T) {
	caches := &Caches{
		ASA:    &util.ASACache{},
		Signer: &util.SignerCache{},
		Auth:   &util.AuthAddressCache{},
		Alias:  &util.AliasCache{},
	}

	if caches.ASA == nil {
		t.Error("Caches.ASA should not be nil")
	}
	if caches.Signer == nil {
		t.Error("Caches.Signer should not be nil")
	}
	if caches.Auth == nil {
		t.Error("Caches.Auth should not be nil")
	}
	if caches.Alias == nil {
		t.Error("Caches.Alias should not be nil")
	}
}
