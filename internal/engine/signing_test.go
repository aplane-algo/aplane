// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"

	"github.com/aplane-algo/aplane/internal/cache"
)

func TestBuildSigningContext_NoAlgodClient(t *testing.T) {
	eng, _ := NewEngine("testnet")
	_, err := eng.BuildSigningContext(context.Background(), testAddr(1))
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("expected ErrNoAlgodClient, got %v", err)
	}
}

func TestBuildSigningContext_SignerLocked(t *testing.T) {
	transport := newAccountMockTransport(t)
	transport.addAccount(testAddr(1), 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)
	eng.SignerCache.Locked = true

	_, err := eng.BuildSigningContext(context.Background(), testAddr(1))
	if !errors.Is(err, ErrSignerLocked) {
		t.Fatalf("expected ErrSignerLocked, got %v", err)
	}
}

func TestBuildSigningContext_SimpleEd25519(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	ctx, err := eng.BuildSigningContext(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Address != addr {
		t.Errorf("Address = %q, want %q", ctx.Address, addr)
	}
	if ctx.SigningAddr != addr {
		t.Errorf("SigningAddr = %q, want %q (no rekey)", ctx.SigningAddr, addr)
	}
	if ctx.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want %q", ctx.KeyType, "ed25519")
	}
	if ctx.IsLSig {
		t.Error("IsLSig should be false for ed25519")
	}
}

func TestBuildSigningContext_RekeyedAccount_CacheHit(t *testing.T) {
	sender := testAddr(1)
	authAddr := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		AuthAddr:   authAddr,
		Status:     "Offline",
	})
	transport.addAccount(authAddr, 1_000_000)

	eng := setupEngineWithMockAlgod(t, transport)
	// Ensure auth addr is in signer cache
	eng.SignerCache.AddAddress(authAddr, "ed25519")

	ctx, err := eng.BuildSigningContext(context.Background(), sender)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Address != sender {
		t.Errorf("Address = %q, want %q", ctx.Address, sender)
	}
	if ctx.SigningAddr != authAddr {
		t.Errorf("SigningAddr = %q, want %q (rekeyed)", ctx.SigningAddr, authAddr)
	}
}

func TestBuildSigningContext_NotSignable(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)

	eng := setupEngineWithMockAlgod(t, transport)
	// Remove address from signer cache
	eng.SignerCache = cache.NewSignerCache()

	_, err := eng.BuildSigningContext(context.Background(), addr)
	if err == nil {
		t.Fatal("expected error for non-signable address")
	}
	if !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("expected ErrNoSigningKey, got: %v", err)
	}
}

func TestBuildSigningContext_RekeyedNotSignable(t *testing.T) {
	sender := testAddr(1)
	authAddr := testAddr(2)

	transport := newAccountMockTransport(t)
	transport.addAccountFull(models.Account{
		Address:    sender,
		Amount:     1_000_000,
		MinBalance: 100_000,
		AuthAddr:   authAddr,
		Status:     "Offline",
	})
	transport.addAccount(authAddr, 1_000_000)

	eng := setupEngineWithMockAlgod(t, transport)
	// sender is in signer cache but authAddr is NOT
	// (setupEngineWithMockAlgod adds both since they're in transport.accounts,
	// so remove authAddr to simulate not-signable)
	eng.SignerCache.RemoveAddress(authAddr)

	_, err := eng.BuildSigningContext(context.Background(), sender)
	if err == nil {
		t.Fatal("expected error for rekeyed-not-signable")
	}
	if !containsStr(err.Error(), "not signable") {
		t.Errorf("expected 'not signable' in error, got: %v", err)
	}
}

func TestBuildSigningContext_DefaultKeyType(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)
	// Set key type to empty string
	eng.SignerCache.AddAddress(addr, "")

	ctx, err := eng.BuildSigningContext(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.KeyType != "ed25519" {
		t.Errorf("KeyType = %q, want %q (default)", ctx.KeyType, "ed25519")
	}
}

func TestBuildSigningContext_FalconKeyType(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)
	eng.SignerCache.AddAddress(addr, "aplane.falcon1024.v1")

	ctx, err := eng.BuildSigningContext(context.Background(), addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.KeyType != "aplane.falcon1024.v1" {
		t.Errorf("KeyType = %q, want %q", ctx.KeyType, "aplane.falcon1024.v1")
	}
	if !ctx.IsLSig {
		t.Error("IsLSig should be true for aplane.falcon1024.v1")
	}
}

func TestBuildSigningContext_ViaAlias(t *testing.T) {
	addr := testAddr(1)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)
	eng.AliasCache.Aliases = map[string]string{"alice": addr}

	ctx, err := eng.BuildSigningContext(context.Background(), "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ctx.Address != addr {
		t.Errorf("Address = %q, want %q", ctx.Address, addr)
	}
}

func TestIsRekeyed(t *testing.T) {
	addr := testAddr(1)
	authAddr := testAddr(2)
	transport := newAccountMockTransport(t)
	transport.addAccount(addr, 1_000_000)
	transport.addAccount(authAddr, 1_000_000)
	eng := setupEngineWithMockAlgod(t, transport)

	// Not rekeyed
	rekeyed, _ := eng.IsRekeyed(addr)
	if rekeyed {
		t.Error("should not be rekeyed")
	}

	// Set auth address to different account
	eng.AuthCache.AuthAddresses[addr] = authAddr
	rekeyed, gotAuth := eng.IsRekeyed(addr)
	if !rekeyed {
		t.Error("should be rekeyed")
	}
	if gotAuth != authAddr {
		t.Errorf("auth addr = %q, want %q", gotAuth, authAddr)
	}
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && strings.Contains(s, substr))
}

// A cached auth address whose key the signer does not hold is refreshed once
// from the chain, and the signing address is picked again from the refreshed
// one.
func TestBuildSigningContext_StaleAuthCacheRefreshed(t *testing.T) {
	sender, onChain, stale := testAddr(1), testAddr(2), testAddr(3)
	for _, tc := range []struct {
		name      string
		chainAuth string // sender's auth address on chain
		cached    string // sender's stale cached auth address
		held      string // the one key the signer holds
		want      string // SigningAddr, or the address the error names
		wantErr   bool
	}{
		{"rekeyed since it was cached", onChain, "", onChain, onChain, false},
		{"rekeyed back to itself", "", stale, sender, sender, false},
		{"rekeyed to a key not held", onChain, stale, sender, onChain, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := newAccountMockTransport(t)
			transport.addAccountFull(models.Account{
				Address: sender, Amount: 1_000_000, MinBalance: 100_000, AuthAddr: tc.chainAuth, Status: "Offline",
			})
			eng := setupEngineWithMockAlgod(t, transport)
			eng.SignerCache = cache.NewSignerCache()
			eng.SignerCache.AddAddress(tc.held, "ed25519")
			eng.AuthCache.AuthAddresses[sender] = tc.cached

			ctx, err := eng.BuildSigningContext(context.Background(), sender)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "rekeyed to "+tc.want+" but that address is not signable") {
					t.Fatalf("BuildSigningContext() error = %v, want it to name %s as not signable", err, tc.want)
				}
				return
			}
			if err != nil || ctx.SigningAddr != tc.want {
				t.Fatalf("BuildSigningContext() = %+v, %v; want SigningAddr %s", ctx, err, tc.want)
			}
		})
	}
}
