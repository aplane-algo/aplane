// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
)

// SigningContext encapsulates all information needed to sign transactions.
// It carries the raw key type; presentation of a human-readable label is the
// UI layer's concern, not the engine's.
type SigningContext struct {
	Address           string // Resolved address (the account)
	SigningAddr       string // Auth address (may differ if rekeyed)
	KeyType           string // e.g., "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1"
	SigSize           int    // Crypto signature size (for fee calculation), 0 for ed25519 and generic lsigs
	IsLSig            bool   // true for LSig-based accounts (DSA or generic)
	AuthorizationKind algorithm.AuthorizationKind
}

// BuildSigningContext builds a complete signing context using the
// caller's context for blockchain lookups.
func (e *Engine) BuildSigningContext(ctx context.Context, addressOrAlias string) (*SigningContext, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Auto-refresh SignerCache if connected but empty
	if err := e.EnsureSignerCache(ctx); err != nil {
		return nil, err
	}

	// Check if signer reported locked state
	if e.signerCacheIsLocked() {
		return nil, ErrSignerLocked
	}

	// First, resolve alias to address
	address, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	// Check cache first to avoid unnecessary blockchain queries
	authAddr, cached := e.GetAuthAddress(address)

	if !cached {
		// Not in cache - query blockchain
		cache.Debug("querying auth address", "address", address)
		acctInfo, err := e.AlgodClient.AccountInformation(address).Do(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to query account info: %w", err)
		}

		authAddr = acctInfo.AuthAddr

		// Update cache with the queried value under the shared client-data lock.
		if err := e.withClientDataLock(func() error {
			if e.DataDir != "" {
				e.AuthCache = cache.LoadAuthCacheFromStore(e.CacheStore, e.Network)
			}
			return e.AuthCache.UpdateAuthAddress(address, authAddr, e.Network)
		}); err != nil {
			cache.Debug("failed to save auth cache", "error", err)
		}
	}

	// Determine which address to use for signing
	var signingAddr string
	if authAddr == "" || authAddr == address {
		// No rekey set, account signs for itself
		signingAddr = address
	} else {
		// Account is rekeyed to authAddr
		signingAddr = authAddr
	}

	// Check if we can sign (address is in SignerCache).
	// If the cached auth address is stale (e.g., account was rekeyed mid-session),
	// refresh from the blockchain once and retry.
	if !e.signerCacheHasAddress(signingAddr) && cached {
		refreshedAuth, err := e.RefreshAuthAddressWithContext(ctx, address)
		if err == nil {
			if refreshedAuth == "" || refreshedAuth == address {
				signingAddr = address
			} else {
				signingAddr = refreshedAuth
				authAddr = refreshedAuth
			}
		}
	}
	if !e.signerCacheHasAddress(signingAddr) {
		if signingAddr == address {
			return nil, fmt.Errorf("%w: %s is not available for signing", ErrNoSigningKey, address)
		}
		return nil, fmt.Errorf("%w: account is rekeyed to %s but that address is not signable", ErrNoSigningKey, authAddr)
	}

	// Get key type from signer cache (source of truth, populated from server's /keys response)
	keyType := e.signerCacheKeyType(signingAddr)
	if keyType == "" {
		keyType = "ed25519" // Default to ed25519 if not specified
	}

	// Unknown non-Ed25519 types preserve the compatibility assumption that
	// they are LogicSigs. Registered metadata is authoritative for known types,
	// including native Falcon, which is neither Ed25519 nor a LogicSig.
	authorizationKind := algorithm.AuthorizationLogicSig
	if keyType == "ed25519" {
		authorizationKind = algorithm.AuthorizationEd25519
	}
	if meta, err := algorithm.GetMetadata(keyType); err == nil {
		authorizationKind = meta.AuthorizationKind()
	}
	isLSig := authorizationKind == algorithm.AuthorizationLogicSig

	return &SigningContext{
		Address:           address,
		SigningAddr:       signingAddr,
		KeyType:           keyType,
		SigSize:           logicsigdsa.GetCryptoSignatureSize(keyType), // 0 for ed25519 and generic lsigs
		IsLSig:            isLSig,
		AuthorizationKind: authorizationKind,
	}, nil
}

// RefreshAuthCache refreshes the auth address cache from blockchain
// using the caller's context for algod lookups.
func (e *Engine) RefreshAuthCache(ctx context.Context) error {
	if e.AlgodClient == nil {
		return ErrNoAlgodClient
	}

	cache.Debug("refreshing auth address cache", "network", e.Network)
	return e.withClientDataLock(func() error {
		if e.DataDir != "" {
			e.AliasCache = cache.LoadAliasCacheFromStore(e.CacheStore)
		}
		e.signerCacheMu.RLock()
		defer e.signerCacheMu.RUnlock()
		e.AuthCache = cache.BuildAuthCacheFromStoreWithContext(ctx, e.CacheStore, e.AlgodClient, &e.AliasCache, &e.SignerCache, e.Network)
		return nil
	})
}

// IsRekeyed checks if an address is rekeyed and returns the auth address if so
func (e *Engine) IsRekeyed(address string) (bool, string) {
	authAddr, exists := e.GetAuthAddress(address)
	if !exists || authAddr == "" || authAddr == address {
		return false, ""
	}
	return true, authAddr
}
