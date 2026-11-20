// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// SigningContext encapsulates all information needed to sign transactions.
// It carries the raw key type; presentation of a human-readable label is the
// UI layer's concern, not the engine's.
type SigningContext struct {
	Address           string // Resolved address (the account)
	SigningAddr       string // Auth address (may differ if rekeyed)
	KeyType           string // e.g., "ed25519", "aplane.falcon1024.v1", "aplane.htlc.v1"
	SigSize           int    // Crypto signature size (for fee calculation), 0 for ed25519 and generic lsigs
	AuthorizationKind algorithm.AuthorizationKind
}

// signingAddressFor returns the address whose key signs for sender, given
// sender's auth address: sender itself when it is not rekeyed, otherwise the
// auth address. A rotating account is the exception: it is authorized by its
// current stage, which the signer derives from the account's key and never
// lists. The signer holds the account itself, so it signs for the account at
// any stage.
func (e *Core) signingAddressFor(sender, authAddr string) string {
	if authAddr == "" || authAddr == sender || e.signerCacheSigningFlow(sender) == signerapi.SigningFlowRotating1 {
		return sender
	}
	return authAddr
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
			e.ReloadAuthCache()
			return e.AuthCache.UpdateAuthAddress(address, authAddr, e.Network)
		}); err != nil {
			cache.Debug("failed to save auth cache", "error", err)
		}
	}

	signingAddr := e.signingAddressFor(address, authAddr)

	// Check if we can sign (address is in SignerCache).
	// If the cached auth address is stale (e.g., account was rekeyed mid-session),
	// refresh from the blockchain once and retry.
	if !e.signerCacheHasAddress(signingAddr) && cached {
		refreshedAuth, err := e.RefreshAuthAddressWithContext(ctx, address)
		if err == nil {
			signingAddr = e.signingAddressFor(address, refreshedAuth)
			authAddr = refreshedAuth
		}
	}
	if !e.signerCacheHasAddress(signingAddr) {
		if signingAddr == address {
			return nil, fmt.Errorf("%w: %s is not available for signing", ErrNoSigningKey, address)
		}
		return nil, fmt.Errorf("%w: account is rekeyed to %s but that address is not signable", ErrNoSigningKey, authAddr)
	}

	// The key type and authorization kind are the signer's, from its /keys
	// answer. A key it reports no kind this client knows for signs nothing.
	keyType := e.signerCacheKeyType(signingAddr)
	authorizationKind, _ := e.signerCacheAuthorizationKind(signingAddr)
	if authorizationKind == "" {
		return nil, fmt.Errorf("%w: the signer reports no transaction authorization this client knows for %s", ErrNoSigningKey, signingAddr)
	}
	return &SigningContext{
		Address:           address,
		SigningAddr:       signingAddr,
		KeyType:           keyType,
		SigSize:           logicsigdsa.GetCryptoSignatureSize(keyType), // 0 for ed25519 and generic lsigs
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
	return e.rebuildAuthCache(ctx)
}

// IsRekeyed checks if an address is rekeyed and returns the auth address if so
func (e *Engine) IsRekeyed(address string) (bool, string) {
	authAddr, exists := e.GetAuthAddress(address)
	if !exists || authAddr == "" || authAddr == address {
		return false, ""
	}
	return true, authAddr
}
