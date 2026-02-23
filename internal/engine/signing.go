// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package engine

import (
	"context"
	"fmt"

	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/util"
)

// SigningContext encapsulates all information needed to sign transactions
type SigningContext struct {
	Address     string // Resolved address (the account)
	SigningAddr string // Auth address (may differ if rekeyed)
	KeyType     string // e.g., "ed25519", "falcon1024-v1", "timelock-v1"
	SigSize     int    // Crypto signature size (for fee calculation), 0 for ed25519 and generic lsigs
	IsLSig      bool   // true for LSig-based accounts (DSA or generic)
}

// DisplayKeyType returns human-readable key type
func (sc *SigningContext) DisplayKeyType() string {
	if sc.IsLSig {
		return sc.KeyType + " lsig"
	}
	return "Ed25519 key"
}

// BuildSigningContext builds a complete signing context:
// 1. Resolves alias to address
// 2. Determines auth address (handles rekeyed accounts)
// 3. Determines key type from signer cache
func (e *Engine) BuildSigningContext(addressOrAlias string) (*SigningContext, error) {
	if e.AlgodClient == nil {
		return nil, ErrNoAlgodClient
	}

	// Auto-refresh SignerCache if connected but empty
	e.EnsureSignerCache()

	// Check if signer reported locked state
	if e.SignerCache.Locked {
		return nil, ErrSignerLocked
	}

	// First, resolve alias to address
	address, err := e.AliasCache.ResolveAddress(addressOrAlias)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAddress, addressOrAlias)
	}

	// Check cache first to avoid unnecessary blockchain queries
	authAddr, cached := e.AuthCache.GetAuthAddress(address)

	if !cached {
		// Not in cache - query blockchain
		util.Debug("querying auth address", "address", address)
		acctInfo, err := e.AlgodClient.AccountInformation(address).Do(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to query account info: %w", err)
		}

		authAddr = acctInfo.AuthAddr

		// Update cache with the queried value
		if err := e.AuthCache.UpdateAuthAddress(address, authAddr, e.Network); err != nil {
			util.Debug("failed to save auth cache", "error", err)
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

	// Check if we can sign (address is in SignerCache)
	if !e.SignerCache.HasAddress(signingAddr) {
		if signingAddr == address {
			return nil, fmt.Errorf("%w: %s is not available for signing", ErrNoSigningKey, address)
		}
		return nil, fmt.Errorf("account is rekeyed to %s but that address is not signable", authAddr)
	}

	// Get key type from signer cache (source of truth, populated from server's /keys response)
	keyType := e.SignerCache.GetKeyType(signingAddr)
	if keyType == "" {
		keyType = "ed25519" // Default to ed25519 if not specified
	}

	// Determine if this is an LSig type (anything other than ed25519)
	isLSig := keyType != "ed25519"

	return &SigningContext{
		Address:     address,
		SigningAddr: signingAddr,
		KeyType:     keyType,
		SigSize:     logicsigdsa.GetCryptoSignatureSize(keyType), // 0 for ed25519 and generic lsigs
		IsLSig:      isLSig,
	}, nil
}

// RefreshAuthCache refreshes the auth address cache from blockchain
func (e *Engine) RefreshAuthCache() error {
	if e.AlgodClient == nil {
		return ErrNoAlgodClient
	}

	util.Debug("refreshing auth address cache", "network", e.Network)
	e.AuthCache = util.BuildAuthCache(e.AlgodClient, &e.AliasCache, &e.SignerCache, e.Network)
	return nil
}

// IsRekeyed checks if an address is rekeyed and returns the auth address if so
func (e *Engine) IsRekeyed(address string) (bool, string) {
	authAddr, exists := e.AuthCache.GetAuthAddress(address)
	if !exists || authAddr == "" || authAddr == address {
		return false, ""
	}
	return true, authAddr
}
