// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package addressbook

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/refname"
)

// IsReservedSetName returns true if the name is reserved for dynamic sets.
func IsReservedSetName(name string) bool {
	return refname.IsDynamicSetName(name)
}

// SignerProvider returns signable addresses dynamically.
type SignerProvider func() []string

// AllAddressesProvider returns all known addresses dynamically.
type AllAddressesProvider func() []string

// HoldersProvider returns addresses holding an asset.
// The assetRef can be "algo", an asset name from cache, or an asset ID.
type HoldersProvider func(assetRef string) ([]string, error)

// Resolver provides unified address resolution for commands.
// It resolves aliases, @setnames, and inline lists to arrays of addresses.
// Special dynamic sets like @signers and @all are resolved via providers.
type Resolver struct {
	AliasCache      *cache.AliasCache
	SetCache        *cache.SetCache
	SignerProvider  SignerProvider
	AllProvider     AllAddressesProvider
	HoldersProvider HoldersProvider
}

// NewResolver creates a new resolver with the given caches.
func NewResolver(aliasCache *cache.AliasCache, setCache *cache.SetCache) *Resolver {
	return &Resolver{
		AliasCache: aliasCache,
		SetCache:   setCache,
	}
}

// WithSignerProvider returns a copy of the resolver with a signer provider set.
func (r *Resolver) WithSignerProvider(provider SignerProvider) *Resolver {
	cp := *r
	cp.SignerProvider = provider
	return &cp
}

// WithAllProvider returns a copy of the resolver with an all-addresses provider set.
func (r *Resolver) WithAllProvider(provider AllAddressesProvider) *Resolver {
	cp := *r
	cp.AllProvider = provider
	return &cp
}

// WithHoldersProvider returns a copy of the resolver with a holders provider set.
func (r *Resolver) WithHoldersProvider(provider HoldersProvider) *Resolver {
	cp := *r
	cp.HoldersProvider = provider
	return &cp
}

// ResolveList resolves a list of inputs (aliases, addresses, or @setnames) to addresses.
func (r *Resolver) ResolveList(inputs []string) ([]string, error) {
	var result []string

	for _, input := range inputs {
		if len(input) == 0 {
			continue
		}

		if input[0] == '@' {
			addresses, emptyErr, err := r.resolveSet(input[1:])
			if err != nil {
				return nil, err
			}
			if len(addresses) == 0 && emptyErr != nil {
				return nil, emptyErr
			}
			result = append(result, addresses...)
		} else {
			addr, err := r.AliasCache.ResolveAddress(input)
			if err != nil {
				return nil, err
			}
			result = append(result, addr)
		}
	}

	return result, nil
}

// ResolveSingle resolves a single input to one address.
// Returns an error if the input resolves to multiple addresses.
func (r *Resolver) ResolveSingle(input string) (string, error) {
	if len(input) == 0 {
		return "", nil
	}

	if input[0] == '@' {
		addresses, _, err := r.resolveSet(input[1:])
		if err != nil {
			return "", err
		}
		if len(addresses) != 1 {
			return "", &MultipleAddressError{SetName: input, Count: len(addresses)}
		}
		return addresses[0], nil
	}

	return r.AliasCache.ResolveAddress(input)
}

// resolveSet resolves one @-token (without the leading '@') to addresses.
// emptyErr is what ResolveList reports when the set legitimately resolved but
// came back empty; ResolveSingle ignores it and reports cardinality instead.
// Stored sets return a nil emptyErr: an empty stored set is not an error in
// list context.
func (r *Resolver) resolveSet(setName string) (addresses []string, emptyErr error, err error) {
	setNameLower := strings.ToLower(setName)

	switch {
	case setNameLower == "signers":
		if r.SignerProvider == nil {
			return nil, nil, fmt.Errorf("@signers not available (not connected to signer)")
		}
		return r.SignerProvider(), fmt.Errorf("@signers is empty (no signable accounts)"), nil

	case setNameLower == "all":
		if r.AllProvider == nil {
			return nil, nil, fmt.Errorf("@all not available")
		}
		return r.AllProvider(), fmt.Errorf("@all is empty (no accounts defined)"), nil

	case strings.HasPrefix(setNameLower, "holders(") && strings.HasSuffix(setNameLower, ")"):
		assetRef, err := holdersAssetRef(setName)
		if err != nil {
			return nil, nil, err
		}
		if r.HoldersProvider == nil {
			return nil, nil, fmt.Errorf("@holders() not available")
		}
		addrs, err := r.HoldersProvider(assetRef)
		if err != nil {
			return nil, nil, fmt.Errorf("@holders(%s): %w", assetRef, err)
		}
		return addrs, fmt.Errorf("@holders(%s) is empty (no holders found)", assetRef), nil

	default:
		addrs, err := r.SetCache.GetSet(setNameLower)
		if err != nil {
			return nil, nil, err
		}
		return addrs, nil, nil
	}
}

func holdersAssetRef(setName string) (string, error) {
	assetRef := setName[8 : len(setName)-1]
	if strings.TrimSpace(assetRef) == "" {
		return "", fmt.Errorf("@holders() asset reference is required")
	}
	return assetRef, nil
}

// MultipleAddressError indicates a set resolved to multiple addresses when one was required.
type MultipleAddressError struct {
	SetName string
	Count   int
}

func (e *MultipleAddressError) Error() string {
	return fmt.Sprintf("%s contains %d addresses; expected exactly 1", e.SetName, e.Count)
}
