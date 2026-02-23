// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package util

import (
	"fmt"
	"strings"
)

// ReservedSetNames contains set names that cannot be used for user-defined sets.
// These are reserved for dynamic sets resolved at runtime.
var ReservedSetNames = map[string]bool{
	"signers": true, // Dynamic set of signable addresses
	"all":     true, // Dynamic set of all known addresses (aliases + signers)
}

// IsReservedSetName returns true if the name is reserved for dynamic sets.
func IsReservedSetName(name string) bool {
	return ReservedSetNames[name]
}

// SignerProvider is a function that returns signable addresses dynamically.
type SignerProvider func() []string

// AllAddressesProvider is a function that returns all known addresses dynamically.
type AllAddressesProvider func() []string

// HoldersProvider is a function that returns addresses holding an asset.
// The assetRef can be "algo", an asset name from cache, or an asset ID.
type HoldersProvider func(assetRef string) ([]string, error)

// AddressResolver provides unified address resolution for commands.
// It resolves aliases, @setnames, and inline lists to arrays of addresses.
// Special dynamic sets like @signers and @all are resolved via providers.
type AddressResolver struct {
	AliasCache      *AliasCache
	SetCache        *SetCache
	SignerProvider  SignerProvider       // Optional: provides @signers dynamic set
	AllProvider     AllAddressesProvider // Optional: provides @all dynamic set
	HoldersProvider HoldersProvider      // Optional: provides @holders(asset) dynamic set
}

// NewAddressResolver creates a new resolver with the given caches
func NewAddressResolver(aliasCache *AliasCache, setCache *SetCache) *AddressResolver {
	return &AddressResolver{
		AliasCache: aliasCache,
		SetCache:   setCache,
	}
}

// WithSignerProvider returns a copy of the resolver with a signer provider set
func (r *AddressResolver) WithSignerProvider(provider SignerProvider) *AddressResolver {
	return &AddressResolver{
		AliasCache:      r.AliasCache,
		SetCache:        r.SetCache,
		SignerProvider:  provider,
		AllProvider:     r.AllProvider,
		HoldersProvider: r.HoldersProvider,
	}
}

// WithAllProvider returns a copy of the resolver with an all-addresses provider set
func (r *AddressResolver) WithAllProvider(provider AllAddressesProvider) *AddressResolver {
	return &AddressResolver{
		AliasCache:      r.AliasCache,
		SetCache:        r.SetCache,
		SignerProvider:  r.SignerProvider,
		AllProvider:     provider,
		HoldersProvider: r.HoldersProvider,
	}
}

// WithHoldersProvider returns a copy of the resolver with a holders provider set
func (r *AddressResolver) WithHoldersProvider(provider HoldersProvider) *AddressResolver {
	return &AddressResolver{
		AliasCache:      r.AliasCache,
		SetCache:        r.SetCache,
		SignerProvider:  r.SignerProvider,
		AllProvider:     r.AllProvider,
		HoldersProvider: provider,
	}
}

// ResolveList resolves a list of inputs (aliases, addresses, or @setnames) to addresses.
// Each input can be:
//   - A raw 58-char Algorand address (passed through)
//   - An alias (resolved via AliasCache)
//   - A @setname (expanded via SetCache)
//   - @signers (dynamic set of signable addresses)
//   - @all (dynamic set of all known addresses)
//   - @holders(asset) (dynamic set of addresses holding an asset)
//
// Returns the flattened list of resolved addresses.
func (r *AddressResolver) ResolveList(inputs []string) ([]string, error) {
	var result []string

	for _, input := range inputs {
		if len(input) == 0 {
			continue
		}

		if input[0] == '@' {
			setName := input[1:]

			// Check for @signers special dynamic set
			if setName == "signers" {
				if r.SignerProvider == nil {
					return nil, fmt.Errorf("@signers not available (not connected to signer)")
				}
				addresses := r.SignerProvider()
				if len(addresses) == 0 {
					return nil, fmt.Errorf("@signers is empty (no signable accounts)")
				}
				result = append(result, addresses...)
				continue
			}

			// Check for @all special dynamic set
			if setName == "all" {
				if r.AllProvider == nil {
					return nil, fmt.Errorf("@all not available")
				}
				addresses := r.AllProvider()
				if len(addresses) == 0 {
					return nil, fmt.Errorf("@all is empty (no accounts defined)")
				}
				result = append(result, addresses...)
				continue
			}

			// Check for @holders(asset) dynamic set
			if strings.HasPrefix(setName, "holders(") && strings.HasSuffix(setName, ")") {
				assetRef := setName[8 : len(setName)-1] // extract asset from "holders(asset)"
				if r.HoldersProvider == nil {
					return nil, fmt.Errorf("@holders() not available")
				}
				addresses, err := r.HoldersProvider(assetRef)
				if err != nil {
					return nil, fmt.Errorf("@holders(%s): %w", assetRef, err)
				}
				if len(addresses) == 0 {
					return nil, fmt.Errorf("@holders(%s) is empty (no holders found)", assetRef)
				}
				result = append(result, addresses...)
				continue
			}

			// Regular set reference - expand to multiple addresses
			addresses, err := r.SetCache.GetSet(setName)
			if err != nil {
				return nil, err
			}
			result = append(result, addresses...)
		} else {
			// Single address or alias
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
// Returns an error if the input resolves to multiple addresses (e.g., a set).
func (r *AddressResolver) ResolveSingle(input string) (string, error) {
	if len(input) == 0 {
		return "", nil
	}

	if input[0] == '@' {
		setName := input[1:]

		// Check for @signers special dynamic set
		if setName == "signers" {
			if r.SignerProvider == nil {
				return "", fmt.Errorf("@signers not available (not connected to signer)")
			}
			addresses := r.SignerProvider()
			if len(addresses) != 1 {
				return "", &MultipleAddressError{SetName: input, Count: len(addresses)}
			}
			return addresses[0], nil
		}

		// Check for @all special dynamic set
		if setName == "all" {
			if r.AllProvider == nil {
				return "", fmt.Errorf("@all not available")
			}
			addresses := r.AllProvider()
			if len(addresses) != 1 {
				return "", &MultipleAddressError{SetName: input, Count: len(addresses)}
			}
			return addresses[0], nil
		}

		// Check for @holders(asset) dynamic set
		if strings.HasPrefix(setName, "holders(") && strings.HasSuffix(setName, ")") {
			assetRef := setName[8 : len(setName)-1]
			if r.HoldersProvider == nil {
				return "", fmt.Errorf("@holders() not available")
			}
			addresses, err := r.HoldersProvider(assetRef)
			if err != nil {
				return "", fmt.Errorf("@holders(%s): %w", assetRef, err)
			}
			if len(addresses) != 1 {
				return "", &MultipleAddressError{SetName: input, Count: len(addresses)}
			}
			return addresses[0], nil
		}

		// Regular set reference - not allowed for single resolution unless exactly one
		addresses, err := r.SetCache.GetSet(setName)
		if err != nil {
			return "", err
		}
		if len(addresses) != 1 {
			return "", &MultipleAddressError{SetName: input, Count: len(addresses)}
		}
		return addresses[0], nil
	}

	// Single address or alias
	return r.AliasCache.ResolveAddress(input)
}

// MultipleAddressError is returned when a single address was expected but multiple were found
type MultipleAddressError struct {
	SetName string
	Count   int
}

func (e *MultipleAddressError) Error() string {
	return fmt.Sprintf("expected single address but set '%s' contains %d addresses", e.SetName, e.Count)
}
