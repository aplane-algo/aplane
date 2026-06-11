// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"context"
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/refname"
)

// AliasMutationResult captures the persistence outcome of an alias change.
type AliasMutationResult struct {
	Address    string
	WasUpdated bool
	OldAddress string
}

// RefreshAuthAddress refreshes the cached auth address for a specific account.
func (s *State) RefreshAuthAddress(addr string) (string, error) {
	return s.RefreshAuthAddressWithContext(context.Background(), addr)
}

func (s *State) RefreshAuthAddressWithContext(ctx context.Context, addr string) (string, error) {
	var authAddr string
	err := s.WithExclusiveLock(func() error {
		if s.DataDir != "" {
			s.AuthCache = cache.LoadAuthCacheFromStore(s.CacheStore, s.Network)
		}
		var err error
		authAddr, err = s.AuthCache.RefreshAuthAddressWithContext(ctx, s.AlgodClient, addr, s.Network)
		return err
	})
	return authAddr, err
}

// AddAlias persists an alias mutation into the client-side cache state.
func (s *State) AddAlias(name, address string) (*AliasMutationResult, error) {
	return s.AddAliasWithContext(context.Background(), name, address)
}

// AddAliasWithContext persists an alias mutation into the client-side cache
// state and uses the caller's context for any opportunistic algod lookups.
func (s *State) AddAliasWithContext(ctx context.Context, name, address string) (*AliasMutationResult, error) {
	name = refname.NormalizeAlias(name)
	if err := refname.ValidateAlias(name); err != nil {
		return nil, err
	}
	decoded, err := types.DecodeAddress(strings.ToUpper(address))
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	address = decoded.String()

	result := &AliasMutationResult{
		Address: address,
	}

	err = s.WithExclusiveLock(func() error {
		s.ReloadAliasCache()
		s.ReloadSetCache()

		if s.AliasCache.Aliases == nil {
			s.AliasCache.Aliases = make(map[string]string)
		}

		if existingAlias := s.AliasCache.GetAliasForAddress(address); existingAlias != "" && existingAlias != name {
			return fmt.Errorf("address already has alias '%s'", existingAlias)
		}

		if oldAddr, exists := s.AliasCache.Aliases[name]; exists {
			if oldAddr == address {
				return nil
			}
			result.WasUpdated = true
			result.OldAddress = oldAddr
		}

		restoreAlias := func() error {
			if result.WasUpdated {
				s.AliasCache.Aliases[name] = result.OldAddress
			} else {
				delete(s.AliasCache.Aliases, name)
			}
			return s.AliasCache.SaveCacheLocked()
		}

		s.AliasCache.Aliases[name] = address
		if err := s.AliasCache.SaveCacheLocked(); err != nil {
			return err
		}

		if s.AlgodClient != nil {
			acctInfo, err := s.AlgodClient.AccountInformation(address).Do(ctx)
			if err == nil {
				if s.DataDir != "" {
					s.AuthCache = cache.LoadAuthCacheFromStore(s.CacheStore, s.Network)
				}
				if err := s.AuthCache.UpdateAuthAddress(address, acctInfo.AuthAddr, s.Network); err != nil {
					if rollbackErr := restoreAlias(); rollbackErr != nil {
						return fmt.Errorf("failed to update auth cache: %w (alias rollback also failed: %v)", err, rollbackErr)
					}
					return fmt.Errorf("failed to update auth cache: %w", err)
				}
				if err := s.AuthCache.PruneToOwnedAddresses(s.ownedAuthAddresses(), s.Network); err != nil {
					if rollbackErr := restoreAlias(); rollbackErr != nil {
						return fmt.Errorf("failed to prune auth cache: %w (alias rollback also failed: %v)", err, rollbackErr)
					}
					return fmt.Errorf("failed to prune auth cache: %w", err)
				}
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if result.WasUpdated && result.OldAddress == address {
		result.WasUpdated = false
		result.OldAddress = ""
	}

	return result, nil
}

// RemoveAlias removes an alias from persisted client-side cache state.
// The returned bool reports whether the alias existed.
func (s *State) RemoveAlias(name string) (string, bool, error) {
	name = refname.NormalizeAlias(name)
	if err := refname.ValidateAlias(name); err != nil {
		return "", false, err
	}
	var address string
	found := true
	err := s.WithExclusiveLock(func() error {
		s.ReloadAliasCache()
		s.ReloadSetCache()
		if s.AliasCache.Aliases == nil {
			found = false
			return nil
		}

		var exists bool
		address, exists = s.AliasCache.Aliases[name]
		if !exists {
			found = false
			return nil
		}

		delete(s.AliasCache.Aliases, name)
		if err := s.AliasCache.SaveCacheLocked(); err != nil {
			return err
		}
		if s.DataDir != "" {
			s.AuthCache = cache.LoadAuthCacheFromStore(s.CacheStore, s.Network)
		}
		return s.AuthCache.PruneToOwnedAddresses(s.ownedAuthAddresses(), s.Network)
	})
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}

	return address, true, nil
}

func (s *State) ownedAuthAddresses() map[string]bool {
	owned := make(map[string]bool)
	for _, addr := range s.AliasCache.Aliases {
		owned[addr] = true
	}
	for addr := range s.SignerCache.Keys {
		owned[addr] = true
	}
	return owned
}
