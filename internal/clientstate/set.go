// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientstate

import (
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/refname"
)

// ResolveAddressFunc resolves one address-like input into a canonical address.
type ResolveAddressFunc func(input string) (string, error)

// SetMutationResult captures the persistence outcome of a set change.
type SetMutationResult struct {
	Addresses  []string
	WasUpdated bool
	OldCount   int
}

// AddSet creates or replaces a set with the given resolved addresses.
func (s *State) AddSet(name string, inputs []string, resolve ResolveAddressFunc) (*SetMutationResult, error) {
	name = refname.NormalizeSet(name)
	if err := refname.ValidateSet(name); err != nil {
		return nil, err
	}
	result := &SetMutationResult{}
	err := s.WithExclusiveLock(func() error {
		s.ReloadAliasCache()
		s.ReloadSetCache()

		resolvedAddresses := make([]string, 0, len(inputs))
		for _, input := range inputs {
			addr, err := resolve(input)
			if err != nil {
				return fmt.Errorf("failed to resolve '%s': %w", input, err)
			}
			resolvedAddresses = append(resolvedAddresses, addr)
		}

		result.Addresses = resolvedAddresses
		if s.SetCache.Sets == nil {
			s.SetCache.Sets = make(map[string][]string)
		}
		if oldAddrs, exists := s.SetCache.Sets[name]; exists {
			result.WasUpdated = true
			result.OldCount = len(oldAddrs)
		}

		s.SetCache.Sets[name] = resolvedAddresses
		return s.SetCache.SaveCacheLocked()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RemoveSet removes a set and reports whether it existed.
func (s *State) RemoveSet(name string) (int, bool, error) {
	name = refname.NormalizeSet(name)
	if err := refname.ValidateSet(name); err != nil {
		return 0, false, err
	}
	var count int
	found := true
	err := s.WithExclusiveLock(func() error {
		s.ReloadSetCache()
		if s.SetCache.Sets == nil {
			found = false
			return nil
		}

		addresses, exists := s.SetCache.Sets[name]
		if !exists {
			found = false
			return nil
		}

		count = len(addresses)
		delete(s.SetCache.Sets, name)
		return s.SetCache.SaveCacheLocked()
	})
	if err != nil {
		return 0, false, err
	}
	if !found {
		return 0, false, nil
	}
	return count, true, nil
}

// AddToSet adds resolved addresses to an existing set or creates it if needed.
func (s *State) AddToSet(name string, inputs []string, resolve ResolveAddressFunc) (*SetMutationResult, error) {
	name = refname.NormalizeSet(name)
	if err := refname.ValidateSet(name); err != nil {
		return nil, err
	}
	result := &SetMutationResult{}
	err := s.WithExclusiveLock(func() error {
		s.ReloadAliasCache()
		s.ReloadSetCache()

		newAddresses := make([]string, 0, len(inputs))
		for _, input := range inputs {
			addr, err := resolve(input)
			if err != nil {
				return fmt.Errorf("failed to resolve '%s': %w", input, err)
			}
			newAddresses = append(newAddresses, addr)
		}

		if s.SetCache.Sets == nil {
			s.SetCache.Sets = make(map[string][]string)
		}

		existingAddresses := s.SetCache.Sets[name]
		result.WasUpdated = len(existingAddresses) > 0
		result.OldCount = len(existingAddresses)

		addressSet := make(map[string]bool)
		for _, addr := range existingAddresses {
			addressSet[addr] = true
		}
		for _, addr := range newAddresses {
			addressSet[addr] = true
		}

		mergedAddresses := make([]string, 0, len(addressSet))
		for addr := range addressSet {
			mergedAddresses = append(mergedAddresses, addr)
		}
		sort.Strings(mergedAddresses)

		s.SetCache.Sets[name] = mergedAddresses
		result.Addresses = mergedAddresses
		return s.SetCache.SaveCacheLocked()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RemoveFromSet removes resolved addresses from an existing set.
func (s *State) RemoveFromSet(name string, inputs []string, resolve ResolveAddressFunc) (*SetMutationResult, bool, error) {
	name = refname.NormalizeSet(name)
	if err := refname.ValidateSet(name); err != nil {
		return nil, false, err
	}
	result := &SetMutationResult{}
	found := true
	err := s.WithExclusiveLock(func() error {
		s.ReloadAliasCache()
		s.ReloadSetCache()

		if s.SetCache.Sets == nil {
			found = false
			return nil
		}
		existingAddresses, exists := s.SetCache.Sets[name]
		if !exists {
			found = false
			return nil
		}

		toRemove := make(map[string]bool)
		for _, input := range inputs {
			addr, err := resolve(input)
			if err != nil {
				return fmt.Errorf("failed to resolve '%s': %w", input, err)
			}
			toRemove[addr] = true
		}

		remainingAddresses := make([]string, 0)
		for _, addr := range existingAddresses {
			if !toRemove[addr] {
				remainingAddresses = append(remainingAddresses, addr)
			}
		}

		result.Addresses = remainingAddresses
		result.WasUpdated = true
		result.OldCount = len(existingAddresses)
		s.SetCache.Sets[name] = remainingAddresses
		return s.SetCache.SaveCacheLocked()
	})
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	return result, true, nil
}
