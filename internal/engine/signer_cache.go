// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

func (e *Engine) signerCacheCount() int {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.Count()
}

func (e *Engine) signerCacheIsLocked() bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.Locked
}

func (e *Engine) setSignerCacheLockedFlag(locked bool) {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.SignerCache.Locked = locked
}

func (e *Engine) resetSignerCache(locked bool) {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.SignerCache = cache.NewSignerCache()
	e.SignerCache.Locked = locked
	e.SignerCache.BindStore(e.CacheStore)
}

func (e *Engine) populateSignerCache(keys []signerapi.KeyInfo) {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.PopulateSignerCache(keys)
}

// populateAndSaveSignerCacheUnderClientLock refreshes the in-memory signer
// cache and persists it while the caller holds the shared APCLIENT_DATA lock.
func (e *Engine) populateAndSaveSignerCacheUnderClientLock(keys []signerapi.KeyInfo) error {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.PopulateSignerCache(keys)
	return e.SaveSignerCacheLocked()
}

func (e *Engine) signerCacheHasAddress(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.HasAddress(address)
}

func (e *Engine) signerCacheKeyType(address string) string {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.GetKeyType(address)
}

func (e *Engine) signerCacheIsGenericLsig(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.IsGenericLsig(address)
}

func (e *Engine) validateSignerLsigArgs(address string, args map[string][]byte) error {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.ValidateLsigArgs(address, args)
}

func (e *Engine) signerCacheKeysSnapshot() map[string]string {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()

	if e.SignerCache.Keys == nil {
		return nil
	}
	keys := make(map[string]string, len(e.SignerCache.Keys))
	for address, keyType := range e.SignerCache.Keys {
		keys[address] = keyType
	}
	return keys
}

func (e *Engine) signerCacheAddresses() []string {
	keys := e.signerCacheKeysSnapshot()
	addresses := make([]string, 0, len(keys))
	for address := range keys {
		addresses = append(addresses, address)
	}
	return addresses
}

func (e *Engine) isAccountSignable(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return cache.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
}
