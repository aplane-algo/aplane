// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/lsig"
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

func (e *Engine) signerCacheLsigSize(address string) int {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.GetLsigSize(address)
}

// DummyFeeReserve returns the additional microAlgo fee a single standalone
// transaction from sender will accrue from server-side dummy transactions
// added for LogicSig budget. It is 0 for ed25519 and for LogicSigs small
// enough to need no dummies. "Spend everything" flows (sweep) must reserve
// this on top of the base transaction fee, because the signer pools the dummy
// fees onto the LogicSig transaction and the account pays them.
func (e *Engine) DummyFeeReserve(sender string, minFee uint64) uint64 {
	effectiveSigner := e.AuthCache.ResolveEffectiveSigner(sender)
	lsigSize := e.signerCacheLsigSize(effectiveSigner)
	if lsigSize <= lsig.TxLsigBudget {
		return 0
	}
	extra := lsigSize - lsig.TxLsigBudget
	dummies := (extra + lsig.TxLsigBudget - 1) / lsig.TxLsigBudget
	return uint64(dummies) * minFee
}

func (e *Engine) signerCacheSentryPublicKey(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.SentryPublicKeyForAddress(address)
}

func (e *Engine) signerCacheSigningFlow(address string) string {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.SigningFlowForAddress(address)
}

func (e *Engine) signerCacheGuardedSigningMetadataNeedsRefresh(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.GuardedSigningMetadataNeedsRefresh(address)
}

func (e *Engine) signerCacheSentryComponentKeyType(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.SentryComponentKeyTypeForAddress(address)
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
