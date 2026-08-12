// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"fmt"
	"math"
	"math/bits"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
)

func (e *Core) signerCacheCount() int {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.Count()
}

func (e *Core) signerCacheIsLocked() bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.Locked
}

func (e *Core) setSignerCacheLockedFlag(locked bool) {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.SignerCache.Locked = locked
}

func (e *Core) resetSignerCache(locked bool) {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.SignerCache = cache.NewSignerCache()
	e.SignerCache.Locked = locked
	e.SignerCache.BindStore(e.CacheStore)
}

func (e *Core) populateSignerCache(keys []signerapi.KeyInfo) {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.PopulateSignerCache(keys)
}

// populateAndSaveSignerCacheUnderClientLock refreshes the in-memory signer
// cache and persists it while the caller holds the shared APCLIENT_DATA lock.
func (e *Core) populateAndSaveSignerCacheUnderClientLock(keys []signerapi.KeyInfo) error {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	e.PopulateSignerCache(keys)
	return e.SaveSignerCacheLocked()
}

func (e *Core) signerCacheHasAddress(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.HasAddress(address)
}

func (e *Core) signerCacheKeyType(address string) string {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.GetKeyType(address)
}

func (e *Core) signerCacheLogicSigResourceProfile(address string) (lsigresource.Profile, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.LogicSigResourceProfile(address)
}

// AuthorizationFeeReserve returns the additional microAlgo fee a standalone
// transaction from sender needs beyond its ordinary base fee. It covers
// LogicSig resource dummies and priced program bytes, plus the native-PQ fee
// contribution. Sweep flows reserve it before choosing a spend-everything
// amount.
func (e *Core) AuthorizationFeeReserve(ctx context.Context, sender string) (uint64, error) {
	effectiveSigner := e.AuthCache.ResolveEffectiveSigner(sender)
	profile, ok := e.signerCacheLogicSigResourceProfile(effectiveSigner)
	isNativeFalcon := e.signerCacheKeyType(effectiveSigner) == nativefalcon.KeyType
	if !ok && !isNativeFalcon {
		return 0, nil
	}
	if ok && isNativeFalcon {
		return 0, fmt.Errorf("signer cache classifies %s as both LogicSig and native Falcon", effectiveSigner)
	}
	if e.AlgodClient == nil {
		return 0, ErrNoAlgodClient
	}
	params, err := e.AlgodClient.SuggestedParams().Do(ctx)
	if err != nil {
		return 0, fmt.Errorf("load consensus parameters for authorization fee reserve: %w", err)
	}
	minFee := params.MinFee
	if minFee == 0 {
		minFee = signing.DefaultMinFee
	}
	if isNativeFalcon {
		consensus, known := sdkconfig.Consensus[protocol.ConsensusVersion(params.ConsensusVersion)]
		if !known {
			return 0, fmt.Errorf("resolve native Falcon fee reserve: unsupported consensus %q", params.ConsensusVersion)
		}
		if !consensus.EnablePQSchemeFalcon1024 {
			return 0, fmt.Errorf("resolve native Falcon fee reserve: consensus %q does not enable Falcon-1024", params.ConsensusVersion)
		}
		reserve, overflow := scaleFeeFactor(minFee, nativefalcon.PQFeeContribution)
		if overflow {
			return 0, fmt.Errorf("native Falcon fee reserve overflowed")
		}
		return reserve, nil
	}
	usage, err := profile.UsageForPath(lsigresource.PathSpend)
	if err != nil {
		usage, err = profile.UsageForPath(lsigresource.PathDefault)
	}
	if err != nil {
		return 0, fmt.Errorf("resolve LogicSig spend resources: %w", err)
	}
	consensus, err := lsigresource.ResolveConsensus(params.ConsensusVersion)
	if err != nil {
		return 0, fmt.Errorf("resolve LogicSig fee reserve: %w", err)
	}
	plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs:        []lsigresource.Usage{usage},
		Dummy: lsigresource.Usage{
			ProgramBytes:  uint64(len(signing.EmbeddedDummyTealTok)),
			MaxOpcodeCost: 1,
		},
	})
	if err != nil {
		return 0, fmt.Errorf("plan LogicSig fee reserve: %w", err)
	}
	dummyFees, overflow := multiplyReserve(plan.DummyCount, minFee)
	if overflow {
		return 0, fmt.Errorf("LogicSig dummy fee reserve overflowed")
	}
	programFee, overflow := scaleFeeFactor(minFee, plan.ProgramFeeFactorUsage)
	if overflow || programFee > math.MaxUint64-dummyFees {
		return 0, fmt.Errorf("LogicSig program fee reserve overflowed")
	}
	return dummyFees + programFee, nil
}

func multiplyReserve(a, b uint64) (uint64, bool) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, true
	}
	return a * b, false
}

func scaleFeeFactor(base, usage uint64) (uint64, bool) {
	const factorScale = uint64(1_000_000)
	hi, lo := bits.Mul64(base, usage)
	if hi >= factorScale {
		return 0, true
	}
	quotient, remainder := bits.Div64(hi, lo, factorScale)
	if remainder != 0 {
		if quotient == math.MaxUint64 {
			return 0, true
		}
		quotient++
	}
	return quotient, false
}

func (e *Core) signerCacheSentryPublicKey(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.SentryPublicKeyForAddress(address)
}

func (e *Core) signerCacheBoundedMaxFee(address string) (uint64, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.BoundedMaxFeeForAddress(address)
}

func (e *Core) signerCacheSigningFlow(address string) string {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.SigningFlowForAddress(address)
}

func (e *Core) signerCacheGuardedSigningMetadataNeedsRefresh(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.GuardedSigningMetadataNeedsRefresh(address)
}

func (e *Core) signerCacheSentryComponentKeyType(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.SentryComponentKeyTypeForAddress(address)
}

func (e *Core) signerCacheIsGenericLsig(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.IsGenericLsig(address)
}

func (e *Core) validateSignerLsigArgs(address string, args map[string][]byte) error {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.ValidateLsigArgs(address, args)
}

func (e *Core) signerCacheKeysSnapshot() map[string]string {
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

func (e *Core) signerCacheAddresses() []string {
	keys := e.signerCacheKeysSnapshot()
	addresses := make([]string, 0, len(keys))
	for address := range keys {
		addresses = append(addresses, address)
	}
	return addresses
}

func (e *Core) isAccountSignable(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return cache.IsAccountSignable(address, &e.SignerCache, &e.AuthCache)
}
