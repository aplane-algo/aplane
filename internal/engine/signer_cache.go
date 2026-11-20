// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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

func (e *Core) populateSignerCache(keys []signerapi.KeyInfo) error {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	return e.PopulateSignerCache(keys)
}

// populateAndSaveSignerCacheUnderClientLock refreshes the in-memory signer
// cache and persists it while the caller holds the shared APCLIENT_DATA lock.
func (e *Core) populateAndSaveSignerCacheUnderClientLock(keys []signerapi.KeyInfo) error {
	e.signerCacheMu.Lock()
	defer e.signerCacheMu.Unlock()
	if err := e.PopulateSignerCache(keys); err != nil {
		return err
	}
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

// signerCacheAuthorizationKind returns the authorization kind the signer
// reported for an address on /keys; the client never derives one from the
// key type. The boolean reports whether the address is present. A present
// address with an empty kind has none this client knows: the signer reported
// no kind (a witness key) or one outside the closed set. The prepare path
// (BuildSigningContext, CanSignForAddressWithKind) refuses such a key, and
// isAccountSignable does not list it. A pre-built group reads no kind: it
// leaves its authorization to the signer, which holds the key.
func (e *Core) signerCacheAuthorizationKind(address string) (algorithm.AuthorizationKind, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	if !e.SignerCache.HasAddress(address) {
		return "", false
	}
	return knownAuthorizationKind(e.SignerCache.AuthorizationKind(address)), true
}

// knownAuthorizationKind returns kind when it is in the closed set, and ""
// otherwise.
func knownAuthorizationKind(kind string) algorithm.AuthorizationKind {
	switch kind := algorithm.AuthorizationKind(kind); kind {
	case algorithm.AuthorizationEd25519, algorithm.AuthorizationNativePQ, algorithm.AuthorizationLogicSig:
		return kind
	default:
		return ""
	}
}

// AuthorizationFeeReserve returns the additional microAlgo fee a standalone
// transaction signed by signingAddr's key needs beyond its ordinary base fee.
// It covers LogicSig resource dummies and priced program bytes, plus the
// native-PQ fee contribution. Sweep flows reserve it before choosing a
// spend-everything amount. The calculation is local and deterministic because
// this release implements one compiled v42 consensus contract. signingAddr is
// the address that signs, SigningContext.SigningAddr: a rekeyed account's
// auth address, a rotating account itself. The auth cache is not read.
func (e *Core) AuthorizationFeeReserve(signingAddr string) (uint64, error) {
	profile, ok := e.signerCacheLogicSigResourceProfile(signingAddr)
	isNativeFalcon := e.signerCacheKeyType(signingAddr) == nativefalcon.KeyType
	if !ok && !isNativeFalcon {
		return 0, nil
	}
	if ok && isNativeFalcon {
		return 0, fmt.Errorf("signer cache classifies %s as both LogicSig and native Falcon", signingAddr)
	}
	consensus, err := lsigresource.CurrentConsensus()
	if err != nil {
		return 0, fmt.Errorf("load compiled v42 authorization contract: %w", err)
	}
	minFee := consensus.MinTxnFee
	if isNativeFalcon {
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
	plan, err := lsigresource.Solve(consensus, lsigresource.PlanInput{
		TransactionCount: 1,
		LogicSigs:        []lsigresource.Usage{usage},
		Dummy: lsigresource.Usage{
			ProgramBytes:  uint64(len(signing.EmbeddedDummyTealTok)),
			MaxOpcodeCost: signing.DummyOpcodeCost,
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

func (e *Core) signerCacheCosignerPublicKey(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.CosignerPublicKeyForAddress(address)
}

func (e *Core) signerCacheBoundedContract(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.BoundedContractForAddress(address)
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

func (e *Core) signerCacheCosignerComponentKeyType(address string) (string, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.SignerCache.CosignerComponentKeyTypeForAddress(address)
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

// SignerCacheAddresses returns, in no set order, the addresses the signer
// cache lists: the signer's aplane keys as apshell last read them.
func (e *Core) SignerCacheAddresses() []string {
	keys := e.signerCacheKeysSnapshot()
	addresses := make([]string, 0, len(keys))
	for address := range keys {
		addresses = append(addresses, address)
	}
	return addresses
}

// isAccountSignable reports whether the client would sign for address: the
// signer holds the key that signs for it (cache.IsAccountSignable: a rotating
// account's own, else its auth address's) and lists it with a kind this
// client knows, so the listing agrees with BuildSigningContext and canSignFor.
func (e *Core) isAccountSignable(address string) bool {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	if !cache.IsAccountSignable(address, &e.SignerCache, &e.AuthCache) {
		return false
	}
	key := address
	if !e.SignerCache.IsRotating(address) {
		key = e.AuthCache.ResolveEffectiveSigner(address)
	}
	return knownAuthorizationKind(e.SignerCache.AuthorizationKind(key)) != ""
}
