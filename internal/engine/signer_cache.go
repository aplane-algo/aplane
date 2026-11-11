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

// signerCacheAuthorizationKind classifies an address from one consistent
// signer-cache snapshot. The boolean reports whether the address is present;
// a present address with an empty kind has invalid or unknown key metadata.
func (e *Core) signerCacheAuthorizationKind(address string) (algorithm.AuthorizationKind, bool) {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	return e.authorizationKindLocked(address)
}

// authorizationKindLocked is signerCacheAuthorizationKind for a caller that
// holds signerCacheMu.
func (e *Core) authorizationKindLocked(address string) (algorithm.AuthorizationKind, bool) {
	if !e.SignerCache.HasAddress(address) {
		return "", false
	}
	if e.SignerCache.IsGenericLsig(address) {
		return algorithm.AuthorizationLogicSig, true
	}
	if _, ok := e.SignerCache.LogicSigResourceProfile(address); ok {
		return algorithm.AuthorizationLogicSig, true
	}
	keyType := e.SignerCache.GetKeyType(address)
	if keyType == "ed25519" {
		return algorithm.AuthorizationEd25519, true
	}
	metadata, err := algorithm.GetMetadata(keyType)
	if err != nil {
		return "", true
	}
	return metadata.AuthorizationKind(), true
}

// AuthorizationFeeReserve returns the additional microAlgo fee a standalone
// transaction from sender needs beyond its ordinary base fee. It covers
// LogicSig resource dummies and priced program bytes, plus the native-PQ fee
// contribution. Sweep flows reserve it before choosing a spend-everything
// amount. The calculation is local and deterministic because this release
// implements one compiled v42 consensus contract.
func (e *Core) AuthorizationFeeReserve(sender string) (uint64, error) {
	effectiveSigner := e.AuthCache.ResolveEffectiveSigner(sender)
	profile, ok := e.signerCacheLogicSigResourceProfile(effectiveSigner)
	isNativeFalcon := e.signerCacheKeyType(effectiveSigner) == nativefalcon.KeyType
	if !ok && !isNativeFalcon {
		return 0, nil
	}
	if ok && isNativeFalcon {
		return 0, fmt.Errorf("signer cache classifies %s as both LogicSig and native Falcon", effectiveSigner)
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

// signerCacheSigningArgNames returns the names of the LogicSig arguments the
// signer reported for address's key: a template's signing arguments, or a
// bounded account's runtime arguments. A native key has none.
func (e *Core) signerCacheSigningArgNames(address string) []string {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	args := e.SignerCache.GetSigningArgs(address)
	names := make([]string, len(args))
	for i, arg := range args {
		names[i] = arg.Name
	}
	return names
}

// validateSignerLsigArgs checks LogicSig arguments against what address's key
// declares. A native key (ed25519 or Falcon) declares none: it signs the
// transaction itself and has no program to pass them to, and the signer
// refuses a request that supplies them. A LogicSig's argument schema names the
// arguments it takes and which of them a template requires. A key the client
// does not hold is left to the signer.
func (e *Core) validateSignerLsigArgs(address string, args map[string][]byte) error {
	e.signerCacheMu.RLock()
	defer e.signerCacheMu.RUnlock()
	if len(args) > 0 {
		if kind, held := e.authorizationKindLocked(address); held &&
			(kind == algorithm.AuthorizationEd25519 || kind == algorithm.AuthorizationNativePQ) {
			return fmt.Errorf("the %s key of %s is not a LogicSig and takes no arguments", e.SignerCache.GetKeyType(address), address)
		}
	} else if !e.SignerCache.IsGenericLsig(address) {
		return nil
	}
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
