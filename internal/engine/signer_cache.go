// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signing"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

// AuthorizationFeeReserve returns the additional microAlgo fee a standalone
// transaction signed by signingAddr's key needs beyond its ordinary base fee.
// It covers LogicSig resource dummies and priced program bytes, plus the
// native-PQ fee contribution. Sweep flows reserve it before choosing a
// spend-everything amount. The calculation is local and deterministic because
// this release implements one compiled v42 consensus contract. signingAddr is
// the address that signs, SigningContext.SigningAddr: a rekeyed account's
// auth address, a rotating account itself. The auth cache is not read.
func (e *Core) AuthorizationFeeReserve(signingAddr string) (uint64, error) {
	profile, ok := e.SignerCacheLogicSigResourceProfile(signingAddr)
	isNativeFalcon := e.SignerCacheKeyType(signingAddr) == nativefalcon.KeyType
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
