// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"math"
	"math/bits"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

const feeFactorScale = uint64(1_000_000)

type authorizationBudget struct {
	pqScheme string
	mutable  bool
	maxFee   uint64
}

func authorizationBudgets(requests []signerapi.SignRequest, snapshot PlannerIdentitySnapshot, boundedItems []*boundedPlanItem, passthrough, foreign map[int]bool, passthroughBytes map[int][]byte) ([]authorizationBudget, *ServiceError) {
	budgets := make([]authorizationBudget, len(requests))
	for i, request := range requests {
		switch {
		case passthrough[i]:
			var stxn types.SignedTxn
			if err := msgpack.Decode(passthroughBytes[i], &stxn); err != nil {
				return nil, badRequest(fmt.Sprintf("transaction %d: cannot inspect passthrough authorization: %v", i+1, err))
			}
			scheme, err := signedTxnPQScheme(stxn)
			if err != nil {
				return nil, badRequest(fmt.Sprintf("transaction %d: %v", i+1, err))
			}
			budgets[i].pqScheme = scheme
		case foreign[i]:
			budgets[i].pqScheme = request.PQScheme
		default:
			budgets[i].mutable = true
			if i < len(boundedItems) && boundedItems[i] != nil && boundedItems[i].Metadata != nil {
				budgets[i].maxFee = boundedItems[i].Metadata.MaxFee
			}
			if snapshot.KeyTypes[request.AuthAddress] == nativefalcon.KeyType {
				budgets[i].pqScheme = nativefalcon.Scheme
			}
		}
		if budgets[i].pqScheme != "" && budgets[i].pqScheme != nativefalcon.Scheme {
			return nil, badRequest(fmt.Sprintf("transaction %d: unsupported native PQ scheme %q", i+1, budgets[i].pqScheme))
		}
	}
	return budgets, nil
}

func signedTxnPQScheme(stxn types.SignedTxn) (string, error) {
	top := !stxn.PQsig.Blank()
	nested := !stxn.Lsig.PQsig.Blank()
	if top && nested {
		return "", fmt.Errorf("signed transaction carries both top-level and delegated PQ authorization")
	}
	if top {
		return string(stxn.PQsig.Scheme[:]), nil
	}
	if nested {
		return string(stxn.Lsig.PQsig.Scheme[:]), nil
	}
	return "", nil
}

func hasNativePQAuthorization(budgets []authorizationBudget) bool {
	for _, budget := range budgets {
		if budget.pqScheme == nativefalcon.Scheme {
			return true
		}
	}
	return false
}

func applyNativePQFees(txns []types.Transaction, budgets []authorizationBudget, network PlannerNetworkParams, immutable bool) (uint64, []int, *ServiceError) {
	targets := make([]int, 0, len(budgets))
	for i, budget := range budgets {
		if budget.mutable {
			targets = append(targets, i)
		}
	}
	info, err := applyGroupFees(txns, budgets, network, lsigresource.Plan{TransactionCount: uint64(len(txns)), GroupSize: uint64(len(txns))}, 0, targets, immutable)
	return info.TotalFees, info.FeeIndices, err
}

func applyGroupFees(txns []types.Transaction, budgets []authorizationBudget, network PlannerNetworkParams, resourcePlan lsigresource.Plan, dummyCount int, preferredTargets []int, immutable bool) (DummyFeeInfo, *ServiceError) {
	var info DummyFeeInfo
	params, ok := sdkconfig.Consensus[protocol.ConsensusVersion(network.ConsensusVersion)]
	if !ok {
		version := network.ConsensusVersion
		if version == "" {
			version = "unknown"
		}
		return info, badRequest(fmt.Sprintf("group fee planning requires a supported consensus protocol (got %s)", version))
	}
	pqCount := uint64(0)
	for _, budget := range budgets {
		if budget.pqScheme == nativefalcon.Scheme {
			pqCount++
		}
	}
	if pqCount > 0 && !params.EnablePQSchemeFalcon1024 {
		return info, badRequest(fmt.Sprintf("native Falcon authorization requires a PQ-capable consensus protocol (got %s)", network.ConsensusVersion))
	}
	minFee := network.MinTxnFee
	if minFee == 0 {
		minFee = 1_000
	}
	const maxSaneMinFee = uint64(1_000_000)
	if minFee > maxSaneMinFee {
		return info, badRequest(fmt.Sprintf("network minimum fee %d microAlgos is implausibly high; refusing group fee planning", minFee))
	}
	var usage uint64
	var paid uint64
	for i, txn := range txns {
		factor := transactionFeeFactor(txn, params)
		if i < len(budgets) && budgets[i].pqScheme == nativefalcon.Scheme {
			factor = saturatingAdd(factor, nativefalcon.PQFeeContribution)
		}
		usage = saturatingAdd(usage, factor)
		paid = saturatingAdd(paid, uint64(txn.Fee))
	}
	usage = saturatingAdd(usage, resourcePlan.ProgramFeeFactorUsage)
	required, overflow := scaledFee(minFee, usage)
	if overflow {
		return info, badRequest("group fee calculation overflowed")
	}
	info.LSigCount = len(preferredTargets)
	info.ProgramFeeContribution, overflow = scaledFee(minFee, resourcePlan.ProgramFeeFactorUsage)
	if overflow {
		return DummyFeeInfo{}, badRequest("LogicSig program fee contribution overflowed")
	}
	pqFactor := saturatingMul(pqCount, nativefalcon.PQFeeContribution)
	info.NativePQFeeContribution, overflow = scaledFee(minFee, pqFactor)
	if overflow {
		return DummyFeeInfo{}, badRequest("native PQ fee contribution overflowed")
	}
	if dummyCount < 0 || uint64(dummyCount) > math.MaxUint64/minFee {
		return DummyFeeInfo{}, badRequest("dummy fee contribution overflowed")
	}
	info.DummyFeeContribution = uint64(dummyCount) * minFee
	if paid >= required {
		return info, nil
	}
	delta := required - paid
	if immutable {
		return DummyFeeInfo{}, badRequest(fmt.Sprintf("immutable group pays %d microAlgos, requires at least %d under consensus fee rules", paid, required))
	}
	targets := make([]int, 0, len(budgets))
	seen := make(map[int]bool, len(budgets))
	addTarget := func(index int) {
		if index >= 0 && index < len(budgets) && budgets[index].mutable && !seen[index] {
			seen[index] = true
			targets = append(targets, index)
		}
	}
	for _, index := range preferredTargets {
		addTarget(index)
	}
	for i, budget := range budgets {
		if budget.mutable {
			addTarget(i)
		}
	}
	if len(targets) == 0 {
		return DummyFeeInfo{}, badRequest("group fee deficit has no signer-controlled transaction")
	}
	totalCapacity := uint64(0)
	for _, target := range targets {
		current := uint64(txns[target].Fee)
		capacity := uint64(math.MaxUint64 - current)
		if budgets[target].maxFee > 0 {
			if current >= budgets[target].maxFee {
				capacity = 0
			} else {
				capacity = budgets[target].maxFee - current
			}
		}
		totalCapacity = saturatingAdd(totalCapacity, capacity)
	}
	if totalCapacity < delta {
		return DummyFeeInfo{}, badRequest(fmt.Sprintf("group fee deficit of %d microAlgos exceeds signer-controlled bounded fee capacity", delta))
	}
	remaining := delta
	for _, target := range targets {
		current := uint64(txns[target].Fee)
		capacity := math.MaxUint64 - current
		if budgets[target].maxFee > 0 {
			if current >= budgets[target].maxFee {
				continue
			}
			capacity = budgets[target].maxFee - current
		}
		add := min(remaining, capacity)
		if add == 0 {
			continue
		}
		txns[target].Fee = types.MicroAlgos(current + add)
		info.FeeIndices = append(info.FeeIndices, target)
		remaining -= add
		if remaining == 0 {
			break
		}
	}
	if remaining != 0 {
		return DummyFeeInfo{}, internal("group fee allocation failed after capacity validation")
	}
	info.TotalFees = delta
	return info, nil
}

func transactionFeeFactor(txn types.Transaction, params sdkconfig.ConsensusParams) uint64 {
	if txn.Type == types.StateProofTx {
		return 0
	}
	factor := feeFactorScale
	if txn.Type == types.HeartbeatTx && txn.HeartbeatTxnFields != nil && txn.HbChallengeDiscount {
		factor = 0
	}
	if len(txn.Note) > params.MaxTxnNoteBytes {
		factor = saturatingAdd(factor, saturatingMul(uint64(len(txn.Note)-params.MaxTxnNoteBytes), uint64(params.PerByteTxnSurcharge)))
	}
	if txn.Type == types.ApplicationCallTx {
		basicProgramBytes := params.MaxAppTotalProgramLen * (1 + params.MaxExtraAppProgramPages)
		programBytes := len(txn.ApprovalProgram) + len(txn.ClearStateProgram)
		if programBytes > basicProgramBytes {
			factor = saturatingAdd(factor, saturatingMul(uint64(programBytes-basicProgramBytes), uint64(params.PerByteTxnSurcharge)))
		}
		argBytes := 0
		for _, arg := range txn.ApplicationArgs {
			argBytes += len(arg)
		}
		if argBytes > params.MaxAppTotalArgLen {
			factor = saturatingAdd(factor, saturatingMul(uint64(argBytes-params.MaxAppTotalArgLen), uint64(params.PerByteTxnSurcharge)))
		}
	}
	return factor
}

func scaledFee(base, usage uint64) (uint64, bool) {
	hi, lo := bits.Mul64(base, usage)
	if hi >= feeFactorScale {
		return math.MaxUint64, true
	}
	quotient, remainder := bits.Div64(hi, lo, feeFactorScale)
	if remainder != 0 {
		if quotient == math.MaxUint64 {
			return math.MaxUint64, true
		}
		quotient++
	}
	return quotient, false
}

func saturatingAdd(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}

func saturatingMul(a, b uint64) uint64 {
	if a != 0 && b > math.MaxUint64/a {
		return math.MaxUint64
	}
	return a * b
}
