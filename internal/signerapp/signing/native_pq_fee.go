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
	"github.com/aplane-algo/aplane/internal/signerapi"
	nativefalcon "github.com/aplane-algo/aplane/internal/signing/falcon1024"
)

const feeFactorScale = uint64(1_000_000)

type authorizationBudget struct {
	pqScheme string
	mutable  bool
}

func authorizationBudgets(requests []signerapi.SignRequest, snapshot PlannerIdentitySnapshot, passthrough, foreign map[int]bool, passthroughBytes map[int][]byte) ([]authorizationBudget, *ServiceError) {
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
	params, ok := sdkconfig.Consensus[protocol.ConsensusVersion(network.ConsensusVersion)]
	if !ok || !params.EnablePQSchemeFalcon1024 {
		version := network.ConsensusVersion
		if version == "" {
			version = "unknown"
		}
		return 0, nil, badRequest(fmt.Sprintf("native Falcon authorization requires a PQ-capable consensus protocol (got %s)", version))
	}
	minFee := network.MinTxnFee
	if minFee == 0 {
		minFee = 1_000
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
	required, overflow := scaledFee(minFee, usage)
	if overflow {
		return 0, nil, badRequest("native PQ group fee calculation overflowed")
	}
	if paid >= required {
		return 0, nil, nil
	}
	delta := required - paid
	if immutable {
		return 0, nil, badRequest(fmt.Sprintf("immutable native PQ group pays %d microAlgos, requires at least %d", paid, required))
	}
	target := -1
	for i, budget := range budgets {
		if budget.mutable {
			target = i
			break
		}
	}
	if target < 0 || target >= len(txns) {
		return 0, nil, badRequest("native PQ fee deficit has no signer-controlled transaction")
	}
	if delta > math.MaxUint64-uint64(txns[target].Fee) {
		return 0, nil, badRequest("native PQ fee adjustment overflows transaction fee")
	}
	txns[target].Fee = types.MicroAlgos(uint64(txns[target].Fee) + delta)
	return delta, []int{target}, nil
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
