// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/lsig"
	"github.com/aplane-algo/aplane/internal/signerapi"
	txsigning "github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// PlannerIdentitySnapshot captures the identity-scoped signer metadata needed for planning.
type PlannerIdentitySnapshot struct {
	Revision  uint64
	KeyFiles  map[string]string
	KeyTypes  map[string]string
	LSigSizes map[string]int
}

// PlannerDeps supplies process-specific data needed by the package-owned planner.
type PlannerDeps interface {
	Snapshot(identityID string) PlannerIdentitySnapshot
	MinTxnFee(genesisHash types.Digest) uint64
}

// PlannerOptions configures non-environmental planner behavior.
type PlannerOptions struct {
	AuditLog               AuditLogger
	Console                Console
	GenerateTxnDescription GenerateTxnDescriptionFunc
	GenesisHashResolver    apconfig.GenesisHashNetworkResolver
}

// NewPlanner constructs the canonical signer planner using package-owned planning logic.
func NewPlanner(deps PlannerDeps, opts PlannerOptions) *Planner {
	return &Planner{
		AuditLog:               opts.AuditLog,
		Console:                opts.Console,
		GenerateTxnDescription: opts.GenerateTxnDescription,
		GenesisHashResolver:    opts.GenesisHashResolver,
		VerifySignableKeys: func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, passthroughIndices, foreignIndices map[int]bool) (int, *ServiceError) {
			return verifySignableKeys(opts.Console, snapshot, identityID, requests, passthroughIndices, foreignIndices)
		},
		CalculateDummies: func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, txns []types.Transaction, passthroughIndices, foreignIndices map[int]bool, hasPassthrough, isPreGrouped bool) (int, []int, *ServiceError) {
			return calculateDummies(opts.Console, snapshot, identityID, requests, txns, passthroughIndices, foreignIndices, hasPassthrough, isPreGrouped)
		},
		BuildFinalGroup: func(txns []types.Transaction, dummiesNeeded int, lsigIndices []int, isPreGrouped bool) ([]types.Transaction, []types.Transaction, DummyFeeInfo, bool, *ServiceError) {
			return buildFinalGroup(deps, opts.Console, txns, dummiesNeeded, lsigIndices, isPreGrouped)
		},
		Snapshot: deps.Snapshot,
	}
}

func verifySignableKeys(console Console, snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, passthroughIndices, foreignIndices map[int]bool) (signableCount int, err *ServiceError) {
	for i, txReq := range requests {
		if passthroughIndices[i] {
			consoleOf(console).Printf("[GROUP]   [%d] passthrough ok\n", i+1)
			continue
		}
		if foreignIndices[i] {
			if txReq.LsigSize > 0 {
				consoleOf(console).Printf("[GROUP]   [%d] foreign (lsig_size=%d) ok\n", i+1, txReq.LsigSize)
			} else {
				consoleOf(console).Printf("[GROUP]   [%d] foreign ok\n", i+1)
			}
			continue
		}

		if _, ok := snapshot.KeyFiles[txReq.AuthAddress]; !ok {
			return 0, badRequest(fmt.Sprintf("transaction %d: no key found for address: %s", i+1, txReq.AuthAddress))
		}

		keyType := snapshot.KeyTypes[txReq.AuthAddress]
		if keyType == "" {
			return 0, internal(fmt.Sprintf("transaction %d: missing key type metadata for auth address %s", i+1, txReq.AuthAddress))
		}
		consoleOf(console).Printf("[GROUP]   [%d] auth=%s type=%s ok\n", i+1, txReq.AuthAddress[:8]+"...", keytypefmt.Display(keyType))
		signableCount++
	}

	return signableCount, nil
}

func calculateDummies(console Console, snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, txns []types.Transaction, passthroughIndices, foreignIndices map[int]bool, hasPassthrough, isPreGrouped bool) (dummiesNeeded int, lsigIndices []int, err *ServiceError) {
	lsigSizes := snapshot.LSigSizes

	if hasPassthrough {
		consoleOf(console).Printf("[GROUP] Passthrough mode: trusting pre-formed group structure (no dummy calculation)\n")
		for i, txReq := range requests {
			if passthroughIndices[i] {
				continue
			}
			if size, ok := lsigSizes[txReq.AuthAddress]; ok && size > 0 {
				lsigIndices = append(lsigIndices, i)
			}
		}
		return 0, lsigIndices, nil
	}

	var totalLsigBytes int
	for i, txReq := range requests {
		if foreignIndices[i] {
			var addErr *ServiceError
			totalLsigBytes, addErr = addLsigBytes(totalLsigBytes, txReq.LsigSize, i+1, "lsig_size")
			if addErr != nil {
				return 0, nil, addErr
			}
			continue
		}
		if size, ok := lsigSizes[txReq.AuthAddress]; ok {
			var addErr *ServiceError
			totalLsigBytes, addErr = addLsigBytes(totalLsigBytes, size, i+1, "stored LogicSig size")
			if addErr != nil {
				return 0, nil, addErr
			}
		}
	}

	currentBudget := len(txns) * lsig.TxLsigBudget
	if totalLsigBytes > currentBudget {
		extraBudgetNeeded := totalLsigBytes - currentBudget
		dummiesNeeded = (extraBudgetNeeded + lsig.TxLsigBudget - 1) / lsig.TxLsigBudget
	}

	const maxGroupSize = 16
	finalGroupSize := len(txns) + dummiesNeeded
	if finalGroupSize > maxGroupSize {
		return 0, nil, badRequest(fmt.Sprintf("group would be %d transactions (max %d) - cannot add %d dummies for LSig budget",
			finalGroupSize, maxGroupSize, dummiesNeeded))
	}

	if isPreGrouped && dummiesNeeded > 0 {
		return 0, nil, badRequest(fmt.Sprintf("pre-grouped transactions require %d additional dummies for LogicSig budget but group is immutable - submit ungrouped transactions instead",
			dummiesNeeded))
	}

	consoleOf(console).Printf("[GROUP] LSig budget: %d bytes needed, %d bytes available (%d txns x %d)\n",
		totalLsigBytes, currentBudget, len(txns), lsig.TxLsigBudget)
	if dummiesNeeded > 0 {
		consoleOf(console).Printf("[GROUP] Need %d dummy transaction(s) for additional budget\n", dummiesNeeded)
	}

	for i, txReq := range requests {
		if foreignIndices[i] {
			if txReq.LsigSize > 0 {
				lsigIndices = append(lsigIndices, i)
			}
			continue
		}
		if size, ok := lsigSizes[txReq.AuthAddress]; ok && size > 0 {
			lsigIndices = append(lsigIndices, i)
		}
	}

	return dummiesNeeded, lsigIndices, nil
}

func addLsigBytes(total, size, txnIndex int, label string) (int, *ServiceError) {
	if size < 0 {
		return 0, badRequest(fmt.Sprintf("transaction %d: invalid negative %s %d", txnIndex, label, size))
	}
	const maxInt = int(^uint(0) >> 1)
	if total > maxInt-size {
		return 0, badRequest(fmt.Sprintf("transaction %d: %s total overflows signer budget calculation", txnIndex, label))
	}
	return total + size, nil
}

func buildFinalGroup(deps PlannerDeps, console Console, txns []types.Transaction, dummiesNeeded int, lsigIndices []int, isPreGrouped bool) (allTxns, dummyTxns []types.Transaction, feeInfo DummyFeeInfo, needsRegroup bool, err *ServiceError) {
	minFee := txsigning.DefaultMinFee
	if len(txns) > 0 {
		minFee = deps.MinTxnFee(txns[0].GenesisHash)
	}
	if minFee == 0 {
		minFee = txsigning.DefaultMinFee
	}

	if dummiesNeeded > 0 {
		calc, feeErr := txsigning.CalculateDummyFees(dummiesNeeded, len(lsigIndices), minFee)
		if feeErr != nil {
			return nil, nil, feeInfo, false, internal(fmt.Sprintf("failed to calculate dummy fees: %v", feeErr))
		}
		feeInfo = DummyFeeInfo{
			TotalFees: calc.TotalFees,
			LSigCount: calc.LSigCount,
		}
	}

	if dummiesNeeded > 0 {
		firstTxn := txns[0]
		sp := types.SuggestedParams{
			Fee:             types.MicroAlgos(firstTxn.Fee),
			FirstRoundValid: types.Round(firstTxn.FirstValid),
			LastRoundValid:  types.Round(firstTxn.LastValid),
			GenesisID:       firstTxn.GenesisID,
			GenesisHash:     firstTxn.GenesisHash[:],
			FlatFee:         true,
		}

		var createErr error
		dummyTxns, createErr = lsig.CreateDummyTransactions(dummiesNeeded, sp)
		if createErr != nil {
			return nil, nil, feeInfo, false, internal(fmt.Sprintf("failed to create dummy transactions: %v", createErr))
		}

		applied, applyErr := txsigning.ApplyDummyFees(txns, lsigIndices, dummiesNeeded, minFee)
		if applyErr != nil {
			return nil, nil, feeInfo, false, internal(fmt.Sprintf("failed to adjust fees: %v", applyErr))
		}
		feeInfo = DummyFeeInfo{
			TotalFees: applied.TotalFees,
			LSigCount: applied.LSigCount,
		}

		if len(lsigIndices) > 0 {
			feePerLSig := uint64(0)
			if applied.LSigCount > 0 {
				feePerLSig = applied.FeePerLSig
			}
			consoleOf(console).Printf("[GROUP] Distributed %d microAlgos dummy fees across %d LSig txn(s) (~%d each)\n",
				feeInfo.TotalFees, feeInfo.LSigCount, feePerLSig)
		} else {
			consoleOf(console).Printf("[GROUP] Added %d dummy transaction(s), fee on first txn\n", dummiesNeeded)
		}
	}

	allTxns = make([]types.Transaction, 0, len(txns)+len(dummyTxns))
	allTxns = append(allTxns, txns...)
	allTxns = append(allTxns, dummyTxns...)

	needsRegroup = dummiesNeeded > 0 || !isPreGrouped
	if needsRegroup && len(allTxns) > 1 {
		for i := range allTxns {
			allTxns[i].Group = types.Digest{}
		}

		gid, groupErr := crypto.ComputeGroupID(allTxns)
		if groupErr != nil {
			return nil, nil, feeInfo, false, internal(fmt.Sprintf("failed to compute group ID: %v", groupErr))
		}

		for i := range allTxns {
			allTxns[i].Group = gid
		}
		consoleOf(console).Printf("[GROUP] Computed new group ID: %x\n", gid[:8])
	}

	return allTxns, dummyTxns, feeInfo, needsRegroup, nil
}
