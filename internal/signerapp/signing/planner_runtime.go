// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"math"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	txsigning "github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// PlannerIdentitySnapshot captures the identity-scoped signer metadata needed for planning.
type PlannerIdentitySnapshot struct {
	Revision    uint64
	KeyFiles    map[string]string
	KeyTypes    map[string]string
	LSigSizes   map[string]int
	KeyMetadata map[string]PlannerKeyMetadata
}

// PlannerKeyMetadata is public scan-time metadata used for dependency
// preflight. It never contains decrypted private material.
type PlannerKeyMetadata struct {
	Category             string
	PublicKeyHex         string
	Parameters           map[string]string
	BoundedAuthorization *boundedmeta.Metadata
	LogicSigResources    *lsigresource.Profile
}

// PlannerDeps supplies process-specific data needed by the package-owned planner.
type PlannerDeps interface {
	Snapshot(identityID string) PlannerIdentitySnapshot
	NetworkParams(genesisHash types.Digest) PlannerNetworkParams
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
	var cachedNetworkHash types.Digest
	var cachedNetworkParams PlannerNetworkParams
	var networkParamsCached bool
	networkParams := func(genesisHash types.Digest) PlannerNetworkParams {
		if !networkParamsCached || cachedNetworkHash != genesisHash {
			cachedNetworkHash = genesisHash
			cachedNetworkParams = deps.NetworkParams(genesisHash)
			networkParamsCached = true
		}
		return cachedNetworkParams
	}
	return &Planner{
		AuditLog:               opts.AuditLog,
		Console:                opts.Console,
		GenerateTxnDescription: opts.GenerateTxnDescription,
		GenesisHashResolver:    opts.GenesisHashResolver,
		VerifySignableKeys: func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, passthroughIndices, foreignIndices map[int]bool) (int, *ServiceError) {
			return verifySignableKeys(opts.Console, snapshot, identityID, requests, passthroughIndices, foreignIndices)
		},
		CalculateDummies: func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, txns []types.Transaction, boundedItems []*boundedPlanItem, passthroughIndices, foreignIndices map[int]bool, passthroughSignedTxns map[int][]byte, network PlannerNetworkParams, hasPassthrough, isPreGrouped bool) (lsigresource.Plan, []int, *ServiceError) {
			return calculateLogicSigResources(opts.Console, snapshot, identityID, requests, txns, boundedItems, passthroughIndices, foreignIndices, passthroughSignedTxns, network, hasPassthrough, isPreGrouped)
		},
		BuildFinalGroup: func(txns []types.Transaction, dummiesNeeded int, lsigIndices []int, isPreGrouped bool) ([]types.Transaction, []types.Transaction, DummyFeeInfo, bool, *ServiceError) {
			minFee := uint64(0)
			if len(txns) > 0 {
				minFee = networkParams(txns[0].GenesisHash).MinTxnFee
			}
			return buildFinalGroup(minFee, opts.Console, txns, dummiesNeeded, lsigIndices, isPreGrouped)
		},
		NetworkParams: networkParams,
		Snapshot:      deps.Snapshot,
	}
}

func calculateLogicSigResources(console Console, snapshot PlannerIdentitySnapshot, _ string, requests []signerapi.SignRequest, txns []types.Transaction, boundedItems []*boundedPlanItem, passthroughIndices, foreignIndices map[int]bool, passthroughSignedTxns map[int][]byte, network PlannerNetworkParams, hasPassthrough, isPreGrouped bool) (lsigresource.Plan, []int, *ServiceError) {
	var profile lsigresource.ConsensusProfile
	profileResolved := false
	resolveProfile := func() *ServiceError {
		if profileResolved {
			return nil
		}
		resolved, profileErr := lsigresource.ResolveConsensus(network.ConsensusVersion)
		if profileErr != nil {
			return badRequest(fmt.Sprintf("cannot plan LogicSig resources for consensus %q: %v", network.ConsensusVersion, profileErr))
		}
		profile = resolved
		profileResolved = true
		return nil
	}

	usages := make([]lsigresource.Usage, 0, len(requests))
	lsigIndices := make([]int, 0, len(requests))
	for i, request := range requests {
		if passthroughIndices[i] {
			usage, present, usageErr := passthroughLogicSigUsage(passthroughSignedTxns[i], i+1)
			if usageErr != nil {
				return lsigresource.Plan{}, nil, usageErr
			}
			if present {
				usages = append(usages, usage)
			}
			continue
		}

		if foreignIndices[i] {
			if request.LsigSize != 0 {
				if profileErr := resolveProfile(); profileErr != nil {
					return lsigresource.Plan{}, nil, profileErr
				}
			}
			usage, present, usageErr := foreignLogicSigUsage(request, profile, i+1)
			if usageErr != nil {
				return lsigresource.Plan{}, nil, usageErr
			}
			if present {
				usages = append(usages, usage)
			}
			continue
		}

		metadata := snapshot.KeyMetadata[request.AuthAddress]
		if metadata.LogicSigResources == nil {
			if size, ok := plannedLogicSigSize(snapshot.LSigSizes, request.AuthAddress, boundedItems, i); ok && size > 0 {
				if profileErr := resolveProfile(); profileErr != nil {
					return lsigresource.Plan{}, nil, profileErr
				}
				if profile.SizingMode == lsigresource.SizingModePricedProgram {
					return lsigresource.Plan{}, nil, badRequest(fmt.Sprintf("transaction %d: LogicSig key %s has legacy combined-size metadata; regenerate this unpublished key before signing on consensus %s", i+1, request.AuthAddress, network.ConsensusVersion))
				}
				usages = append(usages, lsigresource.Usage{ProgramBytes: uint64(size), MaxOpcodeCost: 1})
				lsigIndices = append(lsigIndices, i)
			}
			continue
		}

		path := lsigresource.PathDefault
		if i < len(boundedItems) && boundedItems[i] != nil {
			var pathErr error
			path, pathErr = logicSigAuthorizationPath(boundedItems[i].Path)
			if pathErr != nil {
				return lsigresource.Plan{}, nil, internal(fmt.Sprintf("transaction %d: %v", i+1, pathErr))
			}
		}
		usage, usageErr := metadata.LogicSigResources.UsageForPath(path)
		if usageErr != nil {
			return lsigresource.Plan{}, nil, internal(fmt.Sprintf("transaction %d: invalid stored LogicSig resource profile: %v", i+1, usageErr))
		}
		usages = append(usages, usage)
		lsigIndices = append(lsigIndices, i)
	}
	if len(usages) == 0 {
		return lsigresource.Plan{
			TransactionCount: uint64(len(txns)),
			GroupSize:        uint64(len(txns)),
		}, nil, nil
	}
	if profileErr := resolveProfile(); profileErr != nil {
		return lsigresource.Plan{}, nil, profileErr
	}

	dummy := lsigresource.Usage{
		ProgramBytes:  uint64(len(txsigning.EmbeddedDummyTealTok)),
		MaxOpcodeCost: 1,
	}
	resourcePlan, solveErr := lsigresource.Solve(profile, lsigresource.PlanInput{
		TransactionCount: uint64(len(txns)),
		LogicSigs:        usages,
		Dummy:            dummy,
	})
	if solveErr != nil {
		return lsigresource.Plan{}, nil, badRequest(fmt.Sprintf("LogicSig resources do not fit consensus %s: %v", network.ConsensusVersion, solveErr))
	}
	if resourcePlan.DummyCount > 0 && (isPreGrouped || hasPassthrough) {
		return lsigresource.Plan{}, nil, badRequest(fmt.Sprintf("immutable group requires %d additional dummy transaction(s) for LogicSig arguments/opcode budget; submit an ungrouped unsigned group instead", resourcePlan.DummyCount))
	}

	if resourcePlan.DummyCount > 0 && len(lsigIndices) == 0 {
		for i := range requests {
			if !foreignIndices[i] && !passthroughIndices[i] {
				lsigIndices = append(lsigIndices, i)
				break
			}
		}
	}
	consoleOf(console).Printf("[GROUP] LogicSig resources: program=%d args=%d opcode<=%d, group=%d (%d dummy)\n",
		resourcePlan.TotalProgramBytes,
		resourcePlan.TotalArgumentBytes,
		resourcePlan.TotalMaxOpcodeCost,
		resourcePlan.GroupSize,
		resourcePlan.DummyCount,
	)
	if resourcePlan.ProgramFeeFactorUsage > 0 {
		consoleOf(console).Printf("[GROUP] LogicSig program pricing: %d charged byte(s), fee-factor contribution %d\n",
			resourcePlan.ChargedProgramBytes,
			resourcePlan.ProgramFeeFactorUsage,
		)
	}
	return resourcePlan, lsigIndices, nil
}

func logicSigAuthorizationPath(path boundedPath) (lsigresource.AuthorizationPath, error) {
	switch path {
	case boundedPathPureSpend:
		return lsigresource.PathSpend, nil
	case boundedPathSpendingKeyRekey:
		return lsigresource.PathSpendingRekey, nil
	case boundedPathAdminKeyRekey:
		return lsigresource.PathAdminRekey, nil
	default:
		return 0, fmt.Errorf("unknown bounded authorization path %q", path)
	}
}

func foreignLogicSigUsage(request signerapi.SignRequest, profile lsigresource.ConsensusProfile, txnIndex int) (lsigresource.Usage, bool, *ServiceError) {
	if request.LsigResources != nil {
		return lsigresource.Usage{
			ProgramBytes:  request.LsigResources.ProgramBytes,
			ArgumentBytes: request.LsigResources.ArgumentBytes,
			MaxOpcodeCost: request.LsigResources.MaxOpcodeCost,
		}, true, nil
	}
	if request.LsigSize == 0 {
		return lsigresource.Usage{}, false, nil
	}
	if request.LsigSize < 0 {
		return lsigresource.Usage{}, false, badRequest(fmt.Sprintf("transaction %d: invalid negative lsig_size %d", txnIndex, request.LsigSize))
	}
	if profile.SizingMode == lsigresource.SizingModePricedProgram {
		return lsigresource.Usage{}, false, badRequest(fmt.Sprintf("transaction %d: legacy lsig_size cannot describe v42 LogicSig resources; provide lsig_resources", txnIndex))
	}
	return lsigresource.Usage{ProgramBytes: uint64(request.LsigSize), MaxOpcodeCost: 1}, true, nil
}

func passthroughLogicSigUsage(encoded []byte, txnIndex int) (lsigresource.Usage, bool, *ServiceError) {
	var signed types.SignedTxn
	if err := msgpack.Decode(encoded, &signed); err != nil {
		return lsigresource.Usage{}, false, badRequest(fmt.Sprintf("transaction %d (passthrough): invalid signed transaction msgpack", txnIndex))
	}
	if len(signed.Lsig.Logic) == 0 {
		if !signed.Lsig.Blank() || !signed.Lsig.PQsig.Blank() {
			return lsigresource.Usage{}, false, badRequest(fmt.Sprintf("transaction %d (passthrough): LogicSig authorization fields require a non-empty program", txnIndex))
		}
		return lsigresource.Usage{}, false, nil
	}
	argumentBytes := uint64(0)
	for _, argument := range signed.Lsig.Args {
		if uint64(len(argument)) > math.MaxUint64-argumentBytes {
			return lsigresource.Usage{}, false, badRequest(fmt.Sprintf("transaction %d (passthrough): LogicSig argument size overflows resource calculation", txnIndex))
		}
		argumentBytes += uint64(len(argument))
	}
	// The signer cannot prove the dynamic opcode ceiling of immutable foreign
	// bytecode. The network remains authoritative for execution; the planner
	// accounts the observed bytes and uses the minimum non-zero solver value.
	return lsigresource.Usage{
		ProgramBytes:  uint64(len(signed.Lsig.Logic)),
		ArgumentBytes: argumentBytes,
		MaxOpcodeCost: 1,
	}, true, nil
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
		if msg, ok := sentrySignRejectMessage(keyType); ok {
			return 0, badRequest(fmt.Sprintf("transaction %d: %s", i+1, msg))
		}
		consoleOf(console).Printf("[GROUP]   [%d] auth=%s type=%s ok\n", i+1, txReq.AuthAddress[:8]+"...", keytypefmt.Display(keyType))
		signableCount++
	}

	return signableCount, nil
}

func calculateDummies(console Console, snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, txns []types.Transaction, boundedItems []*boundedPlanItem, passthroughIndices, foreignIndices map[int]bool, hasPassthrough, isPreGrouped bool) (dummiesNeeded int, lsigIndices []int, err *ServiceError) {
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
		if size, ok := plannedLogicSigSize(lsigSizes, txReq.AuthAddress, boundedItems, i); ok {
			var addErr *ServiceError
			totalLsigBytes, addErr = addLsigBytes(totalLsigBytes, size, i+1, "stored LogicSig size")
			if addErr != nil {
				return 0, nil, addErr
			}
		}
	}

	currentBudget := len(txns) * txsigning.TxLsigBudget
	if totalLsigBytes > currentBudget {
		extraBudgetNeeded := totalLsigBytes - currentBudget
		dummiesNeeded = (extraBudgetNeeded + txsigning.TxLsigBudget - 1) / txsigning.TxLsigBudget
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
		totalLsigBytes, currentBudget, len(txns), txsigning.TxLsigBudget)
	if dummiesNeeded > 0 {
		consoleOf(console).Printf("[GROUP] Need %d dummy transaction(s) for additional budget\n", dummiesNeeded)
	}

	// Pool dummy fees only across positions this signer actually signs. The
	// signer must not rewrite the fee on a foreign transaction it neither signs
	// nor verifies: doing so silently mutates another party's bytes and relies
	// on an unenforced cross-party invariant (that a coordinator forwards the
	// fee-adjusted /plan bytes, not the originals). Foreign lsig_size still
	// counts toward dummiesNeeded above, so budget sizing is unchanged; foreign
	// positions simply do not carry a fee share.
	for i, txReq := range requests {
		if foreignIndices[i] {
			continue
		}
		if size, ok := plannedLogicSigSize(lsigSizes, txReq.AuthAddress, boundedItems, i); ok && size > 0 {
			lsigIndices = append(lsigIndices, i)
		}
	}

	// If every LogicSig participant is foreign, there is no local LogicSig
	// position to carry the pooled dummy fee. Fall back to the first
	// signer-signed (sign mode) position so the fee lands on a funded
	// transaction the signer controls — never on a foreign or passthrough slot
	// (which is what ApplyDummyFees' own txns[0] fallback would otherwise do).
	// Request validation guarantees at least one sign-mode position whenever
	// foreign slots are present, so this loop always finds a target.
	if dummiesNeeded > 0 && len(lsigIndices) == 0 {
		for i := range requests {
			if foreignIndices[i] || passthroughIndices[i] {
				continue
			}
			lsigIndices = append(lsigIndices, i)
			break
		}
	}

	return dummiesNeeded, lsigIndices, nil
}

func plannedLogicSigSize(stored map[string]int, authAddress string, boundedItems []*boundedPlanItem, index int) (int, bool) {
	if index < len(boundedItems) && boundedItems[index] != nil {
		item := boundedItems[index]
		size := item.Metadata.LogicSigSizeForPath(boundedMetadataPath(item.Path))
		return size, size > 0
	}
	size, ok := stored[authAddress]
	return size, ok
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

func buildFinalGroup(minFee uint64, console Console, txns []types.Transaction, dummiesNeeded int, lsigIndices []int, isPreGrouped bool) (allTxns, dummyTxns []types.Transaction, feeInfo DummyFeeInfo, needsRegroup bool, err *ServiceError) {
	if minFee == 0 {
		minFee = txsigning.DefaultMinFee
	}
	// Bound the per-transaction min fee against a sane ceiling. A real network's
	// min fee is ~1000 microAlgos; an absurd value (e.g. from a hostile or
	// misconfigured algod) would inflate the pooled dummy fee and could overflow
	// the int-typed mutation report. 1 ALGO is already three orders of magnitude
	// above any real min fee.
	const maxSaneMinFee = uint64(1_000_000)
	if minFee > maxSaneMinFee {
		return nil, nil, feeInfo, false, badRequest(fmt.Sprintf("network minimum fee %d microAlgos is implausibly high; refusing to build dummy-fee group", minFee))
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
		dummyTxns, createErr = txsigning.CreateDummyTransactions(dummiesNeeded, sp)
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
