// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"math"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/keytypefmt"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"
	txsigning "github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// PlannerIdentitySnapshot captures the identity-scoped signer metadata needed for planning.
type PlannerIdentitySnapshot struct {
	Revision    uint64
	KeyFiles    map[string]string
	KeyTypes    map[string]string
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
			return buildFinalGroupWithoutFees(opts.Console, txns, dummiesNeeded, isPreGrouped)
		},
		NetworkParams: networkParams,
		Snapshot:      deps.Snapshot,
	}
}

func buildFinalGroupWithoutFees(console Console, txns []types.Transaction, dummiesNeeded int, isPreGrouped bool) (allTxns, dummyTxns []types.Transaction, feeInfo DummyFeeInfo, needsRegroup bool, err *ServiceError) {
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
		consoleOf(console).Printf("[GROUP] Added %d resource dummy transaction(s); final fee planning follows\n", dummiesNeeded)
	}
	allTxns = make([]types.Transaction, 0, len(txns)+len(dummyTxns))
	allTxns = append(allTxns, txns...)
	allTxns = append(allTxns, dummyTxns...)
	return allTxns, dummyTxns, feeInfo, dummiesNeeded > 0 || !isPreGrouped, nil
}

func calculateLogicSigResources(console Console, snapshot PlannerIdentitySnapshot, _ string, requests []signerapi.SignRequest, txns []types.Transaction, boundedItems []*boundedPlanItem, passthroughIndices, foreignIndices map[int]bool, passthroughSignedTxns map[int][]byte, network PlannerNetworkParams, hasPassthrough, isPreGrouped bool) (lsigresource.Plan, []int, *ServiceError) {
	var profile lsigresource.ConsensusProfile
	profileResolved := false
	resolveProfile := func() *ServiceError {
		if profileResolved {
			return nil
		}
		if network.ConsensusVersion == "" {
			reason := network.ConsensusUnavailable
			if reason == "" {
				reason = "the signer could not determine the active consensus version"
			}
			return badRequest(fmt.Sprintf(
				"cannot plan LogicSig resources: %s; LogicSig program sizing and fees are consensus-defined, so this signer needs a reachable algod for the transaction's network",
				reason,
			))
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
			usage, present, usageErr := foreignLogicSigUsage(request)
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
			if metadata.Category == lsigprovider.CategoryDSALsig || metadata.Category == lsigprovider.CategoryGenericLsig {
				return lsigresource.Plan{}, nil, badRequest(fmt.Sprintf("transaction %d: LogicSig key %s has no structured resource profile; regenerate this unpublished key", i+1, request.AuthAddress))
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

func foreignLogicSigUsage(request signerapi.SignRequest) (lsigresource.Usage, bool, *ServiceError) {
	if request.LsigResources != nil {
		return lsigresource.Usage{
			ProgramBytes:  request.LsigResources.ProgramBytes,
			ArgumentBytes: request.LsigResources.ArgumentBytes,
			MaxOpcodeCost: request.LsigResources.MaxOpcodeCost,
		}, true, nil
	}
	return lsigresource.Usage{}, false, nil
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
			if txReq.LsigResources != nil {
				consoleOf(console).Printf("[GROUP]   [%d] foreign (LogicSig resources declared) ok\n", i+1)
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
		// Planning is a prerequisite of guarded signing: /plan freezes the
		// group before /sign/component and /sign/assemble run. Guarded account
		// keys are therefore valid planning authorities even though the ordinary
		// /sign executor rejects them. Witness keys are not transaction
		// authorities at all and remain invalid here.
		if witness.IsKeyType(keyType) {
			return 0, badRequest(fmt.Sprintf("transaction %d: %s", i+1, sentryComponentSignRejectMessage))
		}
		consoleOf(console).Printf("[GROUP]   [%d] auth=%s type=%s ok\n", i+1, txReq.AuthAddress[:8]+"...", keytypefmt.Display(keyType))
		signableCount++
	}

	return signableCount, nil
}
