// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"encoding/hex"
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

type AuditLogger interface {
	LogSignRequest(identityID, authAddress, txnSender, txnType, details string)
}

type VerifySignableKeysFunc func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, passthroughIndices, foreignIndices map[int]bool) (signableCount int, err *ServiceError)
type CalculateDummiesFunc func(snapshot PlannerIdentitySnapshot, identityID string, requests []signerapi.SignRequest, txns []types.Transaction, boundedItems []*boundedPlanItem, passthroughIndices, foreignIndices map[int]bool, passthroughSignedTxns map[int][]byte, network PlannerNetworkParams, hasPassthrough, isPreGrouped bool) (resourcePlan lsigresource.Plan, lsigIndices []int, err *ServiceError)
type BuildFinalGroupFunc func(txns []types.Transaction, dummiesNeeded int, lsigIndices []int, isPreGrouped bool) (allTxns, dummyTxns []types.Transaction, feeInfo DummyFeeInfo, needsRegroup bool, err *ServiceError)
type GenerateTxnDescriptionFunc func(txnBytesHex string) string

type DummyFeeInfo struct {
	TotalFees               uint64
	LSigCount               int
	FeeIndices              []int
	DummyFeeContribution    uint64
	ProgramFeeContribution  uint64
	NativePQFeeContribution uint64
}

type PlannerNetworkParams struct {
	MinTxnFee        uint64
	ConsensusVersion string
}

// PlanResult contains the output of group-building shared by /sign and /plan.
type PlanResult struct {
	AllTxns               []types.Transaction
	DummyTxns             []types.Transaction
	PassthroughIndices    map[int]bool
	PassthroughSignedTxns map[int][]byte
	ForeignIndices        map[int]bool
	HasForeign            bool
	LsigIndices           []int
	DummiesNeeded         int
	LogicSigResourcePlan  lsigresource.Plan
	FeeInfo               DummyFeeInfo
	NeedsRegroup          bool
	IsPreGrouped          bool
	HasPassthrough        bool
	// AuthKeyTypes[i] is the signing key type for req.Requests[i]. Empty when
	// the slot is passthrough, foreign, or the auth address is unknown.
	AuthKeyTypes []string
	// KnownAddresses is the signer-local address set materialized from the same
	// key snapshot used for planning.
	KnownAddresses map[string]bool
	// BoundedItems[i] records the signer-classified path for a bounded key after
	// all group and fee mutations. Other entries are nil.
	BoundedItems []*boundedPlanItem
}

// SnapshotFunc retrieves the identity snapshot needed for planning.
type SnapshotFunc func(identityID string) PlannerIdentitySnapshot

type Planner struct {
	AuditLog               AuditLogger
	Console                Console
	GenerateTxnDescription GenerateTxnDescriptionFunc
	VerifySignableKeys     VerifySignableKeysFunc
	CalculateDummies       CalculateDummiesFunc
	BuildFinalGroup        BuildFinalGroupFunc
	GenesisHashResolver    apconfig.GenesisHashNetworkResolver
	NetworkParams          func(genesisHash types.Digest) PlannerNetworkParams
	Snapshot               SnapshotFunc
}

func (p *Planner) PlanGroup(identityID string, req signerapi.GroupSignRequest) (*PlanResult, *ServiceError) {
	console := consoleOf(p.Console)
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}

	passthroughIndices, foreignIndices, err := categorizeRequests(req.Requests)
	if err != nil {
		return nil, err
	}
	hasPassthrough := len(passthroughIndices) > 0
	hasForeign := len(foreignIndices) > 0

	console.Printf("[GROUP] Received %d transaction(s)", len(req.Requests))
	if hasPassthrough || hasForeign {
		signCount := len(req.Requests) - len(passthroughIndices) - len(foreignIndices)
		if hasPassthrough {
			console.Printf(" (%d passthrough, %d to sign)", len(passthroughIndices), signCount)
		}
		if hasForeign {
			console.Printf(" (%d foreign, %d to sign)", len(foreignIndices), signCount)
		}
	}
	console.Println()

	txns, passthroughSignedTxns, err := decodeTransactions(req.Requests, passthroughIndices, console)
	if err != nil {
		return nil, err
	}

	if p.AuditLog != nil && p.GenerateTxnDescription != nil {
		for i, txReq := range req.Requests {
			if passthroughIndices[i] {
				p.AuditLog.LogSignRequest(identityID, "", txns[i].Sender.String(), "passthrough", "pre-signed transaction")
			} else if foreignIndices[i] {
				p.AuditLog.LogSignRequest(identityID, "", txns[i].Sender.String(), "foreign", p.GenerateTxnDescription(txReq.TxnBytesHex))
			} else {
				p.AuditLog.LogSignRequest(identityID, txReq.AuthAddress, txns[i].Sender.String(), "", p.GenerateTxnDescription(txReq.TxnBytesHex))
			}
		}
	}

	isPreGrouped, err := validateGroupConsistency(txns, hasPassthrough, console)
	if err != nil {
		return nil, err
	}

	if err = validateKnownNetwork(txns, p.GenesisHashResolver); err != nil {
		return nil, err
	}

	if len(txns) > 1 {
		if err = validateNetworkParams(txns, console); err != nil {
			return nil, err
		}
	}

	var snapshot PlannerIdentitySnapshot
	if p.Snapshot != nil {
		snapshot = p.Snapshot(identityID)
	}

	signableCount, err := p.VerifySignableKeys(snapshot, identityID, req.Requests, passthroughIndices, foreignIndices)
	if err != nil {
		return nil, err
	}

	if signableCount > 0 {
		console.Printf("[GROUP] %d key(s) available for signing\n", signableCount)
	}
	if hasPassthrough {
		console.Printf("[GROUP] %d passthrough transaction(s) will be included as-is\n", len(passthroughIndices))
	}
	if hasForeign {
		console.Printf("[GROUP] %d foreign transaction(s) will not be signed\n", len(foreignIndices))
	}

	// Classify bounded requests before budgeting: the admin-key rekey slot must
	// reserve the contract-admin signature bytes that ordinary spends never
	// carry. This pass sees pre-pooling fees, so it is sizing input only — the
	// authoritative classification runs on the finalized group below.
	sizingBoundedItems, err := resolveBoundedPlanItems(snapshot, req.Requests, txns, passthroughIndices, foreignIndices)
	if err != nil {
		return nil, err
	}

	if p.NetworkParams == nil || len(txns) == 0 {
		return nil, internal("LogicSig planning requires network consensus parameters")
	}
	networkParams := p.NetworkParams(txns[0].GenesisHash)
	resourcePlan, lsigIndices, err := p.CalculateDummies(snapshot, identityID, req.Requests, txns, sizingBoundedItems, passthroughIndices, foreignIndices, passthroughSignedTxns, networkParams, hasPassthrough, isPreGrouped)
	if err != nil {
		return nil, err
	}
	dummiesNeeded := int(resourcePlan.DummyCount)

	allTxns, dummyTxns, feeInfo, needsRegroup, err := p.BuildFinalGroup(txns, dummiesNeeded, lsigIndices, isPreGrouped)
	if err != nil {
		return nil, err
	}

	budgets, budgetErr := authorizationBudgets(req.Requests, snapshot, sizingBoundedItems, passthroughIndices, foreignIndices, passthroughSignedTxns)
	if budgetErr != nil {
		return nil, budgetErr
	}
	if networkParams.ConsensusVersion != "" || dummiesNeeded > 0 || resourcePlan.ProgramFeeFactorUsage > 0 || hasNativePQAuthorization(budgets) {
		plannedFees, feeErr := applyGroupFees(allTxns, budgets, networkParams, resourcePlan, dummiesNeeded, lsigIndices, isPreGrouped || hasPassthrough)
		if feeErr != nil {
			return nil, feeErr
		}
		feeInfo = plannedFees
		needsRegroup = needsRegroup || feeInfo.TotalFees > 0
	}
	if needsRegroup && len(allTxns) > 1 {
		for i := range allTxns {
			allTxns[i].Group = types.Digest{}
		}
		gid, groupErr := algocrypto.ComputeGroupID(allTxns)
		if groupErr != nil {
			return nil, internal(fmt.Sprintf("failed to compute final group ID: %v", groupErr))
		}
		for i := range allTxns {
			allTxns[i].Group = gid
		}
	}

	// Re-classify against the finalized transactions: pooled dummy fees mutate
	// the original LogicSig slots, and the bounded fee ceiling must hold for the
	// fees actually signed. Fee pooling cannot change a transaction's shape, so
	// the sizing pass and this pass always agree on the path. Dummies are
	// appended after the originals, so request indices are unchanged.
	boundedItems, err := resolveBoundedPlanItems(snapshot, req.Requests, allTxns, passthroughIndices, foreignIndices)
	if err != nil {
		return nil, err
	}

	authKeyTypes := make([]string, len(req.Requests))
	for i, txReq := range req.Requests {
		if passthroughIndices[i] || foreignIndices[i] {
			continue
		}
		authKeyTypes[i] = snapshot.KeyTypes[txReq.AuthAddress]
	}
	knownAddresses := knownAddressesFromSnapshot(snapshot)

	return &PlanResult{
		AllTxns:               allTxns,
		DummyTxns:             dummyTxns,
		PassthroughIndices:    passthroughIndices,
		PassthroughSignedTxns: passthroughSignedTxns,
		ForeignIndices:        foreignIndices,
		HasForeign:            hasForeign,
		LsigIndices:           lsigIndices,
		DummiesNeeded:         dummiesNeeded,
		LogicSigResourcePlan:  resourcePlan,
		FeeInfo:               feeInfo,
		NeedsRegroup:          needsRegroup,
		IsPreGrouped:          isPreGrouped,
		HasPassthrough:        hasPassthrough,
		AuthKeyTypes:          authKeyTypes,
		KnownAddresses:        knownAddresses,
		BoundedItems:          boundedItems,
	}, nil
}

func knownAddressesFromSnapshot(snapshot PlannerIdentitySnapshot) map[string]bool {
	if len(snapshot.KeyFiles) == 0 {
		return nil
	}
	known := make(map[string]bool, len(snapshot.KeyFiles))
	for address := range snapshot.KeyFiles {
		known[address] = true
	}
	return known
}

func BuildMutationReport(plan *PlanResult, originalCount int) *signerapi.MutationReport {
	groupIDChanged := plan.NeedsRegroup && len(plan.AllTxns) > 1
	if plan.DummiesNeeded == 0 && plan.FeeInfo.TotalFees == 0 && !groupIDChanged && !plan.HasPassthrough && !plan.HasForeign {
		return nil
	}

	mutations := &signerapi.MutationReport{
		OriginalCount: originalCount,
		FinalCount:    len(plan.AllTxns),
	}

	if plan.DummiesNeeded > 0 {
		mutations.DummiesAdded = plan.DummiesNeeded
		mutations.Reason = "lsig_budget"
	}
	mutations.TotalFeesDelta = int(plan.FeeInfo.TotalFees)
	mutations.FeesModified = appendUniqueIndices(mutations.FeesModified, plan.FeeInfo.FeeIndices...)
	if plan.FeeInfo.ProgramFeeContribution > 0 {
		if mutations.Reason == "" {
			mutations.Reason = "lsig_program_fee"
		} else {
			mutations.Reason += "+lsig_program_fee"
		}
	}
	if plan.FeeInfo.NativePQFeeContribution > 0 {
		if mutations.Reason == "" {
			mutations.Reason = "native_pq_fee"
		} else {
			mutations.Reason += "+native_pq_fee"
		}
	}

	if groupIDChanged {
		mutations.GroupIDChanged = true
	}

	if plan.HasPassthrough {
		mutations.PassthroughCount = len(plan.PassthroughIndices)
		if mutations.Reason == "" {
			mutations.Reason = "passthrough"
		}
	}

	if plan.HasForeign {
		mutations.ForeignCount = len(plan.ForeignIndices)
		if mutations.Reason == "" {
			mutations.Reason = "foreign"
		}
	}

	return mutations
}

func appendUniqueIndices(dst []int, indices ...int) []int {
	for _, index := range indices {
		found := false
		for _, existing := range dst {
			if existing == index {
				found = true
				break
			}
		}
		if !found {
			dst = append(dst, index)
		}
	}
	return dst
}

func categorizeRequests(requests []signerapi.SignRequest) (passthroughIndices, foreignIndices map[int]bool, err *ServiceError) {
	passthroughIndices = make(map[int]bool)
	foreignIndices = make(map[int]bool)

	for i, txReq := range requests {
		mode, err := txReq.Mode()
		if err != nil {
			return nil, nil, badRequest(fmt.Sprintf("transaction %d: %s", i+1, err.Error()))
		}

		switch mode {
		case signerapi.RequestModePassthrough:
			passthroughIndices[i] = true
		case signerapi.RequestModeForeign:
			foreignIndices[i] = true
		}
	}

	return passthroughIndices, foreignIndices, nil
}

func decodeTransactions(requests []signerapi.SignRequest, passthroughIndices map[int]bool, console Console) (txns []types.Transaction, passthroughSignedTxns map[int][]byte, err *ServiceError) {
	txns = make([]types.Transaction, len(requests))
	passthroughSignedTxns = make(map[int][]byte)

	for i, txReq := range requests {
		if passthroughIndices[i] {
			stxnBytes, err := hex.DecodeString(txReq.SignedTxnHex)
			if err != nil {
				return nil, nil, badRequest(fmt.Sprintf("transaction %d (passthrough): invalid hex encoding", i+1))
			}

			var stxn types.SignedTxn
			if err := msgpack.Decode(stxnBytes, &stxn); err != nil {
				return nil, nil, badRequest(fmt.Sprintf("transaction %d (passthrough): invalid signed transaction msgpack", i+1))
			}

			txns[i] = stxn.Txn
			passthroughSignedTxns[i] = stxnBytes
			console.Printf("  [%d] sender=%s group=%x (passthrough)\n", i+1, stxn.Txn.Sender.String(), stxn.Txn.Group[:8])
			continue
		}

		txnBytesWithPrefix, err := hex.DecodeString(txReq.TxnBytesHex)
		if err != nil {
			return nil, nil, badRequest(fmt.Sprintf("transaction %d: invalid hex encoding", i+1))
		}

		txnBytes := txnBytesWithPrefix
		if len(txnBytes) > 2 && txnBytes[0] == 'T' && txnBytes[1] == 'X' {
			txnBytes = txnBytes[2:]
		}

		var txn types.Transaction
		if err := msgpack.Decode(txnBytes, &txn); err != nil {
			return nil, nil, badRequest(fmt.Sprintf("transaction %d: invalid msgpack", i+1))
		}

		txns[i] = txn
		console.Printf("  [%d] sender=%s group=%x\n", i+1, txn.Sender.String(), txn.Group[:8])
	}

	return txns, passthroughSignedTxns, nil
}

func validateGroupConsistency(txns []types.Transaction, hasPassthrough bool, console Console) (isPreGrouped bool, err *ServiceError) {
	var emptyDigest types.Digest
	firstGroup := txns[0].Group
	isPreGrouped = firstGroup != emptyDigest

	for i, txn := range txns {
		if isPreGrouped {
			if txn.Group != firstGroup {
				return false, badRequest(fmt.Sprintf("transaction %d has different group ID - request must contain single group", i+1))
			}
		} else if txn.Group != emptyDigest {
			return false, badRequest(fmt.Sprintf("transaction %d has group ID but transaction 1 does not - inconsistent grouping", i+1))
		}
	}

	// For pre-grouped input the signer signs the bytes as-is and the approval
	// display asserts the claimed group ID. Recompute it from the transactions
	// and reject a mismatch, so the operator is never shown (and the signer
	// never signs over) a group ID that does not bind these exact members.
	if isPreGrouped {
		if err := verifyClaimedGroupID(txns, firstGroup); err != nil {
			return false, err
		}
	}

	if hasPassthrough && !isPreGrouped {
		return false, badRequest("passthrough transactions require pre-set group ID - server cannot add dummies or modify group without invalidating existing signatures")
	}

	out := consoleOf(console)
	if isPreGrouped {
		out.Printf("[GROUP] Pre-grouped transactions (group ID: %x...)\n", firstGroup[:8])
	} else if len(txns) > 1 {
		out.Printf("[GROUP] Ungrouped transactions - will compute group ID\n")
	} else {
		out.Printf("[GROUP] Single ungrouped transaction\n")
	}

	return isPreGrouped, nil
}

// verifyClaimedGroupID recomputes the group ID over the pre-grouped
// transactions (with their Group field cleared) and checks it equals the
// claimed digest every member carries.
func verifyClaimedGroupID(txns []types.Transaction, claimed types.Digest) *ServiceError {
	cleared := make([]types.Transaction, len(txns))
	copy(cleared, txns)
	for i := range cleared {
		cleared[i].Group = types.Digest{}
	}
	computed, err := algocrypto.ComputeGroupID(cleared)
	if err != nil {
		return internal(fmt.Sprintf("failed to recompute group ID: %v", err))
	}
	if computed != claimed {
		return badRequest("claimed group ID does not match the transactions in the group")
	}
	return nil
}

func validateKnownNetwork(txns []types.Transaction, resolver apconfig.GenesisHashNetworkResolver) *ServiceError {
	for i, txn := range txns {
		if _, ok := resolver.NetworkForGenesisHashBytes(txn.GenesisHash[:]); !ok {
			return badRequest(fmt.Sprintf("transaction %d has unrecognized genesis hash %x", i+1, txn.GenesisHash[:]))
		}
	}
	return nil
}

func validateNetworkParams(txns []types.Transaction, console Console) *ServiceError {
	firstTxn := txns[0]
	maxFirstValid := firstTxn.FirstValid
	minLastValid := firstTxn.LastValid

	for i := 1; i < len(txns); i++ {
		txn := txns[i]
		if txn.GenesisHash != firstTxn.GenesisHash {
			return badRequest(fmt.Sprintf("transaction %d has different genesis hash - all transactions must target the same network", i+1))
		}
		if txn.FirstValid > maxFirstValid {
			maxFirstValid = txn.FirstValid
		}
		if txn.LastValid < minLastValid {
			minLastValid = txn.LastValid
		}
	}

	if maxFirstValid > minLastValid {
		return badRequest(fmt.Sprintf("transaction validity windows do not overlap (earliest LastValid: %d, latest FirstValid: %d) - group would never be valid", minLastValid, maxFirstValid))
	}

	console.Printf("[GROUP] Network params validated, validity window: rounds %d-%d\n", maxFirstValid, minLastValid)
	return nil
}
