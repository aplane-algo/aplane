// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

// ValidateFrozenComponentContext reconstructs the complete group-policy input
// from typed position declarations and signer-owned metadata. It validates the
// supplied bytes in place and never invokes the canonical planner or mutates,
// appends, regroups, fee-pools, or repairs the group.
func (s *Service) ValidateFrozenComponentContext(identityID string, request signerapi.BoundedComponentRequest) (*PlanResult, signerapi.GroupSignRequest, *ServiceError) {
	if err := request.Validate(); err != nil {
		return nil, signerapi.GroupSignRequest{}, badRequest(err.Error())
	}
	group, decodeErr := canonical.DecodeGroupHex(request.GroupBytesHex)
	if decodeErr != nil {
		return nil, signerapi.GroupSignRequest{}, badRequest(decodeErr.Error())
	}
	allTxns := makeTxnSlice(group)
	isPreGrouped, groupErr := validateGroupConsistency(allTxns, false, s.Console)
	if groupErr != nil {
		return nil, signerapi.GroupSignRequest{}, groupErr
	}
	if err := validateKnownNetwork(allTxns, s.Planner.GenesisHashResolver); err != nil {
		return nil, signerapi.GroupSignRequest{}, err
	}
	if len(allTxns) > 1 {
		if err := validateNetworkParams(allTxns, consoleOf(s.Console)); err != nil {
			return nil, signerapi.GroupSignRequest{}, err
		}
	}

	req := request.GroupSignRequest()
	evalCount := len(req.Requests)
	if evalCount == 0 || evalCount > len(allTxns) {
		return nil, signerapi.GroupSignRequest{}, badRequest("frozen component original prefix is empty or invalid")
	}
	originals := allTxns[:evalCount]
	foreign := make(map[int]bool, len(request.ContextualPositions))
	for _, position := range request.ContextualPositions {
		foreign[position.TargetIndex] = true
	}

	var snapshot PlannerIdentitySnapshot
	if s.Planner.Snapshot != nil {
		snapshot = s.Planner.Snapshot(identityID)
	}
	if _, err := s.Planner.VerifySignableKeys(snapshot, identityID, req.Requests, map[int]bool{}, foreign); err != nil {
		return nil, signerapi.GroupSignRequest{}, err
	}
	boundedItems, err := resolveBoundedPlanItems(snapshot, req.Requests, originals, map[int]bool{}, foreign)
	if err != nil {
		return nil, signerapi.GroupSignRequest{}, err
	}
	resourcePlan, lsigIndices, err := s.Planner.CalculateDummies(snapshot, identityID, req.Requests, originals, boundedItems, map[int]bool{}, foreign, nil, false, false)
	if err != nil {
		return nil, signerapi.GroupSignRequest{}, err
	}
	expectedDummies := int(resourcePlan.DummyCount)
	if expectedDummies != len(request.DummyPositions) {
		return nil, signerapi.GroupSignRequest{}, badRequest(fmt.Sprintf("frozen group declares %d dummy position(s), authorization resources require %d", len(request.DummyPositions), expectedDummies))
	}
	dummyTxns := allTxns[evalCount:]
	for i, dummy := range dummyTxns {
		if !matchesSignerAddedDummyForSelfNoOp(dummy, originals[0], i) {
			return nil, signerapi.GroupSignRequest{}, badRequest(fmt.Sprintf("dummy position %d is not the canonical signer-added dummy", evalCount+i))
		}
	}

	budgets, budgetErr := authorizationBudgets(req.Requests, snapshot, boundedItems, map[int]bool{}, foreign, nil)
	if budgetErr != nil {
		return nil, signerapi.GroupSignRequest{}, budgetErr
	}
	feeInfo, feeErr := applyGroupFees(append([]types.Transaction(nil), allTxns...), budgets, resourcePlan, expectedDummies, lsigIndices, true)
	if feeErr != nil {
		return nil, signerapi.GroupSignRequest{}, feeErr
	}
	// Re-resolve after fee and group validation so bounded max-fee and path
	// checks apply to the exact bytes that will be signed.
	boundedItems, err = resolveBoundedPlanItems(snapshot, req.Requests, originals, map[int]bool{}, foreign)
	if err != nil {
		return nil, signerapi.GroupSignRequest{}, err
	}
	authKeyTypes := make([]string, evalCount)
	for i, txReq := range req.Requests {
		if !foreign[i] {
			authKeyTypes[i] = snapshot.KeyTypes[txReq.AuthAddress]
		}
	}
	return &PlanResult{
		AllTxns: allTxns, DummyTxns: dummyTxns,
		PassthroughIndices: map[int]bool{}, PassthroughSignedTxns: map[int][]byte{},
		ForeignIndices: foreign, HasForeign: len(foreign) > 0,
		LsigIndices: lsigIndices, DummiesNeeded: expectedDummies,
		LogicSigResourcePlan: resourcePlan, FeeInfo: feeInfo,
		NeedsRegroup: false, IsPreGrouped: isPreGrouped, HasPassthrough: false,
		AuthKeyTypes: authKeyTypes, KnownAddresses: knownAddressesFromSnapshot(snapshot),
		BoundedItems: boundedItems,
	}, req, nil
}

func makeTxnSlice(group *canonical.Group) []types.Transaction {
	txns := make([]types.Transaction, len(group.Entries))
	for i, entry := range group.Entries {
		txns[i] = entry.Txn
	}
	return txns
}
