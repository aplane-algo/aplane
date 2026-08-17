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
func (s *Service) ValidateFrozenComponentContext(identityID string, request signerapi.ComponentRequest) (*PlanResult, signerapi.GroupSignRequest, *ServiceError) {
	if err := request.Validate(); err != nil {
		return nil, signerapi.GroupSignRequest{}, badRequest(err.Error())
	}
	group, decodeErr := canonical.DecodeGroupHex(request.GroupBytesHex)
	if decodeErr != nil {
		return nil, signerapi.GroupSignRequest{}, badRequest(decodeErr.Error())
	}
	allTxns := makeTxnSlice(group)
	if err := validateFrozenComponentDummyPartition(request, allTxns); err != nil {
		return nil, signerapi.GroupSignRequest{}, err
	}
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
		return nil, signerapi.GroupSignRequest{}, s.frozenComponentPlannerError(err)
	}
	boundedItems, err := resolveBoundedPlanItems(snapshot, req.Requests, originals, map[int]bool{}, foreign)
	if err != nil {
		return nil, signerapi.GroupSignRequest{}, s.frozenComponentPlannerError(err)
	}
	resourcePlan, lsigIndices, err := s.Planner.CalculateDummies(snapshot, identityID, req.Requests, originals, boundedItems, map[int]bool{}, foreign, nil, false, false)
	if err != nil {
		return nil, signerapi.GroupSignRequest{}, s.frozenComponentPlannerError(err)
	}
	expectedDummies := int(resourcePlan.DummyCount)
	if expectedDummies != len(request.DummyPositions) {
		return nil, signerapi.GroupSignRequest{}, badRequest(fmt.Sprintf("frozen group declares %d dummy position(s), authorization resources require %d", len(request.DummyPositions), expectedDummies))
	}
	dummyTxns := allTxns[evalCount:]

	budgets, budgetErr := authorizationBudgets(req.Requests, snapshot, boundedItems, map[int]bool{}, foreign, nil)
	if budgetErr != nil {
		return nil, signerapi.GroupSignRequest{}, s.frozenComponentPlannerError(budgetErr)
	}
	feeInfo, feeErr := applyGroupFees(append([]types.Transaction(nil), allTxns...), budgets, resourcePlan, expectedDummies, lsigIndices, true)
	if feeErr != nil {
		return nil, signerapi.GroupSignRequest{}, s.frozenComponentPlannerError(feeErr)
	}
	s.Planner.logSignRequests(identityID, req, originals, map[int]bool{}, foreign)
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

func (s *Service) frozenComponentPlannerError(err *ServiceError) *ServiceError {
	if err != nil && s.IsUnlocked != nil && !s.IsUnlocked() {
		return lockedError()
	}
	return err
}

// validateFrozenComponentDummyPartition makes the request's position labels
// semantic rather than merely structural. Canonical signer-added dummies are
// reserved for the declared contiguous suffix: callers may neither fabricate a
// declared dummy nor relabel a real dummy as an original policy input.
func validateFrozenComponentDummyPartition(request signerapi.ComponentRequest, allTxns []types.Transaction) *ServiceError {
	originalCount := len(allTxns) - len(request.DummyPositions)
	if originalCount <= 0 || originalCount > len(allTxns) {
		return badRequest("frozen component original prefix is empty or invalid")
	}
	original := allTxns[0]
	for offset, dummy := range allTxns[originalCount:] {
		if !matchesSignerAddedDummyForSelfNoOp(dummy, original, offset) {
			return badRequest(fmt.Sprintf("dummy position %d is not the canonical signer-added dummy", originalCount+offset))
		}
	}
	for start := 1; start < originalCount; start++ {
		canonicalSuffix := true
		for offset, candidate := range allTxns[start:] {
			if !matchesSignerAddedDummyForSelfNoOp(candidate, original, offset) {
				canonicalSuffix = false
				break
			}
		}
		if canonicalSuffix {
			return badRequest(fmt.Sprintf("canonical signer-added dummy suffix beginning at position %d must be declared as dummy_positions", start))
		}
	}
	return nil
}

func makeTxnSlice(group *canonical.Group) []types.Transaction {
	txns := make([]types.Transaction, len(group.Entries))
	for i, entry := range group.Entries {
		txns[i] = entry.Txn
	}
	return txns
}
