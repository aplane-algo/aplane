// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"sort"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
)

type ComponentSignPlan struct {
	RequestID    string
	ComponentKey string
	Group        *canonical.Group
	Targets      []ComponentSignTarget
}

type ComponentSignTarget struct {
	TargetIndex int
	Sender      string
	TxID        [32]byte
	// Fee is the target's fee in microAlgos, as the frozen group has it.
	Fee     uint64
	Message [32]byte
}

// componentPlanRequest is a cosigner request as SignComponentsWithContext
// hands it on: validated (signerapi.ComponentRequest.Validate, so every
// target index is distinct and inside the group) and decoded once.
type componentPlanRequest struct {
	RequestID     string
	ComponentKey  string
	Group         *canonical.Group
	TargetIndices []int
}

// prepareComponentSigning lists the request's targets in group order, each
// with the cosigner-role component message the cosigner signs for it.
func prepareComponentSigning(req componentPlanRequest) *ComponentSignPlan {
	targetIndices := append([]int(nil), req.TargetIndices...)
	sort.Ints(targetIndices)

	targets := make([]ComponentSignTarget, len(targetIndices))
	for i, targetIndex := range targetIndices {
		// No bounds check here: signerapi.ComponentRequest.Validate, which
		// SignComponentsWithContext runs first, refuses a target index that
		// is negative, repeated or outside the group's original prefix
		// (TestComponentRequestValidateRefusesBadTargetIndices).
		entry := req.Group.Entries[targetIndex]
		targets[i] = ComponentSignTarget{
			TargetIndex: targetIndex,
			Sender:      entry.Txn.Sender.String(),
			TxID:        entry.TxID,
			Fee:         uint64(entry.Txn.Fee),
			Message:     message.ComponentMessage(message.RoleCosigner, entry.TxID),
		}
	}

	return &ComponentSignPlan{
		RequestID:    req.RequestID,
		ComponentKey: req.ComponentKey,
		Group:        req.Group,
		Targets:      targets,
	}
}
