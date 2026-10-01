// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/cosigner/message"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// ComponentSignRole is an internal gate/message role derived from the public
// component target kind. It is not part of the HTTP request surface.
type ComponentSignRole string

const (
	ComponentSignRoleUser     ComponentSignRole = "user"
	ComponentSignRoleCosigner ComponentSignRole = "cosigner"
)

type ComponentSignPlan struct {
	RequestID    string
	Role         ComponentSignRole
	MessageRole  message.Role
	ComponentKey string
	Group        *canonical.Group
	Requests     []signerapi.SignRequest
	Targets      []ComponentSignTarget
}

type ComponentSignTarget struct {
	TargetIndex int
	Sender      string
	TxID        [32]byte
	Message     [32]byte
}

type componentPlanRequest struct {
	RequestID     string
	Role          ComponentSignRole
	ComponentKey  string
	GroupBytesHex []string
	TargetIndices []int
	Requests      []signerapi.SignRequest
}

func prepareComponentSigning(req componentPlanRequest) (*ComponentSignPlan, *ServiceError) {
	if err := req.validate(); err != nil {
		return nil, badRequest(err.Error())
	}

	role, err := componentMessageRole(req.Role)
	if err != nil {
		return nil, badRequest(err.Error())
	}

	group, decodeErr := canonical.DecodeGroupHex(req.GroupBytesHex)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}

	targetIndices := append([]int(nil), req.TargetIndices...)
	sort.Ints(targetIndices)

	targets := make([]ComponentSignTarget, len(targetIndices))
	for i, targetIndex := range targetIndices {
		entry := group.Entries[targetIndex]
		targets[i] = ComponentSignTarget{
			TargetIndex: targetIndex,
			Sender:      entry.Txn.Sender.String(),
			TxID:        entry.TxID,
			Message:     message.ComponentMessage(role, entry.TxID),
		}
	}

	return &ComponentSignPlan{
		RequestID:    guardedRequestID("cmp", req.RequestID),
		Role:         req.Role,
		MessageRole:  role,
		ComponentKey: req.ComponentKey,
		Group:        group,
		Requests:     append([]signerapi.SignRequest(nil), req.Requests...),
		Targets:      targets,
	}, nil
}

func (r componentPlanRequest) validate() error {
	switch r.Role {
	case ComponentSignRoleUser:
		if r.ComponentKey == "" {
			return fmt.Errorf("component_key is required for user role")
		}
	case ComponentSignRoleCosigner:
	default:
		return fmt.Errorf("role must be %q or %q", ComponentSignRoleUser, ComponentSignRoleCosigner)
	}
	if len(r.GroupBytesHex) == 0 {
		return fmt.Errorf("group_bytes_hex is empty")
	}
	if len(r.TargetIndices) == 0 {
		return fmt.Errorf("target_indices is empty")
	}
	seen := make(map[int]bool, len(r.TargetIndices))
	for _, index := range r.TargetIndices {
		if index < 0 || index >= len(r.GroupBytesHex) {
			return fmt.Errorf("target_indices %d out of range", index)
		}
		if seen[index] {
			return fmt.Errorf("target_indices contains duplicate %d", index)
		}
		seen[index] = true
	}
	return nil
}

func componentMessageRole(role ComponentSignRole) (message.Role, error) {
	switch role {
	case ComponentSignRoleUser:
		return message.RoleUser, nil
	case ComponentSignRoleCosigner:
		return message.RoleCosigner, nil
	default:
		return 0, fmt.Errorf("role must be %q or %q", ComponentSignRoleUser, ComponentSignRoleCosigner)
	}
}
