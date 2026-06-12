// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"
	"sort"

	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
)

type ComponentSignPlan struct {
	RequestID    string
	Role         signerapi.ComponentSignRole
	MessageRole  message.Role
	ComponentKey string
	Group        *canonical.Group
	Targets      []ComponentSignTarget
}

type ComponentSignTarget struct {
	TargetIndex int
	Sender      string
	TxID        [32]byte
	Message     [32]byte
}

func PrepareComponentSigning(req signerapi.ComponentSignRequest) (*ComponentSignPlan, *ServiceError) {
	if err := req.Validate(); err != nil {
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
		Targets:      targets,
	}, nil
}

func componentMessageRole(role signerapi.ComponentSignRole) (message.Role, error) {
	switch role {
	case signerapi.ComponentSignRoleUser:
		return message.RoleUser, nil
	case signerapi.ComponentSignRoleSentry:
		return message.RoleSentry, nil
	default:
		return 0, fmt.Errorf("role must be %q or %q", signerapi.ComponentSignRoleUser, signerapi.ComponentSignRoleSentry)
	}
}
