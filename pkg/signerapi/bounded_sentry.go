// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

// BoundedComponentRequest asks the account signer to validate and approve one
// frozen canonical group, then release bounded base-signature material for its
// declared targets. Targets and contextual positions partition the original
// prefix; dummies declare the contiguous signer-added suffix.
type BoundedComponentRequest struct {
	RequestID           string                     `json:"request_id,omitempty"`
	GroupBytesHex       []string                   `json:"group_bytes_hex"`
	Targets             []BoundedComponentTarget   `json:"targets"`
	ContextualPositions []ComponentContextPosition `json:"contextual_positions,omitempty"`
	DummyPositions      []ComponentDummyPosition   `json:"dummy_positions,omitempty"`
}

func (r BoundedComponentRequest) GroupSignRequest() GroupSignRequest {
	originalCount := len(r.GroupBytesHex) - len(r.DummyPositions)
	if originalCount < 0 {
		originalCount = 0
	}
	requests := make([]SignRequest, originalCount)
	for i := range requests {
		requests[i].TxnBytesHex = r.GroupBytesHex[i]
	}
	for _, target := range r.Targets {
		if target.TargetIndex >= 0 && target.TargetIndex < originalCount {
			requests[target.TargetIndex].AuthAddress = target.AuthAddress
			requests[target.TargetIndex].LsigArgs = target.LsigArgs
		}
	}
	for _, position := range r.ContextualPositions {
		if position.TargetIndex >= 0 && position.TargetIndex < originalCount {
			requests[position.TargetIndex].LsigResources = position.LsigResources
			requests[position.TargetIndex].PQScheme = position.PQScheme
		}
	}
	return GroupSignRequest{RequestID: r.RequestID, Requests: requests}
}

func (r BoundedComponentRequest) ComponentRequest() ComponentRequest {
	targets := make([]ComponentTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		targets = append(targets, ComponentTarget{
			TargetIndex: target.TargetIndex, Kind: ComponentTargetKindBoundedBase,
			AuthAddress: target.AuthAddress, LsigArgs: target.LsigArgs,
		})
	}
	return ComponentRequest{
		RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets,
		ContextualPositions: r.ContextualPositions, DummyPositions: r.DummyPositions,
	}
}

type BoundedComponentTarget struct {
	TargetIndex int               `json:"target_index"`
	AuthAddress string            `json:"auth_address"`
	LsigArgs    map[string]string `json:"lsig_args,omitempty"`
}

type ComponentContextPosition struct {
	TargetIndex   int                    `json:"target_index"`
	LsigResources *LogicSigResourceUsage `json:"lsig_resources,omitempty"`
	PQScheme      string                 `json:"pq_scheme,omitempty"`
}

type ComponentDummyPosition struct {
	TargetIndex int `json:"target_index"`
}

func (r BoundedComponentRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if err := validateGroupBytesHex(r.GroupBytesHex); err != nil {
		return err
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("targets array is empty")
	}
	if len(r.DummyPositions) > len(r.GroupBytesHex) {
		return fmt.Errorf("dummy_positions exceeds group length")
	}
	originalCount := len(r.GroupBytesHex) - len(r.DummyPositions)
	covered := make([]bool, originalCount)
	for i, target := range r.Targets {
		if target.TargetIndex < 0 || target.TargetIndex >= originalCount {
			return fmt.Errorf("target %d: target_index %d is outside original prefix", i+1, target.TargetIndex)
		}
		if covered[target.TargetIndex] {
			return fmt.Errorf("target %d: duplicate or overlapping target_index %d", i+1, target.TargetIndex)
		}
		covered[target.TargetIndex] = true
		if target.AuthAddress == "" {
			return fmt.Errorf("target %d: auth_address is required", i+1)
		}
	}
	for i, position := range r.ContextualPositions {
		if position.TargetIndex < 0 || position.TargetIndex >= originalCount {
			return fmt.Errorf("contextual position %d: target_index %d is outside original prefix", i+1, position.TargetIndex)
		}
		if covered[position.TargetIndex] {
			return fmt.Errorf("contextual position %d: duplicate or overlapping target_index %d", i+1, position.TargetIndex)
		}
		covered[position.TargetIndex] = true
		contextRequest := SignRequest{TxnBytesHex: "frozen", LsigResources: position.LsigResources, PQScheme: position.PQScheme}
		if err := contextRequest.Validate(); err != nil {
			return fmt.Errorf("contextual position %d: %w", i+1, err)
		}
	}
	for index, ok := range covered {
		if !ok {
			return fmt.Errorf("original group position %d is not covered", index)
		}
	}
	for i, dummy := range r.DummyPositions {
		expected := originalCount + i
		if dummy.TargetIndex != expected {
			return fmt.Errorf("dummy position %d: target_index %d must equal contiguous suffix index %d", i+1, dummy.TargetIndex, expected)
		}
	}
	return nil
}

type BoundedBaseComponent struct {
	TargetIndex     int               `json:"target_index"`
	BoundedAccount  string            `json:"bounded_account"`
	BaseSignatures  []string          `json:"base_signatures"`
	RuntimeArgs     map[string]string `json:"runtime_args,omitempty"`
	AssemblyReceipt string            `json:"assembly_receipt"`
	SignatureScheme string            `json:"signature_scheme"`
}

type BoundedComponentResponse struct {
	RequestID    string                 `json:"request_id"`
	Transactions []string               `json:"transactions"`
	Components   []BoundedBaseComponent `json:"components"`
	Mutations    *MutationReport        `json:"mutations,omitempty"`
}

func (r BoundedComponentResponse) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil || r.RequestID == "" {
		return fmt.Errorf("request_id is invalid or empty")
	}
	if len(r.Transactions) == 0 || len(r.Components) == 0 {
		return fmt.Errorf("transactions and components are required")
	}
	seen := make(map[int]bool, len(r.Components))
	for i, component := range r.Components {
		if component.TargetIndex < 0 || component.TargetIndex >= len(r.Transactions) || seen[component.TargetIndex] {
			return fmt.Errorf("component %d has invalid or duplicate target_index", i+1)
		}
		seen[component.TargetIndex] = true
		if component.BoundedAccount == "" || len(component.BaseSignatures) == 0 || component.AssemblyReceipt == "" || component.SignatureScheme == "" {
			return fmt.Errorf("component %d is incomplete", i+1)
		}
	}
	return nil
}

type BoundedAssemblyRequest struct {
	RequestID     string                   `json:"request_id,omitempty"`
	GroupBytesHex []string                 `json:"group_bytes_hex"`
	Targets       []BoundedAssemblyTarget  `json:"targets,omitempty"`
	Passthrough   []GuardedPassthroughItem `json:"passthrough,omitempty"`
}

type BoundedAssemblyTarget struct {
	TargetIndex     int               `json:"target_index"`
	BoundedAccount  string            `json:"bounded_account"`
	BaseSignatures  []string          `json:"base_signatures"`
	RuntimeArgs     map[string]string `json:"runtime_args,omitempty"`
	AssemblyReceipt string            `json:"assembly_receipt"`
	// BaseSourceRequestID is informational correlation metadata only; the
	// assembly receipt binds authorization to the account, transaction,
	// metadata, and runtime arguments.
	BaseSourceRequestID string `json:"base_source_request_id,omitempty"`
	SentrySignature     string `json:"sentry_signature"`
	// SentrySourceRequestID is informational correlation metadata only.
	SentrySourceRequestID string `json:"sentry_source_request_id,omitempty"`
}

type BoundedAssemblyResponse = AssemblyResponse

func (r BoundedAssemblyRequest) Validate() error {
	return r.AssemblyRequest().Validate()
}

// AssemblyRequest converts the legacy bounded-only shape to the shared
// discriminated assembly contract. It exists only while the unreleased route
// migration is staged.
func (r BoundedAssemblyRequest) AssemblyRequest() AssemblyRequest {
	targets := make([]AssemblyTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		targets = append(targets, AssemblyTarget{
			TargetIndex: target.TargetIndex, Kind: AssemblyTargetKindBoundedSentry,
			AuthAddress: target.BoundedAccount, BaseSignatures: target.BaseSignatures,
			BoundedRuntimeArgs: target.RuntimeArgs, AssemblyReceipt: target.AssemblyReceipt,
			BaseSourceRequestID: target.BaseSourceRequestID, SentrySignature: target.SentrySignature,
			SentrySourceRequestID: target.SentrySourceRequestID,
		})
	}
	return AssemblyRequest{RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets, Passthrough: r.Passthrough}
}
