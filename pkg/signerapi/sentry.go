// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

const maxComponentGroupSize = 16

// ComponentTargetKind selects the authorization and signing semantics for one
// target on the shared POST /sign/component route.
type ComponentTargetKind string

const (
	ComponentTargetKindUser        ComponentTargetKind = "user"
	ComponentTargetKindSentry      ComponentTargetKind = "sentry"
	ComponentTargetKindBoundedBase ComponentTargetKind = "bounded-base"
)

// ComponentRequest asks one signer to release kind-tagged components for a
// frozen group. Targets and contextual positions partition the original
// prefix; declared dummies form its canonical contiguous suffix.
type ComponentRequest struct {
	RequestID           string                     `json:"request_id,omitempty"`
	GroupBytesHex       []string                   `json:"group_bytes_hex"`
	Targets             []ComponentTarget          `json:"targets"`
	ContextualPositions []ComponentContextPosition `json:"contextual_positions,omitempty"`
	DummyPositions      []ComponentDummyPosition   `json:"dummy_positions,omitempty"`
}

type ComponentTarget struct {
	TargetIndex  int                 `json:"target_index"`
	Kind         ComponentTargetKind `json:"kind"`
	AuthAddress  string              `json:"auth_address,omitempty"`
	ComponentKey string              `json:"component_key,omitempty"`
	LsigArgs     map[string]string   `json:"lsig_args,omitempty"`
}

type ComponentContextPosition struct {
	TargetIndex   int                    `json:"target_index"`
	LsigResources *LogicSigResourceUsage `json:"lsig_resources,omitempty"`
	PQScheme      string                 `json:"pq_scheme,omitempty"`
}

type ComponentDummyPosition struct {
	TargetIndex int `json:"target_index"`
}

type Component struct {
	TargetIndex     int                 `json:"target_index"`
	Kind            ComponentTargetKind `json:"kind"`
	Signature       string              `json:"signature,omitempty"`
	SignatureScheme string              `json:"signature_scheme"`
	AuthAddress     string              `json:"auth_address,omitempty"`
	BaseSignatures  []string            `json:"base_signatures,omitempty"`
	RuntimeArgs     map[string]string   `json:"runtime_args,omitempty"`
	AssemblyReceipt string              `json:"assembly_receipt,omitempty"`
}

type ComponentResponse struct {
	RequestID  string      `json:"request_id"`
	Components []Component `json:"components"`
}

func (r ComponentRequest) Validate() error {
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
	kind := r.Targets[0].Kind
	for i, target := range r.Targets {
		if target.TargetIndex < 0 || target.TargetIndex >= originalCount {
			return fmt.Errorf("target %d: target_index %d is outside original prefix", i+1, target.TargetIndex)
		}
		if covered[target.TargetIndex] {
			return fmt.Errorf("target %d: duplicate or overlapping target_index %d", i+1, target.TargetIndex)
		}
		covered[target.TargetIndex] = true
		if target.Kind != kind {
			return fmt.Errorf("mixed component target kinds are not supported")
		}
		switch target.Kind {
		case ComponentTargetKindUser:
			if target.AuthAddress == "" || target.ComponentKey != "" || len(target.LsigArgs) != 0 {
				return fmt.Errorf("target %d: user target requires only auth_address", i+1)
			}
			if i > 0 && target.AuthAddress != r.Targets[0].AuthAddress {
				return fmt.Errorf("user targets must share one auth_address")
			}
		case ComponentTargetKindSentry:
			if target.AuthAddress != "" || len(target.LsigArgs) != 0 {
				return fmt.Errorf("target %d: sentry target forbids auth_address and lsig_args", i+1)
			}
			if i > 0 && target.ComponentKey != r.Targets[0].ComponentKey {
				return fmt.Errorf("sentry targets must share one component_key")
			}
		case ComponentTargetKindBoundedBase:
			if target.AuthAddress == "" || target.ComponentKey != "" {
				return fmt.Errorf("target %d: bounded-base target requires auth_address and forbids component_key", i+1)
			}
		default:
			return fmt.Errorf("target %d: unsupported component kind %q", i+1, target.Kind)
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

func (r ComponentRequest) TargetKind() ComponentTargetKind {
	if len(r.Targets) == 0 {
		return ""
	}
	return r.Targets[0].Kind
}

func (r ComponentRequest) GroupSignRequest() GroupSignRequest {
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

func (r ComponentResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Components) == 0 {
		return fmt.Errorf("components array is empty")
	}
	seen := make(map[int]bool, len(r.Components))
	for i, component := range r.Components {
		if component.TargetIndex < 0 || seen[component.TargetIndex] {
			return fmt.Errorf("component %d has invalid or duplicate target_index", i+1)
		}
		seen[component.TargetIndex] = true
		switch component.Kind {
		case ComponentTargetKindUser, ComponentTargetKindSentry:
			if component.Signature == "" || component.SignatureScheme == "" || len(component.BaseSignatures) != 0 || component.AssemblyReceipt != "" {
				return fmt.Errorf("component %d has invalid signature material", i+1)
			}
		case ComponentTargetKindBoundedBase:
			if component.AuthAddress == "" || len(component.BaseSignatures) == 0 || component.AssemblyReceipt == "" || component.SignatureScheme == "" || component.Signature != "" {
				return fmt.Errorf("component %d has invalid bounded-base material", i+1)
			}
		default:
			return fmt.Errorf("component %d has unsupported kind %q", i+1, component.Kind)
		}
	}
	return nil
}

func validateGroupBytesHex(items []string) error {
	if len(items) == 0 {
		return fmt.Errorf("group_bytes_hex is empty")
	}
	if len(items) > maxComponentGroupSize {
		return fmt.Errorf("group_bytes_hex length %d exceeds max %d", len(items), maxComponentGroupSize)
	}
	for i, item := range items {
		if item == "" {
			return fmt.Errorf("group_bytes_hex %d is empty", i)
		}
	}
	return nil
}

func validateAssemblyIndex(index, groupLen int, covered []bool) error {
	if index < 0 || index >= groupLen {
		return fmt.Errorf("target_index %d out of range", index)
	}
	if covered[index] {
		return fmt.Errorf("duplicate target_index %d", index)
	}
	covered[index] = true
	return nil
}

func validateOptionalSourceRequestID(id string) error {
	if id == "" {
		return nil
	}
	return validateSignRequestID(id)
}
