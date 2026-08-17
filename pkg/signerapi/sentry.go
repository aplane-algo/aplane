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

// ComponentSignRole is the role-specific component signature requested from
// POST /sign/component.
type ComponentSignRole string

const (
	ComponentSignRoleUser   ComponentSignRole = "user"
	ComponentSignRoleSentry ComponentSignRole = "sentry"
)

// ComponentSignRequest is the request payload for POST /sign/component.
// RequestID is optional. When omitted, apsigner returns a generated response
// ID for correlation only; component signing is not a /sign/cancel live handle
// in the current MVP.
type ComponentSignRequest struct {
	RequestID     string            `json:"request_id,omitempty"`
	Role          ComponentSignRole `json:"role"`
	ComponentKey  string            `json:"component_key,omitempty"`
	GroupBytesHex []string          `json:"group_bytes_hex"`
	TargetIndices []int             `json:"target_indices"`
}

// ComponentSignature carries one raw role-separated component signature.
type ComponentSignature struct {
	TargetIndex     int    `json:"target_index"`
	Signature       string `json:"signature"`
	SignatureScheme string `json:"signature_scheme"`
}

// ComponentSignResponse is the response payload from POST /sign/component.
type ComponentSignResponse struct {
	RequestID    string               `json:"request_id"`
	ComponentKey string               `json:"component_key,omitempty"`
	Signatures   []ComponentSignature `json:"signatures"`
}

// GuardedAssemblyRequest is the request payload for POST /sign/assemble.
// RequestID is optional. When omitted, apsigner returns a generated response
// ID for correlation only; assembly is not a /sign/cancel live handle.
type GuardedAssemblyRequest struct {
	RequestID     string                   `json:"request_id,omitempty"`
	GroupBytesHex []string                 `json:"group_bytes_hex"`
	Targets       []GuardedAssemblyTarget  `json:"targets,omitempty"`
	Passthrough   []GuardedPassthroughItem `json:"passthrough,omitempty"`
}

// GuardedAssemblyTarget carries one guarded-account group position plus its
// user and sentry component signatures.
type GuardedAssemblyTarget struct {
	TargetIndex    int    `json:"target_index"`
	GuardedAccount string `json:"guarded_account"`
	UserSignature  string `json:"user_signature"`
	// UserSourceRequestID is informational correlation metadata only; assembly
	// authorization is bound by the signatures and frozen group bytes.
	UserSourceRequestID string `json:"user_source_request_id,omitempty"`
	SentrySignature     string `json:"sentry_signature"`
	// SentrySourceRequestID is informational correlation metadata only.
	SentrySourceRequestID string   `json:"sentry_source_request_id,omitempty"`
	RuntimeArgs           []string `json:"runtime_args,omitempty"`
}

// GuardedPassthroughItem carries an already-signed group position to preserve
// unchanged during assembly.
type GuardedPassthroughItem = AssemblyPassthroughItem

// GuardedAssemblyResponse is the response payload from POST /sign/assemble.
type GuardedAssemblyResponse = AssemblyResponse

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

func (r ComponentRequest) LegacySignRequest() ComponentSignRequest {
	legacy := ComponentSignRequest{RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex}
	for _, target := range r.Targets {
		legacy.TargetIndices = append(legacy.TargetIndices, target.TargetIndex)
		switch target.Kind {
		case ComponentTargetKindUser:
			legacy.Role = ComponentSignRoleUser
			if legacy.ComponentKey == "" {
				legacy.ComponentKey = target.AuthAddress
			}
		case ComponentTargetKindSentry:
			legacy.Role = ComponentSignRoleSentry
			if legacy.ComponentKey == "" {
				legacy.ComponentKey = target.ComponentKey
			}
		}
	}
	return legacy
}

func (r ComponentRequest) BoundedRequest() BoundedComponentRequest {
	targets := make([]BoundedComponentTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		targets = append(targets, BoundedComponentTarget{
			TargetIndex: target.TargetIndex, AuthAddress: target.AuthAddress, LsigArgs: target.LsigArgs,
		})
	}
	return BoundedComponentRequest{
		RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets,
		ContextualPositions: r.ContextualPositions, DummyPositions: r.DummyPositions,
	}
}

func (r ComponentSignRequest) ComponentRequest() ComponentRequest {
	targetSet := make(map[int]bool, len(r.TargetIndices))
	targets := make([]ComponentTarget, 0, len(r.TargetIndices))
	for _, index := range r.TargetIndices {
		targetSet[index] = true
		target := ComponentTarget{TargetIndex: index}
		if r.Role == ComponentSignRoleUser {
			target.Kind, target.AuthAddress = ComponentTargetKindUser, r.ComponentKey
		} else {
			target.Kind, target.ComponentKey = ComponentTargetKindSentry, r.ComponentKey
		}
		targets = append(targets, target)
	}
	context := make([]ComponentContextPosition, 0, len(r.GroupBytesHex)-len(targets))
	for index := range r.GroupBytesHex {
		if !targetSet[index] {
			context = append(context, ComponentContextPosition{TargetIndex: index})
		}
	}
	return ComponentRequest{RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets, ContextualPositions: context}
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

// Validate checks the request shape that can be validated without signer state.
func (r ComponentSignRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	switch r.Role {
	case ComponentSignRoleUser:
		if r.ComponentKey == "" {
			return fmt.Errorf("component_key is required for user role")
		}
	case ComponentSignRoleSentry:
	default:
		return fmt.Errorf("role must be %q or %q", ComponentSignRoleUser, ComponentSignRoleSentry)
	}
	if err := validateGroupBytesHex(r.GroupBytesHex); err != nil {
		return err
	}
	return validateTargetIndices(r.TargetIndices, len(r.GroupBytesHex))
}

// Validate checks the response shape.
func (r ComponentSignResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.Signatures) == 0 {
		return fmt.Errorf("signatures array is empty")
	}
	seen := make(map[int]struct{}, len(r.Signatures))
	for i, sig := range r.Signatures {
		if sig.TargetIndex < 0 {
			return fmt.Errorf("signature %d: target_index must be non-negative", i+1)
		}
		if _, ok := seen[sig.TargetIndex]; ok {
			return fmt.Errorf("signature %d: duplicate target_index %d", i+1, sig.TargetIndex)
		}
		seen[sig.TargetIndex] = struct{}{}
		if sig.Signature == "" {
			return fmt.Errorf("signature %d: signature is required", i+1)
		}
		if sig.SignatureScheme == "" {
			return fmt.Errorf("signature %d: signature_scheme is required", i+1)
		}
	}
	return nil
}

// Validate checks the request shape that can be validated without signer state.
func (r GuardedAssemblyRequest) Validate() error {
	return r.AssemblyRequest().Validate()
}

// AssemblyRequest converts the legacy guarded-only shape to the shared
// discriminated assembly contract. It exists only while the unreleased route
// migration is staged.
func (r GuardedAssemblyRequest) AssemblyRequest() AssemblyRequest {
	targets := make([]AssemblyTarget, 0, len(r.Targets))
	for _, target := range r.Targets {
		targets = append(targets, AssemblyTarget{
			TargetIndex: target.TargetIndex, Kind: AssemblyTargetKindGuarded,
			AuthAddress: target.GuardedAccount, UserSignature: target.UserSignature,
			UserSourceRequestID: target.UserSourceRequestID, GuardedRuntimeArgs: target.RuntimeArgs,
			SentrySignature: target.SentrySignature, SentrySourceRequestID: target.SentrySourceRequestID,
		})
	}
	return AssemblyRequest{RequestID: r.RequestID, GroupBytesHex: r.GroupBytesHex, Targets: targets, Passthrough: r.Passthrough}
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

func validateTargetIndices(indices []int, groupLen int) error {
	if len(indices) == 0 {
		return fmt.Errorf("target_indices is empty")
	}
	seen := make(map[int]struct{}, len(indices))
	for _, index := range indices {
		if index < 0 || index >= groupLen {
			return fmt.Errorf("target_indices %d out of range", index)
		}
		if _, ok := seen[index]; ok {
			return fmt.Errorf("target_indices contains duplicate %d", index)
		}
		seen[index] = struct{}{}
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
