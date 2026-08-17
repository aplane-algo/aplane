// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

const maxComponentGroupSize = 16

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
