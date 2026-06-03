// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

const maxAttestorGroupSize = 16

// ComponentSignRole is the role-specific component signature requested from
// POST /sign/component.
type ComponentSignRole string

const (
	ComponentSignRoleUser     ComponentSignRole = "user"
	ComponentSignRoleAttestor ComponentSignRole = "attestor"
)

// ComponentSignRequest is the request payload for POST /sign/component.
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

// AttestedAssemblyRequest is the request payload for POST /sign/assemble.
type AttestedAssemblyRequest struct {
	RequestID     string                    `json:"request_id,omitempty"`
	GroupBytesHex []string                  `json:"group_bytes_hex"`
	Targets       []AttestedAssemblyTarget  `json:"targets,omitempty"`
	Passthrough   []AttestedPassthroughItem `json:"passthrough,omitempty"`
}

// AttestedAssemblyTarget carries one attested-account group position plus its
// user and attestor component signatures.
type AttestedAssemblyTarget struct {
	TargetIndex             int      `json:"target_index"`
	AttestedAccount         string   `json:"attested_account"`
	UserSignature           string   `json:"user_signature"`
	UserSourceRequestID     string   `json:"user_source_request_id,omitempty"`
	AttestorSignature       string   `json:"attestor_signature"`
	AttestorSourceRequestID string   `json:"attestor_source_request_id,omitempty"`
	RuntimeArgs             []string `json:"runtime_args,omitempty"`
}

// AttestedPassthroughItem carries an already-signed group position to preserve
// unchanged during assembly.
type AttestedPassthroughItem struct {
	TargetIndex  int    `json:"target_index"`
	SignedTxnHex string `json:"signed_txn_hex"`
}

// AttestedAssemblyResponse is the response payload from POST /sign/assemble.
type AttestedAssemblyResponse struct {
	RequestID   string   `json:"request_id"`
	SignedGroup []string `json:"signed_group"`
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
	case ComponentSignRoleAttestor:
	default:
		return fmt.Errorf("role must be %q or %q", ComponentSignRoleUser, ComponentSignRoleAttestor)
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
func (r AttestedAssemblyRequest) Validate() error {
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if err := validateGroupBytesHex(r.GroupBytesHex); err != nil {
		return err
	}
	if len(r.Targets) == 0 && len(r.Passthrough) == 0 {
		return fmt.Errorf("targets or passthrough is required")
	}

	covered := make([]bool, len(r.GroupBytesHex))
	for i, target := range r.Targets {
		if err := validateAssemblyIndex(target.TargetIndex, len(r.GroupBytesHex), covered); err != nil {
			return fmt.Errorf("target %d: %w", i+1, err)
		}
		if target.AttestedAccount == "" {
			return fmt.Errorf("target %d: attested_account is required", i+1)
		}
		if target.UserSignature == "" {
			return fmt.Errorf("target %d: user_signature is required", i+1)
		}
		if target.AttestorSignature == "" {
			return fmt.Errorf("target %d: attestor_signature is required", i+1)
		}
		if err := validateOptionalSourceRequestID(target.UserSourceRequestID); err != nil {
			return fmt.Errorf("target %d: user_source_request_id: %w", i+1, err)
		}
		if err := validateOptionalSourceRequestID(target.AttestorSourceRequestID); err != nil {
			return fmt.Errorf("target %d: attestor_source_request_id: %w", i+1, err)
		}
	}
	for i, passthrough := range r.Passthrough {
		if err := validateAssemblyIndex(passthrough.TargetIndex, len(r.GroupBytesHex), covered); err != nil {
			return fmt.Errorf("passthrough %d: %w", i+1, err)
		}
		if passthrough.SignedTxnHex == "" {
			return fmt.Errorf("passthrough %d: signed_txn_hex is required", i+1)
		}
	}
	for i, ok := range covered {
		if !ok {
			return fmt.Errorf("group position %d is not covered by targets or passthrough", i)
		}
	}
	return nil
}

// Validate checks the response shape.
func (r AttestedAssemblyResponse) Validate() error {
	if r.RequestID == "" {
		return fmt.Errorf("request_id is required")
	}
	if err := validateSignRequestID(r.RequestID); err != nil {
		return err
	}
	if len(r.SignedGroup) == 0 {
		return fmt.Errorf("signed_group is empty")
	}
	for i, signed := range r.SignedGroup {
		if signed == "" {
			return fmt.Errorf("signed_group %d is empty", i)
		}
	}
	return nil
}

func validateGroupBytesHex(items []string) error {
	if len(items) == 0 {
		return fmt.Errorf("group_bytes_hex is empty")
	}
	if len(items) > maxAttestorGroupSize {
		return fmt.Errorf("group_bytes_hex length %d exceeds max %d", len(items), maxAttestorGroupSize)
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
	for i, index := range indices {
		if index < 0 || index >= groupLen {
			return fmt.Errorf("target_indices %d out of range", index)
		}
		if _, ok := seen[index]; ok {
			return fmt.Errorf("target_indices contains duplicate %d", index)
		}
		seen[index] = struct{}{}
		if i > 0 && index < indices[i-1] {
			continue
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
