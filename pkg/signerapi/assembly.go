// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

// AssemblyTargetKind selects the authorization material used for one target.
type AssemblyTargetKind string

const (
	AssemblyTargetKindBoundedCosigner AssemblyTargetKind = "bounded-cosigner"
)

// AssemblyRequest is the shared request payload for POST /sign/assemble.
// Every group position must appear exactly once as a target or passthrough.
type AssemblyRequest struct {
	RequestID     string                    `json:"request_id,omitempty"`
	GroupBytesHex []string                  `json:"group_bytes_hex"`
	Targets       []AssemblyTarget          `json:"targets,omitempty"`
	Passthrough   []AssemblyPassthroughItem `json:"passthrough,omitempty"`
}

// AssemblyTarget carries the authorization material for one frozen group
// position.
type AssemblyTarget struct {
	TargetIndex int                `json:"target_index"`
	Kind        AssemblyTargetKind `json:"kind"`
	AuthAddress string             `json:"auth_address"`

	BaseSignatures      []string          `json:"base_signatures,omitempty"`
	BoundedRuntimeArgs  map[string]string `json:"bounded_runtime_args,omitempty"`
	AssemblyReceipt     string            `json:"assembly_receipt,omitempty"`
	BaseSourceRequestID string            `json:"base_source_request_id,omitempty"`

	// CosignerSignature is required on every bounded-cosigner target except a
	// listed rekey, which takes none; assembly classifies the transaction to
	// decide.
	CosignerSignature       string `json:"cosigner_signature,omitempty"`
	CosignerSourceRequestID string `json:"cosigner_source_request_id,omitempty"`
}

// AssemblyPassthroughItem carries an already-signed group position unchanged.
type AssemblyPassthroughItem struct {
	TargetIndex  int    `json:"target_index"`
	SignedTxnHex string `json:"signed_txn_hex"`
}

// AssemblyResponse is the response payload from POST /sign/assemble.
type AssemblyResponse struct {
	RequestID   string   `json:"request_id"`
	SignedGroup []string `json:"signed_group"`
}

// Validate checks the request shape that can be validated without signer
// state. A passthrough-only request is valid; assembly still verifies every
// signed position against the frozen group.
func (r AssemblyRequest) Validate() error {
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
		if err := target.validate(); err != nil {
			return fmt.Errorf("target %d: %w", i+1, err)
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

func (t AssemblyTarget) validate() error {
	if t.AuthAddress == "" {
		return fmt.Errorf("auth_address is required")
	}
	if t.CosignerSignature == "" && t.CosignerSourceRequestID != "" {
		return fmt.Errorf("cosigner_source_request_id needs a cosigner_signature")
	}
	if err := validateOptionalSourceRequestID(t.CosignerSourceRequestID); err != nil {
		return fmt.Errorf("cosigner_source_request_id: %w", err)
	}
	switch t.Kind {
	case AssemblyTargetKindBoundedCosigner:
		if len(t.BaseSignatures) == 0 || t.AssemblyReceipt == "" {
			return fmt.Errorf("base_signatures and assembly_receipt are required for bounded-cosigner target")
		}
		if err := validateOptionalSourceRequestID(t.BaseSourceRequestID); err != nil {
			return fmt.Errorf("base_source_request_id: %w", err)
		}
	default:
		return fmt.Errorf("kind must be %q", AssemblyTargetKindBoundedCosigner)
	}
	return nil
}

// Validate checks the response shape.
func (r AssemblyResponse) Validate() error {
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
