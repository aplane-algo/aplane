// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import "fmt"

// BoundedComponentRequest asks the account signer to approve a finalized
// group and release only the bounded base-signature arguments for its
// sentry-enabled spend positions.
type BoundedComponentRequest struct {
	RequestID string        `json:"request_id,omitempty"`
	Requests  []SignRequest `json:"requests"`
}

func (r BoundedComponentRequest) GroupSignRequest() GroupSignRequest {
	return GroupSignRequest(r)
}

func (r BoundedComponentRequest) Validate() error { return r.GroupSignRequest().Validate() }

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
