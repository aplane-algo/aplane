// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
)

// AdminPolicyClient is the synchronous admin-protocol boundary used by
// AdminStore. The concrete TUI client adapts IPC/SSH transport to this small
// interface; tests can fake it without importing TUI state.
type AdminPolicyClient interface {
	GetPolicySnapshot(context.Context, Target) (AdminPolicySnapshot, error)
	ValidatePolicy(context.Context, Target, string) (AdminPolicyValidation, error)
	ReplacePolicy(context.Context, Target, string, string) (AdminPolicySnapshot, error)
}

// AdminPolicySnapshot is the policy snapshot shape AdminStore needs from the
// admin protocol.
type AdminPolicySnapshot struct {
	Success      bool
	Target       Target
	IdentityID   string
	PolicyYAML   string
	PolicySHA256 string
	Canonical    bool
	Code         string
	Error        string
}

// AdminPolicyValidation is the validation-only admin protocol result shape.
type AdminPolicyValidation struct {
	Success    bool
	Target     Target
	IdentityID string
	Code       string
	Error      string
}

// AdminStore edits a signer-owned policy document through the online admin
// protocol. It keeps the last loaded snapshot SHA for optimistic concurrency
// when saving.
type AdminStore struct {
	Client AdminPolicyClient
	Target Target

	identityID string
	lastSHA    string
	policyYAML string
}

// Persistence reports that Save replaces the daemon-owned production policy.
func (s *AdminStore) Persistence() Persistence {
	return Persistence{Kind: PersistenceProduction}
}

func (s *AdminStore) Load(ctx context.Context) (*policy.StoredConfig, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := s.resolvedTarget()
	if err != nil {
		return nil, err
	}
	if s.Client == nil {
		return nil, fmt.Errorf("admin policy client is required")
	}
	snapshot, err := s.Client.GetPolicySnapshot(ctx, target)
	if err != nil {
		return nil, err
	}
	if err := requireSnapshotSuccess(snapshot, target, "load"); err != nil {
		return nil, err
	}
	stored, err := target.Parse([]byte(snapshot.PolicyYAML))
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s snapshot: %w", target.DocumentName(), err)
	}
	s.identityID = snapshot.IdentityID
	s.lastSHA = strings.TrimSpace(snapshot.PolicySHA256)
	s.policyYAML = snapshot.PolicyYAML
	return stored, nil
}

func (s *AdminStore) Validate(ctx context.Context, stored *policy.StoredConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, data, err := s.marshal(stored)
	if err != nil {
		return err
	}
	if s.Client == nil {
		return fmt.Errorf("admin policy client is required")
	}
	result, err := s.Client.ValidatePolicy(ctx, target, string(data))
	if err != nil {
		return err
	}
	if !result.Success {
		return adminPolicyError("validate", target, result.Code, result.Error)
	}
	if result.Target != "" && result.Target != target {
		return fmt.Errorf("validate returned target %q, want %q", result.Target, target)
	}
	if result.IdentityID != "" {
		s.identityID = result.IdentityID
	}
	return nil
}

func (s *AdminStore) Save(ctx context.Context, stored *policy.StoredConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, data, err := s.marshal(stored)
	if err != nil {
		return err
	}
	if s.Client == nil {
		return fmt.Errorf("admin policy client is required")
	}
	snapshot, err := s.Client.ReplacePolicy(ctx, target, string(data), s.lastSHA)
	if err != nil {
		return err
	}
	if err := requireSnapshotSuccess(snapshot, target, "save"); err != nil {
		return err
	}
	s.identityID = snapshot.IdentityID
	s.lastSHA = strings.TrimSpace(snapshot.PolicySHA256)
	s.policyYAML = snapshot.PolicyYAML
	return nil
}

// SaveYAML validates and replaces exact caller-supplied YAML bytes while
// retaining optimistic concurrency from the last successful Load. This is the
// batch/pipe counterpart to the structured editor's canonical Save method.
func (s *AdminStore) SaveYAML(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target, err := s.resolvedTarget()
	if err != nil {
		return err
	}
	if _, err := target.Parse(data); err != nil {
		return fmt.Errorf("failed to parse %s: %w", target.DocumentName(), err)
	}
	if s.Client == nil {
		return fmt.Errorf("admin policy client is required")
	}
	validation, err := s.Client.ValidatePolicy(ctx, target, string(data))
	if err != nil {
		return err
	}
	if !validation.Success {
		return adminPolicyError("validate", target, validation.Code, validation.Error)
	}
	snapshot, err := s.Client.ReplacePolicy(ctx, target, string(data), s.lastSHA)
	if err != nil {
		return err
	}
	if err := requireSnapshotSuccess(snapshot, target, "save"); err != nil {
		return err
	}
	s.identityID = snapshot.IdentityID
	s.lastSHA = strings.TrimSpace(snapshot.PolicySHA256)
	s.policyYAML = snapshot.PolicyYAML
	return nil
}

// ModeLabel identifies this backend in policytui headers.
func (s *AdminStore) ModeLabel() string {
	return "online"
}

// IdentityID returns the identity reported by the last successful admin policy
// operation, if any.
func (s *AdminStore) IdentityID() string {
	if s == nil {
		return ""
	}
	return s.identityID
}

// LastSHA256 returns the canonical snapshot SHA from the last successful Load
// or Save.
func (s *AdminStore) LastSHA256() string {
	if s == nil {
		return ""
	}
	return s.lastSHA
}

// PolicyYAML returns the exact document bytes from the last successful Load or
// Save, as represented on the admin protocol.
func (s *AdminStore) PolicyYAML() string {
	if s == nil {
		return ""
	}
	return s.policyYAML
}

func (s *AdminStore) marshal(stored *policy.StoredConfig) (Target, []byte, error) {
	target, err := s.resolvedTarget()
	if err != nil {
		return "", nil, err
	}
	data, err := target.Marshal(stored)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal %s: %w", target.DocumentName(), err)
	}
	return target, data, nil
}

func (s *AdminStore) resolvedTarget() (Target, error) {
	target := TargetSigner
	if s != nil && s.Target != "" && s.Target != TargetAuto {
		target = s.Target
	}
	switch target {
	case TargetSigner, TargetSentry:
		return target, nil
	default:
		return "", fmt.Errorf("invalid admin policy target %q", target)
	}
}

func requireSnapshotSuccess(snapshot AdminPolicySnapshot, target Target, action string) error {
	if !snapshot.Success {
		return adminPolicyError(action, target, snapshot.Code, snapshot.Error)
	}
	if snapshot.Target != "" && snapshot.Target != target {
		return fmt.Errorf("%s returned target %q, want %q", action, snapshot.Target, target)
	}
	if strings.TrimSpace(snapshot.PolicyYAML) == "" {
		return fmt.Errorf("%s returned empty %s snapshot", action, target.DocumentName())
	}
	return nil
}

func adminPolicyError(action string, target Target, code, message string) error {
	if strings.TrimSpace(message) == "" {
		message = "request failed"
	}
	if strings.TrimSpace(code) != "" {
		return fmt.Errorf("%s %s failed [%s]: %s", action, target.StatusNoun(), code, message)
	}
	return fmt.Errorf("%s %s failed: %s", action, target.StatusNoun(), message)
}
