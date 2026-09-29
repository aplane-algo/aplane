// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Target identifies the policy document domain the shared editor is editing.
type Target string

const (
	TargetAuto     Target = "auto"
	TargetSigner   Target = "signer"
	TargetCosigner Target = "cosigner"
)

func ParseTarget(raw string) (Target, error) {
	switch target := Target(strings.ToLower(strings.TrimSpace(raw))); target {
	case "", TargetAuto:
		return TargetAuto, nil
	case TargetSigner, TargetCosigner:
		return target, nil
	default:
		return "", fmt.Errorf("invalid policy target %q (expected auto, signer, or cosigner)", raw)
	}
}

func TargetForNodeRole(role noderole.Role) (Target, error) {
	switch role {
	case noderole.RoleSigner:
		return TargetSigner, nil
	case noderole.RoleCosigner:
		return TargetCosigner, nil
	default:
		return "", fmt.Errorf("unsupported node role %q", role)
	}
}

// ResolveTarget resolves auto from root node.yaml. Explicit signer or cosigner
// targets are returned as-is for offline review and conversion.
func ResolveTarget(dataDir string, target Target) (Target, error) {
	if target == "" {
		target = TargetAuto
	}
	if target != TargetAuto {
		if _, err := ParseTarget(string(target)); err != nil {
			return "", err
		}
		return target, nil
	}
	if dataDir == "" {
		return TargetSigner, nil
	}
	doc, _, err := noderole.Load(storepaths.NewPaths(dataDir))
	if err != nil {
		return "", fmt.Errorf("failed to resolve policy target from node role: %w", err)
	}
	resolved, err := TargetForNodeRole(doc.Role)
	if err != nil {
		return "", fmt.Errorf("failed to resolve policy target from node role: %w", err)
	}
	return resolved, nil
}

func (t Target) DocumentName() string {
	return "policy.yaml"
}

func (t Target) SidecarName() string {
	return t.DocumentName() + ".hmac"
}

func (t Target) Label() string {
	switch t {
	case TargetCosigner:
		return "Cosigner Policy"
	default:
		return "Signer Policy"
	}
}

func (t Target) StatusNoun() string {
	switch t {
	case TargetCosigner:
		return "cosigner policy"
	default:
		return "policy"
	}
}

func (t Target) Parse(data []byte) (*policy.StoredConfig, error) {
	switch t {
	case TargetCosigner:
		return policy.ParseStoredCosignerConfig(data)
	default:
		return policy.ParseStoredConfig(data)
	}
}

func (t Target) Marshal(stored *policy.StoredConfig) ([]byte, error) {
	switch t {
	case TargetCosigner:
		return policy.MarshalStoredCosignerConfig(stored)
	default:
		return policy.MarshalStoredConfig(stored)
	}
}
