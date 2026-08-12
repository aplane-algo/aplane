// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigprovider

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/lsigresource"
)

// OpcodeProfileProvider exposes an independently reviewed opcode ceiling for
// the provider's final compiled LogicSig paths. Implementations must derive the
// declaration from the exact persisted program contract, not from salt style,
// program length, or the per-group-member opcode allowance.
type OpcodeProfileProvider interface {
	LogicSigOpcodeProfile() lsigresource.OpcodeProfile
}

// ResolveOpcodeProfile returns the required provider-owned reviewed profile.
// The bounded flag describes the final durable authorization shape and
// prevents default-path metadata from being attached to a bounded key (or vice
// versa).
func ResolveOpcodeProfile(provider any, bounded bool) (lsigresource.OpcodeProfile, error) {
	declared, ok := provider.(OpcodeProfileProvider)
	if !ok {
		return lsigresource.OpcodeProfile{}, fmt.Errorf("provider does not declare a reviewed LogicSig opcode profile")
	}
	profile := declared.LogicSigOpcodeProfile()
	if err := profile.Validate(bounded); err != nil {
		return lsigresource.OpcodeProfile{}, fmt.Errorf("invalid reviewed LogicSig opcode profile: %w", err)
	}
	return profile, nil
}
