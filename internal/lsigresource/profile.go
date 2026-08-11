// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import "fmt"

// SingleTransactionOpcodeCeiling is the v41/v42 stateless per-group-member
// opcode unit. It may be used as a conservative path ceiling only for a
// program independently reviewed to fit one unit; it is not an analyzer.
const SingleTransactionOpcodeCeiling = 20_000

// AuthorizationPath is a closed signing path whose argument and opcode
// ceilings may differ while the compiled program remains the same.
type AuthorizationPath uint8

const (
	PathDefault AuthorizationPath = iota + 1
	PathSpend
	PathSpendingRekey
	PathAdminRekey
)

// PathProfile is the maximum resource use of one reachable authorization path.
type PathProfile struct {
	ArgumentBytes uint64 `json:"argument_bytes"`
	MaxOpcodeCost uint64 `json:"max_opcode_cost"`
}

// Profile materializes the resources for one stored final LogicSig program.
// ProgramBytes is derived from the final bytecode rather than persisted as an
// independent authority. Bounded paths are explicit; they never fall back to
// Default silently.
type Profile struct {
	ProgramBytes  uint64
	Default       *PathProfile
	Spend         *PathProfile
	SpendingRekey *PathProfile
	AdminRekey    *PathProfile
}

// UsageForPath returns a complete solver usage for the selected path.
func (p Profile) UsageForPath(path AuthorizationPath) (Usage, error) {
	if p.ProgramBytes == 0 {
		return Usage{}, fmt.Errorf("%w: profile program is empty", ErrInvalidUsage)
	}
	var selected *PathProfile
	switch path {
	case PathDefault:
		selected = p.Default
	case PathSpend:
		selected = p.Spend
	case PathSpendingRekey:
		selected = p.SpendingRekey
	case PathAdminRekey:
		selected = p.AdminRekey
	default:
		return Usage{}, fmt.Errorf("%w: unknown authorization path %d", ErrInvalidUsage, path)
	}
	if selected == nil {
		return Usage{}, fmt.Errorf("%w: authorization path %d has no resource profile", ErrInvalidUsage, path)
	}
	if selected.MaxOpcodeCost == 0 {
		return Usage{}, fmt.Errorf("%w: authorization path %d has zero opcode ceiling", ErrInvalidUsage, path)
	}
	return Usage{
		ProgramBytes:  p.ProgramBytes,
		ArgumentBytes: selected.ArgumentBytes,
		MaxOpcodeCost: selected.MaxOpcodeCost,
	}, nil
}

// Clone returns a deep copy suitable for immutable runtime snapshots.
func (p Profile) Clone() Profile {
	return Profile{
		ProgramBytes:  p.ProgramBytes,
		Default:       clonePathProfile(p.Default),
		Spend:         clonePathProfile(p.Spend),
		SpendingRekey: clonePathProfile(p.SpendingRekey),
		AdminRekey:    clonePathProfile(p.AdminRekey),
	}
}

func clonePathProfile(profile *PathProfile) *PathProfile {
	if profile == nil {
		return nil
	}
	cloned := *profile
	return &cloned
}
