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

// MaximumDeclaredOpcodeCost is the largest path ceiling accepted in durable
// metadata. It is the full v42 group pool, not a per-transaction allowance.
const MaximumDeclaredOpcodeCost = 16 * SingleTransactionOpcodeCeiling

// OpcodeProfile is the durable portion of a LogicSig resource profile. The
// program length and argument maxima are derived from other authoritative key
// fields; only reviewed opcode ceilings need their own stored contract.
type OpcodeProfile struct {
	Default       uint64 `json:"default,omitempty"`
	Spend         uint64 `json:"spend,omitempty"`
	SpendingRekey uint64 `json:"spending_rekey,omitempty"`
	AdminRekey    uint64 `json:"admin_rekey,omitempty"`
}

// DefaultOpcodeProfile returns the closed profile for a non-bounded LogicSig.
func DefaultOpcodeProfile(maxCost uint64) OpcodeProfile {
	return OpcodeProfile{Default: maxCost}
}

// BoundedOpcodeProfile returns the closed profile for bounded authorization.
func BoundedOpcodeProfile(spend, spendingRekey, adminRekey uint64) OpcodeProfile {
	return OpcodeProfile{Spend: spend, SpendingRekey: spendingRekey, AdminRekey: adminRekey}
}

// Validate checks that exactly the expected path vocabulary is populated.
func (p OpcodeProfile) Validate(bounded bool) error {
	check := func(path string, value uint64, required bool) error {
		if required && value == 0 {
			return fmt.Errorf("%w: %s opcode ceiling is missing", ErrInvalidUsage, path)
		}
		if !required && value != 0 {
			return fmt.Errorf("%w: %s opcode ceiling is not valid for this profile", ErrInvalidUsage, path)
		}
		if value > MaximumDeclaredOpcodeCost {
			return fmt.Errorf("%w: %s opcode ceiling %d exceeds maximum %d", ErrInvalidUsage, path, value, MaximumDeclaredOpcodeCost)
		}
		return nil
	}
	if err := check("default", p.Default, !bounded); err != nil {
		return err
	}
	if err := check("spend", p.Spend, bounded); err != nil {
		return err
	}
	if err := check("spending_rekey", p.SpendingRekey, bounded); err != nil {
		return err
	}
	return check("admin_rekey", p.AdminRekey, bounded)
}

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
	ProgramBytes  uint64       `json:"program_bytes"`
	Default       *PathProfile `json:"default,omitempty"`
	Spend         *PathProfile `json:"spend,omitempty"`
	SpendingRekey *PathProfile `json:"spending_rekey,omitempty"`
	AdminRekey    *PathProfile `json:"admin_rekey,omitempty"`
}

// Materialize combines derived program/argument sizes with the durable opcode
// ceilings. Bounded path arguments must contain all three closed paths.
func Materialize(programBytes uint64, defaultArgs *uint64, boundedArgs map[AuthorizationPath]uint64, opcodes OpcodeProfile) (Profile, error) {
	bounded := defaultArgs == nil
	if err := opcodes.Validate(bounded); err != nil {
		return Profile{}, err
	}
	profile := Profile{ProgramBytes: programBytes}
	if !bounded {
		profile.Default = &PathProfile{ArgumentBytes: *defaultArgs, MaxOpcodeCost: opcodes.Default}
		return profile, nil
	}
	spend, spendOK := boundedArgs[PathSpend]
	spendingRekey, spendingRekeyOK := boundedArgs[PathSpendingRekey]
	adminRekey, adminRekeyOK := boundedArgs[PathAdminRekey]
	if !spendOK || !spendingRekeyOK || !adminRekeyOK {
		return Profile{}, fmt.Errorf("%w: bounded argument profile is incomplete", ErrInvalidUsage)
	}
	profile.Spend = &PathProfile{ArgumentBytes: spend, MaxOpcodeCost: opcodes.Spend}
	profile.SpendingRekey = &PathProfile{ArgumentBytes: spendingRekey, MaxOpcodeCost: opcodes.SpendingRekey}
	profile.AdminRekey = &PathProfile{ArgumentBytes: adminRekey, MaxOpcodeCost: opcodes.AdminRekey}
	return profile, nil
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
