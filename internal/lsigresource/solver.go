// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import (
	"errors"
	"fmt"
)

var ErrGroupTooLarge = errors.New("LogicSig resource demand exceeds maximum group size")

// PlanInput describes an unsigned group. TransactionCount excludes any dummy
// transactions the solver may add. LogicSigs contains at most one entry per
// requested transaction. Dummy is the resource use of each added dummy.
type PlanInput struct {
	TransactionCount uint64
	LogicSigs        []Usage
	Dummy            Usage
}

// Plan is the complete resource result for the final unsigned group.
type Plan struct {
	TransactionCount      uint64
	DummyCount            uint64
	GroupSize             uint64
	TotalProgramBytes     uint64
	TotalArgumentBytes    uint64
	TotalMaxOpcodeCost    uint64
	ArgumentsPooled       bool
	ChargedProgramBytes   uint64
	ProgramFeeFactorUsage uint64
}

// Solve calculates the smallest group satisfying the selected consensus
// profile. It never adds a dummy solely to reduce priced program bytes.
func Solve(profile ConsensusProfile, input PlanInput) (Plan, error) {
	if err := profile.validate(); err != nil {
		return Plan{}, err
	}
	if input.TransactionCount == 0 {
		return Plan{}, fmt.Errorf("%w: transaction count is zero", ErrInvalidUsage)
	}
	if uint64(len(input.LogicSigs)) > input.TransactionCount {
		return Plan{}, fmt.Errorf("%w: %d LogicSigs for %d transactions", ErrInvalidUsage, len(input.LogicSigs), input.TransactionCount)
	}
	if input.TransactionCount > profile.MaxGroupSize {
		return Plan{}, fmt.Errorf("%w: requested group has %d transactions, maximum is %d", ErrGroupTooLarge, input.TransactionCount, profile.MaxGroupSize)
	}
	for i, usage := range input.LogicSigs {
		if err := usage.validate(profile); err != nil {
			return Plan{}, fmt.Errorf("LogicSig %d: %w", i, err)
		}
	}
	if err := input.Dummy.validate(profile); err != nil {
		return Plan{}, fmt.Errorf("dummy LogicSig: %w", err)
	}

	dummies := uint64(0)
	for iteration := uint64(0); iteration <= profile.MaxGroupSize; iteration++ {
		groupSize, err := checkedAdd(input.TransactionCount, dummies)
		if err != nil {
			return Plan{}, err
		}
		if groupSize > profile.MaxGroupSize {
			return Plan{}, fmt.Errorf("%w: required group has %d transactions, maximum is %d", ErrGroupTooLarge, groupSize, profile.MaxGroupSize)
		}

		totals, err := calculateTotals(input.LogicSigs, input.Dummy, dummies, profile.SizeUnit)
		if err != nil {
			return Plan{}, err
		}
		required, err := requiredGroupSize(profile, input.TransactionCount, totals)
		if err != nil {
			return Plan{}, err
		}
		if required > profile.MaxGroupSize {
			return Plan{}, fmt.Errorf("%w: resources require %d transactions, maximum is %d", ErrGroupTooLarge, required, profile.MaxGroupSize)
		}
		nextDummies := required - input.TransactionCount
		if nextDummies == dummies {
			return finalizePlan(profile, input.TransactionCount, dummies, totals)
		}
		if nextDummies < dummies {
			return Plan{}, fmt.Errorf("%w: dummy fixed point was not monotonic", ErrInvalidUsage)
		}
		dummies = nextDummies
	}
	return Plan{}, fmt.Errorf("%w: dummy fixed point did not converge", ErrInvalidUsage)
}

type resourceTotals struct {
	programBytes  uint64
	argumentBytes uint64
	opcodeCost    uint64
	largeArgument bool
}

func calculateTotals(real []Usage, dummy Usage, dummyCount, sizeUnit uint64) (resourceTotals, error) {
	var totals resourceTotals
	for _, usage := range real {
		totals.largeArgument = totals.largeArgument || usage.ArgumentBytes > sizeUnit
		var err error
		totals.programBytes, err = checkedAdd(totals.programBytes, usage.ProgramBytes)
		if err != nil {
			return resourceTotals{}, err
		}
		totals.argumentBytes, err = checkedAdd(totals.argumentBytes, usage.ArgumentBytes)
		if err != nil {
			return resourceTotals{}, err
		}
		totals.opcodeCost, err = checkedAdd(totals.opcodeCost, usage.MaxOpcodeCost)
		if err != nil {
			return resourceTotals{}, err
		}
	}
	dummyPrograms, err := checkedMul(dummy.ProgramBytes, dummyCount)
	if err != nil {
		return resourceTotals{}, err
	}
	dummyArgs, err := checkedMul(dummy.ArgumentBytes, dummyCount)
	if err != nil {
		return resourceTotals{}, err
	}
	dummyCost, err := checkedMul(dummy.MaxOpcodeCost, dummyCount)
	if err != nil {
		return resourceTotals{}, err
	}
	if totals.programBytes, err = checkedAdd(totals.programBytes, dummyPrograms); err != nil {
		return resourceTotals{}, err
	}
	if totals.argumentBytes, err = checkedAdd(totals.argumentBytes, dummyArgs); err != nil {
		return resourceTotals{}, err
	}
	if totals.opcodeCost, err = checkedAdd(totals.opcodeCost, dummyCost); err != nil {
		return resourceTotals{}, err
	}
	totals.largeArgument = totals.largeArgument || (dummyCount > 0 && dummy.ArgumentBytes > sizeUnit)
	return totals, nil
}

func requiredGroupSize(profile ConsensusProfile, requested uint64, totals resourceTotals) (uint64, error) {
	required := requested
	costRequired, err := ceilDiv(totals.opcodeCost, profile.OpcodeUnit)
	if err != nil {
		return 0, err
	}
	required = max(required, costRequired)

	switch profile.SizingMode {
	case SizingModeLegacyCombined:
		combined, err := checkedAdd(totals.programBytes, totals.argumentBytes)
		if err != nil {
			return 0, err
		}
		sizeRequired, err := ceilDiv(combined, profile.SizeUnit)
		if err != nil {
			return 0, err
		}
		required = max(required, sizeRequired)
	case SizingModePricedProgram:
		if totals.largeArgument {
			argsRequired, err := ceilDiv(totals.argumentBytes, profile.SizeUnit)
			if err != nil {
				return 0, err
			}
			required = max(required, argsRequired)
		}
	default:
		return 0, fmt.Errorf("%w: unknown sizing mode %d", ErrInvalidUsage, profile.SizingMode)
	}
	return required, nil
}

func finalizePlan(profile ConsensusProfile, requested, dummies uint64, totals resourceTotals) (Plan, error) {
	groupSize, err := checkedAdd(requested, dummies)
	if err != nil {
		return Plan{}, err
	}
	chargedProgramBytes := uint64(0)
	programFeeFactorUsage := uint64(0)
	if profile.SizingMode == SizingModePricedProgram {
		freeProgramBytes, err := checkedMul(groupSize, profile.SizeUnit)
		if err != nil {
			return Plan{}, err
		}
		if totals.programBytes > freeProgramBytes {
			chargedProgramBytes = totals.programBytes - freeProgramBytes
		}
		programFeeFactorUsage, err = checkedMul(chargedProgramBytes, profile.PerByteTxnSurcharge)
		if err != nil {
			return Plan{}, err
		}
	}
	return Plan{
		TransactionCount:      requested,
		DummyCount:            dummies,
		GroupSize:             groupSize,
		TotalProgramBytes:     totals.programBytes,
		TotalArgumentBytes:    totals.argumentBytes,
		TotalMaxOpcodeCost:    totals.opcodeCost,
		ArgumentsPooled:       totals.largeArgument,
		ChargedProgramBytes:   chargedProgramBytes,
		ProgramFeeFactorUsage: programFeeFactorUsage,
	}, nil
}
