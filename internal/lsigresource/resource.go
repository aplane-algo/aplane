// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package lsigresource models consensus-bearing LogicSig resources without
// combining program bytes, argument bytes, and opcode cost into one scalar.
package lsigresource

import (
	"errors"
	"fmt"
	"math"
)

var (
	ErrInvalidUsage     = errors.New("invalid LogicSig resource usage")
	ErrResourceOverflow = errors.New("LogicSig resource arithmetic overflow")
)

// Usage describes one LogicSig authorization at the path selected for the
// transaction. MaxOpcodeCost is a reviewed upper bound, not a sampled cost.
type Usage struct {
	ProgramBytes  uint64
	ArgumentBytes uint64
	MaxOpcodeCost uint64
}

func (u Usage) validate(profile ConsensusProfile) error {
	if u.ProgramBytes == 0 {
		return fmt.Errorf("%w: program is empty", ErrInvalidUsage)
	}
	if u.ProgramBytes > profile.MaxProgramBytes {
		return fmt.Errorf(
			"%w: program has %d bytes, protocol maximum is %d",
			ErrInvalidUsage,
			u.ProgramBytes,
			profile.MaxProgramBytes,
		)
	}
	return nil
}

func checkedAdd(a, b uint64) (uint64, error) {
	if b > math.MaxUint64-a {
		return 0, ErrResourceOverflow
	}
	return a + b, nil
}

func checkedMul(a, b uint64) (uint64, error) {
	if a != 0 && b > math.MaxUint64/a {
		return 0, ErrResourceOverflow
	}
	return a * b, nil
}

func ceilDiv(value, unit uint64) (uint64, error) {
	if unit == 0 {
		return 0, fmt.Errorf("%w: zero resource unit", ErrInvalidUsage)
	}
	if value == 0 {
		return 0, nil
	}
	numerator, err := checkedAdd(value, unit-1)
	if err != nil {
		return 0, err
	}
	return numerator / unit, nil
}
