// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
)

var ErrUnknownConsensus = errors.New("unsupported LogicSig consensus profile")

// SizingMode selects a consensus algorithm explicitly. Numeric fee parameters
// do not imply a mode because pricing and sizing may evolve independently.
type SizingMode uint8

const (
	SizingModeLegacyCombined SizingMode = iota + 1
	SizingModePricedProgram
)

// ConsensusProfile is the closed subset of consensus parameters required by
// LogicSig resource planning.
type ConsensusProfile struct {
	Version                protocol.ConsensusVersion
	SizingMode             SizingMode
	MaxGroupSize           uint64
	SizeUnit               uint64
	MaxProgramBytes        uint64
	OpcodeUnit             uint64
	PerByteTxnSurcharge    uint64
	MaximumLogicSigVersion uint64
}

var supportedSizingModes = map[protocol.ConsensusVersion]SizingMode{
	protocol.ConsensusV41:    SizingModeLegacyCombined,
	protocol.ConsensusV42:    SizingModePricedProgram,
	protocol.ConsensusVFnet5: SizingModePricedProgram,
	// ConsensusFuture is what a development LocalNet reports. The SDK defines
	// it as v42 with a higher LogicSigVersion, so it prices programs the same
	// way; omitting it makes every LogicSig unplannable on LocalNet while
	// ed25519 keeps working.
	protocol.ConsensusFuture: SizingModePricedProgram,
}

// ResolveConsensus returns a fail-closed profile for a specifically supported
// protocol. Adding an SDK consensus entry does not silently select a mode.
func ResolveConsensus(version string) (ConsensusProfile, error) {
	consensusVersion := protocol.ConsensusVersion(version)
	mode, ok := supportedSizingModes[consensusVersion]
	if !ok {
		return ConsensusProfile{}, fmt.Errorf("%w: %q", ErrUnknownConsensus, version)
	}
	params, ok := sdkconfig.Consensus[consensusVersion]
	if !ok {
		return ConsensusProfile{}, fmt.Errorf("%w: SDK has no parameters for %q", ErrUnknownConsensus, version)
	}
	profile := ConsensusProfile{
		Version:                consensusVersion,
		SizingMode:             mode,
		MaxGroupSize:           uint64(params.MaxTxGroupSize),
		SizeUnit:               params.LogicSigMaxSize,
		MaxProgramBytes:        params.MaxAbsoluteLogicSigProgramSize,
		OpcodeUnit:             params.LogicSigMaxCost,
		PerByteTxnSurcharge:    uint64(params.PerByteTxnSurcharge),
		MaximumLogicSigVersion: params.LogicSigVersion,
	}
	if err := profile.validate(); err != nil {
		return ConsensusProfile{}, fmt.Errorf("consensus profile %q: %w", version, err)
	}
	return profile, nil
}

func (p ConsensusProfile) validate() error {
	if p.SizingMode != SizingModeLegacyCombined && p.SizingMode != SizingModePricedProgram {
		return fmt.Errorf("%w: unknown sizing mode %d", ErrInvalidUsage, p.SizingMode)
	}
	if p.MaxGroupSize == 0 || p.SizeUnit == 0 || p.MaxProgramBytes == 0 || p.OpcodeUnit == 0 {
		return fmt.Errorf("%w: consensus resource unit is zero", ErrInvalidUsage)
	}
	return nil
}
