// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package lsigresource

import (
	"errors"
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/protocol"
	sdkconfig "github.com/algorand/go-algorand-sdk/v2/protocol/config"
)

var ErrUnknownConsensus = errors.New("unsupported consensus contract")

// CurrentConsensusVersion is the sole consensus contract implemented by this
// APlane release. Supporting another protocol requires updating and reviewing
// this package; versions are never ordered or inferred at runtime.
const CurrentConsensusVersion = protocol.ConsensusV42

// ConsensusProfile is the closed subset of consensus parameters required by
// LogicSig resource planning.
type ConsensusProfile struct {
	Version                protocol.ConsensusVersion
	MaxGroupSize           uint64
	MinTxnFee              uint64
	SizeUnit               uint64
	MaxProgramBytes        uint64
	OpcodeUnit             uint64
	PerByteTxnSurcharge    uint64
	MaximumLogicSigVersion uint64
}

// ResolveConsensus verifies that an algod-reported identifier represents the
// one consensus contract supported by this release, then returns the compiled
// v42 profile.
func ResolveConsensus(version string) (ConsensusProfile, error) {
	consensusVersion := protocol.ConsensusVersion(version)
	if consensusVersion != CurrentConsensusVersion {
		return ConsensusProfile{}, fmt.Errorf("%w: %q", ErrUnknownConsensus, version)
	}
	return CurrentConsensus()
}

// CurrentConsensus returns the compiled and validated v42 planning contract.
func CurrentConsensus() (ConsensusProfile, error) {
	params, ok := sdkconfig.Consensus[CurrentConsensusVersion]
	if !ok {
		return ConsensusProfile{}, fmt.Errorf("%w: SDK has no parameters for %q", ErrUnknownConsensus, CurrentConsensusVersion)
	}
	profile := ConsensusProfile{
		Version:                CurrentConsensusVersion,
		MaxGroupSize:           uint64(params.MaxTxGroupSize),
		MinTxnFee:              params.MinTxnFee,
		SizeUnit:               params.LogicSigMaxSize,
		MaxProgramBytes:        params.MaxAbsoluteLogicSigProgramSize,
		OpcodeUnit:             params.LogicSigMaxCost,
		PerByteTxnSurcharge:    uint64(params.PerByteTxnSurcharge),
		MaximumLogicSigVersion: params.LogicSigVersion,
	}
	if err := profile.validate(); err != nil {
		return ConsensusProfile{}, fmt.Errorf("consensus profile %q: %w", CurrentConsensusVersion, err)
	}
	return profile, nil
}

func (p ConsensusProfile) validate() error {
	if p.MaxGroupSize == 0 || p.MinTxnFee == 0 || p.SizeUnit == 0 || p.MaxProgramBytes == 0 || p.OpcodeUnit == 0 {
		return fmt.Errorf("%w: consensus resource unit is zero", ErrInvalidUsage)
	}
	return nil
}
