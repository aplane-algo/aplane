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

// CurrentConsensusVersion is the compiled authorization contract used by the
// signer. V43 retains v42's authorization and resource rules; its close-out
// change is enforced by algod and client preflight. Supporting another protocol
// requires review here; versions are never ordered or inferred at runtime.
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

// ResolveConsensus accepts only the reviewed v42 and v43 identifiers and returns
// the corresponding compiled planning profile, preserving the reported version.
func ResolveConsensus(version string) (ConsensusProfile, error) {
	consensusVersion := protocol.ConsensusVersion(version)
	switch consensusVersion {
	case protocol.ConsensusV42, protocol.ConsensusV43:
		return consensusProfile(consensusVersion)
	default:
		return ConsensusProfile{}, fmt.Errorf("%w: %q", ErrUnknownConsensus, version)
	}
}

// CurrentConsensus returns the compiled planning contract shared by v42 and v43.
func CurrentConsensus() (ConsensusProfile, error) {
	return consensusProfile(CurrentConsensusVersion)
}

func consensusProfile(version protocol.ConsensusVersion) (ConsensusProfile, error) {
	params, ok := sdkconfig.Consensus[version]
	if !ok {
		return ConsensusProfile{}, fmt.Errorf("%w: SDK has no parameters for %q", ErrUnknownConsensus, version)
	}
	profile := ConsensusProfile{
		Version:                version,
		MaxGroupSize:           uint64(params.MaxTxGroupSize),
		MinTxnFee:              params.MinTxnFee,
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
	if p.MaxGroupSize == 0 || p.MinTxnFee == 0 || p.SizeUnit == 0 || p.MaxProgramBytes == 0 || p.OpcodeUnit == 0 {
		return fmt.Errorf("%w: consensus resource unit is zero", ErrInvalidUsage)
	}
	return nil
}
