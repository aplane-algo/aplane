// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Config is the effective policy compiled from one document: a node's
// default, or one key's own policy. A key is governed by exactly one Config;
// there is no inheritance between documents.
type Config struct {
	Role                        noderole.Role
	RejectForeignRekey          bool
	RejectRekey                 bool
	RejectCloseRemainder        bool
	RejectAssetClose            bool
	RejectClawback              bool
	AlwaysReviewWarnings        bool
	AutoApproveSelfNoOpTransfer bool
	MaxFeeMicroAlgos            uint64
	// TransactionTypes is the per-type verdict map. A nil map rejects every
	// type: a Config that was never given one fails closed.
	TransactionTypes    TransactionTypesV1
	ReviewAlgoPayments  map[string]uint64
	MaxAlgoPayments     map[string]uint64
	ReviewASAAmounts    map[string]map[uint64]uint64
	MaxASAAmounts       map[string]map[uint64]uint64
	TransferPolicy      *TransferPolicy
	RekeyPolicy         *RekeyPolicy
	GenesisHashResolver apconfig.GenesisHashNetworkResolver
	FormatASAAmount     func(network string, assetID uint64, raw uint64) (string, bool)
}

// DefaultConfig returns the base a document is compiled onto: the runtime
// context (genesis-hash resolver, amount formatter) plus the product
// defaults a test may rely on when it builds a Config by hand. Every verdict
// field is replaced when a document compiles; nothing here reaches a key on
// its own. TransactionTypes allows every type so a hand-built Config is
// unconstrained by type unless the test says otherwise.
func DefaultConfig() *Config {
	return DefaultConfigWithGenesisHashResolver(apconfig.DefaultGenesisHashNetworkResolver())
}

// DefaultConfigWithGenesisHashResolver returns DefaultConfig with the given
// genesis-hash-to-network resolver.
func DefaultConfigWithGenesisHashResolver(resolver apconfig.GenesisHashNetworkResolver) *Config {
	return &Config{
		Role:                 noderole.RoleSigner,
		RejectForeignRekey:   true,
		RejectCloseRemainder: false,
		RejectAssetClose:     false,
		RejectClawback:       false,
		TransactionTypes:     TransactionTypesV1{TransactionTypeWildcard: TransactionTypeAllow},
		ReviewAlgoPayments:   make(map[string]uint64),
		MaxAlgoPayments:      make(map[string]uint64),
		ReviewASAAmounts:     make(map[string]map[uint64]uint64),
		MaxASAAmounts:        make(map[string]map[uint64]uint64),
		GenesisHashResolver:  resolver,
	}
}

// VerdictForType returns the policy's verdict for a transaction type. A
// Config with no TransactionTypes map rejects every type.
func (c *Config) VerdictForType(txType types.TxType) TransactionTypeVerdict {
	if c == nil {
		return TransactionTypeReject
	}
	return c.TransactionTypes.Verdict(string(txType))
}

// Clone returns a deep copy of the policy config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	cp := *c
	cp.TransactionTypes = c.TransactionTypes.Clone()
	if c.MaxASAAmounts != nil {
		cp.MaxASAAmounts = cloneASAAmounts(c.MaxASAAmounts)
	}
	if c.ReviewASAAmounts != nil {
		cp.ReviewASAAmounts = cloneASAAmounts(c.ReviewASAAmounts)
	}
	if c.MaxAlgoPayments != nil {
		cp.MaxAlgoPayments = cloneUintMap(c.MaxAlgoPayments)
	}
	if c.ReviewAlgoPayments != nil {
		cp.ReviewAlgoPayments = cloneUintMap(c.ReviewAlgoPayments)
	}
	if c.TransferPolicy != nil {
		cp.TransferPolicy = c.TransferPolicy.Clone()
	}
	if c.RekeyPolicy != nil {
		cp.RekeyPolicy = c.RekeyPolicy.Clone()
	}
	return &cp
}

func cloneUintMap(in map[string]uint64) map[string]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]uint64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneASAAmounts(in map[string]map[uint64]uint64) map[string]map[uint64]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]map[uint64]uint64, len(in))
	for network, limits := range in {
		if limits == nil {
			out[network] = nil
			continue
		}
		copied := make(map[uint64]uint64, len(limits))
		for assetID, amount := range limits {
			copied[assetID] = amount
		}
		out[network] = copied
	}
	return out
}
