// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"maps"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// Config is the effective policy compiled from one document: a node's
// default, or one key's own policy. A key is governed by exactly one Config;
// there is no inheritance between documents.
type Config struct {
	Role noderole.Role
	// Rekeys is the signer role's rekey rejection. A value that is not one of
	// the three settings rejects every rekey, so a Config never given one fails
	// closed. The cosigner role ignores it.
	Rekeys                      SignerRekeys
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
		Rekeys:               RekeysRejectForeign,
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
	cp.TransactionTypes = maps.Clone(c.TransactionTypes)
	cp.MaxASAAmounts = cloneASAAmounts(c.MaxASAAmounts)
	cp.ReviewASAAmounts = cloneASAAmounts(c.ReviewASAAmounts)
	cp.MaxAlgoPayments = maps.Clone(c.MaxAlgoPayments)
	cp.ReviewAlgoPayments = maps.Clone(c.ReviewAlgoPayments)
	cp.TransferPolicy = c.TransferPolicy.Clone()
	cp.RekeyPolicy = c.RekeyPolicy.Clone()
	return &cp
}

func cloneASAAmounts(in map[string]map[uint64]uint64) map[string]map[uint64]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]map[uint64]uint64, len(in))
	for network, limits := range in {
		out[network] = maps.Clone(limits)
	}
	return out
}
