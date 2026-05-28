// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

type TransferMovementKind string

const (
	TransferMovementPay        TransferMovementKind = "pay"
	TransferMovementPayClose   TransferMovementKind = "pay_close"
	TransferMovementAxfer      TransferMovementKind = "axfer"
	TransferMovementAxferOptIn TransferMovementKind = "axfer_optin"
	TransferMovementAssetClose TransferMovementKind = "asset_close"
	TransferMovementClawback   TransferMovementKind = "clawback"
)

type TransferAssetRef struct {
	Algo  bool
	ASAID uint64
}

type TransferMovement struct {
	Kind        TransferMovementKind
	Network     string
	Source      types.Address
	AssetSource types.Address
	Asset       TransferAssetRef
	Destination types.Address
	Amount      uint64
	AmountKnown bool
}

type transferRoutingTier int

const (
	transferRoutingNone transferRoutingTier = iota
	transferRoutingReview
	transferRoutingDeny
)

type transferRoutingVerdict struct {
	Tier   transferRoutingTier
	RuleID string
	Msg    string
}

// ExtractTransferMovements converts direct pay and axfer transactions into the
// movement model used by transfer routing. Other transaction types are out of
// scope and produce no movements.
func ExtractTransferMovements(txn types.Transaction) []TransferMovement {
	switch txn.Type {
	case types.PaymentTx:
		return extractPaymentMovements(txn)
	case types.AssetTransferTx:
		return extractAssetTransferMovements(txn)
	default:
		return nil
	}
}

// CheckTxnTransferRoutingPolicyLints evaluates transfer routing outcomes that
// hard-reject the transaction.
func CheckTxnTransferRoutingPolicyLints(txn types.Transaction, cfg *Config, routingExempt bool) []LintViolation {
	verdicts := evaluateTransferRouting(txn, cfg, routingExempt)
	out := make([]LintViolation, 0, len(verdicts))
	for _, verdict := range verdicts {
		if verdict.Tier != transferRoutingDeny {
			continue
		}
		out = append(out, LintViolation{
			RuleID:   verdict.RuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  verdict.Msg,
		})
	}
	return out
}

// CheckTxnTransferRoutingReviewPolicyLints evaluates transfer routing outcomes
// that force operator review after hard-reject policy has passed.
func CheckTxnTransferRoutingReviewPolicyLints(txn types.Transaction, cfg *Config, routingExempt bool) []LintViolation {
	verdicts := evaluateTransferRouting(txn, cfg, routingExempt)
	out := make([]LintViolation, 0, len(verdicts))
	for _, verdict := range verdicts {
		if verdict.Tier != transferRoutingReview {
			continue
		}
		out = append(out, LintViolation{
			RuleID:   verdict.RuleID,
			Scope:    "txn",
			TxnIndex: -1,
			Message:  verdict.Msg,
		})
	}
	return out
}

func extractPaymentMovements(txn types.Transaction) []TransferMovement {
	movements := []TransferMovement{{
		Kind:        TransferMovementPay,
		Source:      txn.Sender,
		Asset:       TransferAssetRef{Algo: true},
		Destination: txn.Receiver,
		Amount:      uint64(txn.Amount),
		AmountKnown: true,
	}}
	if !txn.CloseRemainderTo.IsZero() {
		movements = append(movements, TransferMovement{
			Kind:        TransferMovementPayClose,
			Source:      txn.Sender,
			Asset:       TransferAssetRef{Algo: true},
			Destination: txn.CloseRemainderTo,
			AmountKnown: false,
		})
	}
	return movements
}

func extractAssetTransferMovements(txn types.Transaction) []TransferMovement {
	asset := TransferAssetRef{ASAID: uint64(txn.XferAsset)}
	isClawback := !txn.AssetSender.IsZero() && txn.AssetSender != txn.Sender
	if isClawback {
		movements := []TransferMovement{{
			Kind:        TransferMovementClawback,
			Source:      txn.Sender,
			AssetSource: txn.AssetSender,
			Asset:       asset,
			Destination: txn.AssetReceiver,
			Amount:      txn.AssetAmount,
			AmountKnown: true,
		}}
		if !txn.AssetCloseTo.IsZero() {
			movements = append(movements, TransferMovement{
				Kind:        TransferMovementAssetClose,
				Source:      txn.AssetSender,
				Asset:       asset,
				Destination: txn.AssetCloseTo,
				AmountKnown: false,
			})
		}
		return movements
	}

	kind := TransferMovementAxfer
	if txn.AssetReceiver == txn.Sender &&
		txn.AssetAmount == 0 &&
		txn.AssetSender.IsZero() &&
		txn.AssetCloseTo.IsZero() {
		kind = TransferMovementAxferOptIn
	}
	movements := []TransferMovement{{
		Kind:        kind,
		Source:      txn.Sender,
		Asset:       asset,
		Destination: txn.AssetReceiver,
		Amount:      txn.AssetAmount,
		AmountKnown: true,
	}}
	if !txn.AssetCloseTo.IsZero() {
		movements = append(movements, TransferMovement{
			Kind:        TransferMovementAssetClose,
			Source:      txn.Sender,
			Asset:       asset,
			Destination: txn.AssetCloseTo,
			AmountKnown: false,
		})
	}
	return movements
}

func evaluateTransferRouting(txn types.Transaction, cfg *Config, routingExempt bool) []transferRoutingVerdict {
	if cfg == nil || cfg.TransferPolicy == nil || !cfg.TransferPolicy.Enabled || routingExempt {
		return nil
	}
	movements := ExtractTransferMovements(txn)
	if len(movements) == 0 {
		return nil
	}
	network := networkFromGenesisHash(txn.GenesisHash, cfg.GenesisHashResolver)
	out := make([]transferRoutingVerdict, 0, len(movements))
	for _, movement := range movements {
		movement.Network = network
		if verdict, ok := blockedDestinationVerdict(movement, cfg.TransferPolicy); ok {
			out = append(out, verdict)
			continue
		}
		if network == "" {
			if verdict, ok := routeMissVerdict(cfg.TransferPolicy, TransferRoutingUnknownGenesisRuleID, "cannot evaluate transfer routing for unknown genesis hash"); ok {
				out = append(out, verdict)
			}
			continue
		}
		if verdict, ok := evaluateTransferMovement(movement, cfg.TransferPolicy); ok {
			out = append(out, verdict)
		}
	}
	return out
}

func blockedDestinationVerdict(movement TransferMovement, tp *TransferPolicy) (transferRoutingVerdict, bool) {
	if len(tp.BlockedDestinations) == 0 || movement.Kind == TransferMovementAxferOptIn {
		return transferRoutingVerdict{}, false
	}
	if _, ok := tp.BlockedDestinations[movement.Destination]; !ok {
		return transferRoutingVerdict{}, false
	}
	return transferRoutingVerdict{
		Tier:   transferRoutingDeny,
		RuleID: TransferRoutingBlockedDestinationRuleID,
		Msg:    fmt.Sprintf("transfer routing rejected blocked destination %s for %s movement", movement.Destination, movement.Kind),
	}, true
}

func evaluateTransferMovement(movement TransferMovement, tp *TransferPolicy) (transferRoutingVerdict, bool) {
	matches := matchingTransferRoutes(movement, tp)
	if len(matches) == 0 {
		switch {
		case isCloseMovement(movement.Kind):
			return routeMissVerdictFor(
				tp.CloseOnNoRoute,
				TransferRoutingCloseRejectedRuleID,
				TransferRoutingCloseRouteMissRuleID,
				fmt.Sprintf("transfer routing found no close.allow route for %s movement", movement.Kind),
			)
		case movement.Kind == TransferMovementClawback:
			return routeMissVerdictFor(
				tp.ClawbackOnNoRoute,
				TransferRoutingClawbackRejectedRuleID,
				TransferRoutingClawbackRouteMissRuleID,
				"transfer routing found no clawback.allow route for clawback movement",
			)
		default:
			return routeMissVerdict(tp, TransferRoutingRouteMissRuleID, fmt.Sprintf("transfer routing found no route for %s movement", movement.Kind))
		}
	}
	if isCloseMovement(movement.Kind) && !anyRouteAllowsClose(matches) {
		return transferRoutingVerdict{
			Tier:   transferRoutingDeny,
			RuleID: closeRejectedRuleID(matches),
			Msg:    fmt.Sprintf("transfer routing rejected %s movement without close.allow route", movement.Kind),
		}, true
	}
	if movement.Kind == TransferMovementClawback && !anyRouteAllowsClawback(matches) {
		return transferRoutingVerdict{
			Tier:   transferRoutingDeny,
			RuleID: clawbackRejectedRuleID(matches),
			Msg:    "transfer routing rejected clawback movement without clawback.allow route",
		}, true
	}
	if movement.AmountKnown {
		if route, threshold, ok := aggregatedRejectThreshold(matches, movement.Network); ok && movement.Amount > threshold {
			return transferRoutingVerdict{
				Tier:   transferRoutingDeny,
				RuleID: TransferRoutingRouteRuleID(route.ID, TransferRoutingRejectAboveOutcome),
				Msg:    fmt.Sprintf("transfer routing amount %d exceeds reject threshold %d", movement.Amount, threshold),
			}, true
		}
		if route, threshold, ok := aggregatedReviewThreshold(matches, movement.Network); ok && movement.Amount > threshold {
			return transferRoutingVerdict{
				Tier:   transferRoutingReview,
				RuleID: TransferRoutingRouteRuleID(route.ID, TransferRoutingReviewAboveOutcome),
				Msg:    fmt.Sprintf("transfer routing amount %d exceeds review threshold %d", movement.Amount, threshold),
			}, true
		}
	}
	return transferRoutingVerdict{}, false
}

func routeMissVerdict(tp *TransferPolicy, ruleID, msg string) (transferRoutingVerdict, bool) {
	return routeMissVerdictFor(tp.OnNoRoute, ruleID, ruleID, msg)
}

func routeMissVerdictFor(action TransferOnNoRoute, rejectRuleID, reviewRuleID, msg string) (transferRoutingVerdict, bool) {
	switch action {
	case TransferOnNoRouteReject:
		return transferRoutingVerdict{Tier: transferRoutingDeny, RuleID: rejectRuleID, Msg: msg}, true
	case TransferOnNoRouteReview:
		return transferRoutingVerdict{Tier: transferRoutingReview, RuleID: reviewRuleID, Msg: msg}, true
	default:
		return transferRoutingVerdict{}, false
	}
}

func matchingTransferRoutes(movement TransferMovement, tp *TransferPolicy) []CompiledTransferRoute {
	var matches []CompiledTransferRoute
	for _, route := range tp.Routes {
		if !route.Enabled {
			continue
		}
		if !routeMatchesNetwork(route, movement.Network) {
			continue
		}
		if !addressTermsMatch(route.Sources, tp.AddressSets, movement.Network, movement.Source, movement.Source) {
			continue
		}
		if !assetTermsMatch(route.Assets, tp.AssetSets, movement.Network, movement.Asset) {
			continue
		}
		if !addressTermsMatch(route.Destinations, tp.AddressSets, movement.Network, movement.Destination, movement.Source) {
			continue
		}
		if movement.Kind == TransferMovementClawback {
			if !addressTermsMatch(route.AssetSources, tp.AddressSets, movement.Network, movement.AssetSource, movement.Source) {
				continue
			}
		} else if len(route.AssetSources.Direct) > 0 || len(route.AssetSources.Sets) > 0 || route.AssetSources.Wildcard || route.AssetSources.Self {
			continue
		}
		matches = append(matches, route)
	}
	return matches
}

func routeMatchesNetwork(route CompiledTransferRoute, network string) bool {
	if network == "" {
		return false
	}
	if route.NetworkWildcard {
		return true
	}
	_, ok := route.Networks[network]
	return ok
}

func addressTermsMatch(terms compiledAddressTerms, sets map[string]compiledAddressSet, network string, candidate, self types.Address) bool {
	if terms.Wildcard {
		return true
	}
	if terms.Self && candidate == self {
		return true
	}
	for _, addr := range terms.Direct {
		if candidate == addr {
			return true
		}
	}
	for _, setName := range terms.Sets {
		if addressSetContains(sets[setName], network, candidate) {
			return true
		}
	}
	return false
}

func addressSetContains(set compiledAddressSet, network string, candidate types.Address) bool {
	for _, addr := range set.Flat {
		if candidate == addr {
			return true
		}
	}
	for _, addr := range set.ByNetwork[network] {
		if candidate == addr {
			return true
		}
	}
	return false
}

func assetTermsMatch(terms compiledAssetTerms, sets map[string]compiledAssetSet, network string, candidate TransferAssetRef) bool {
	if terms.Wildcard {
		return true
	}
	if candidate.Algo {
		return terms.Algo
	}
	for _, id := range terms.ASAIDs {
		if candidate.ASAID == id {
			return true
		}
	}
	for _, setName := range terms.Sets {
		for _, id := range sets[setName].ByNetwork[network] {
			if candidate.ASAID == id {
				return true
			}
		}
	}
	return false
}

func anyRouteAllowsClose(routes []CompiledTransferRoute) bool {
	for _, route := range routes {
		if route.AllowClose {
			return true
		}
	}
	return false
}

func anyRouteAllowsClawback(routes []CompiledTransferRoute) bool {
	for _, route := range routes {
		if route.AllowClawback {
			return true
		}
	}
	return false
}

func aggregatedRejectThreshold(routes []CompiledTransferRoute, network string) (CompiledTransferRoute, uint64, bool) {
	return aggregateThreshold(routes, network, func(limits AmountLimits) *uint64 { return limits.RejectAbove })
}

func aggregatedReviewThreshold(routes []CompiledTransferRoute, network string) (CompiledTransferRoute, uint64, bool) {
	return aggregateThreshold(routes, network, func(limits AmountLimits) *uint64 { return limits.ReviewAbove })
}

func aggregateThreshold(routes []CompiledTransferRoute, network string, pick func(AmountLimits) *uint64) (CompiledTransferRoute, uint64, bool) {
	var selected CompiledTransferRoute
	var selectedThreshold uint64
	found := false
	for _, route := range routes {
		limits, ok := effectiveRouteLimits(route, network)
		if !ok {
			continue
		}
		threshold := pick(limits)
		if threshold == nil {
			continue
		}
		if !found || *threshold < selectedThreshold {
			selected = route
			selectedThreshold = *threshold
			found = true
		}
	}
	return selected, selectedThreshold, found
}

func effectiveRouteLimits(route CompiledTransferRoute, network string) (AmountLimits, bool) {
	if limits, ok := route.LimitsByNetwork[network]; ok {
		return limits, true
	}
	if route.Limits != nil {
		return *route.Limits, true
	}
	return AmountLimits{}, false
}

func isCloseMovement(kind TransferMovementKind) bool {
	return kind == TransferMovementPayClose || kind == TransferMovementAssetClose
}

func closeRejectedRuleID(routes []CompiledTransferRoute) string {
	if len(routes) == 0 {
		return TransferRoutingCloseRejectedRuleID
	}
	return TransferRoutingRouteRuleID(routes[0].ID, TransferRoutingCloseRejectedOutcome)
}

func clawbackRejectedRuleID(routes []CompiledTransferRoute) string {
	if len(routes) == 0 {
		return TransferRoutingClawbackRejectedRuleID
	}
	return TransferRoutingRouteRuleID(routes[0].ID, TransferRoutingClawbackRejectedOutcome)
}
