// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aplane-algo/aplane/internal/noderole"
)

const (
	ConfigAdvisorySeverityWarning = "warning"

	ConfigAdvisoryRejectCloseRemainderRouteOverlap = "policy_overlap:reject_close_remainder:route_close_allow"
	ConfigAdvisoryRejectAssetCloseRouteOverlap     = "policy_overlap:reject_asset_close:route_close_allow"
	ConfigAdvisoryRejectClawbackRouteOverlap       = "policy_overlap:reject_clawback:route_clawback_allow"
	// ConfigAdvisoryRejectedTypeRouted reports a route for a transfer type
	// the document's transaction_types rejects; the route can never match.
	ConfigAdvisoryRejectedTypeRouted = "policy_overlap:transaction_types:route_unreachable"
	// ConfigAdvisoryCosignerNoFeeCap reports a cosigner document that lets the
	// cosigner sign, through a route or a type allowed without routing, but
	// caps no fee: a cosigner has no warning review, so a transaction it signs
	// can carry any fee.
	ConfigAdvisoryCosignerNoFeeCap = "policy_fee:cosigner_routes_without_fee_cap"
	// ConfigAdvisoryCosignerTypeWithoutRouting reports a cosigner document
	// that allows a type transfer routing doesn't govern: nothing but the type
	// verdict stands behind it.
	ConfigAdvisoryCosignerTypeWithoutRouting = "policy_scope:cosigner_type_without_routing"
	// ConfigAdvisoryRekeyPolicyAnyTarget reports a rekey rule whose targets
	// include "*".
	ConfigAdvisoryRekeyPolicyAnyTarget = "policy_scope:rekey_policy_any_target"
	// ConfigAdvisoryRouteCloseToAnyAddress reports a route that allows
	// close-out to a wildcard destination.
	ConfigAdvisoryRouteCloseToAnyAddress = "policy_scope:route_close_to_any_address"
)

// ConfigAdvisory is a non-fatal policy-model warning. It reports confusing or
// redundant stored policy shapes without changing load/evaluation behavior.
// Pointer is the JSON Pointer of the field an author would change to resolve
// it; "" means the document as a whole.
type ConfigAdvisory struct {
	RuleID   string
	Pointer  string
	Severity string
	Message  string
}

// Advisories reports policy shapes that are valid but worth a second look.
// Some can surprise because one policy layer cannot weaken another: a route
// that allows close-out or clawback does not override a reject_* setting, and
// a route for a transaction type the document rejects never matches. Others
// say what a wide choice means: a cosigner type with no routing behind it, a
// rekey rule open to any target, a route that closes out to any address. An
// advisory never refuses the document.
func (d *PolicyV1) Advisories() []ConfigAdvisory {
	if d == nil {
		return nil
	}
	var out []ConfigAdvisory
	add := func(ruleID, pointer, message string) {
		out = append(out, ConfigAdvisory{RuleID: ruleID, Pointer: pointer, Severity: ConfigAdvisorySeverityWarning, Message: message})
	}
	allowsClose, allowsClawback := false, false
	for _, route := range d.Routes {
		allowsClose = allowsClose || route.AllowClose
		allowsClawback = allowsClawback || route.AllowClawback
	}
	if d.RejectCloseRemainder && allowsClose {
		add(ConfigAdvisoryRejectCloseRemainderRouteOverlap, "/reject_close_remainder", "reject_close_remainder still rejects ALGO close-out even when a route sets allow_close")
	}
	if d.RejectAssetClose && allowsClose {
		add(ConfigAdvisoryRejectAssetCloseRouteOverlap, "/reject_asset_close", "reject_asset_close still rejects ASA close-out even when a route sets allow_close")
	}
	if d.RejectClawback && allowsClawback {
		add(ConfigAdvisoryRejectClawbackRouteOverlap, "/reject_clawback", "reject_clawback still rejects clawback even when a route sets allow_clawback")
	}
	if len(d.Routes) > 0 {
		var rejected []string
		for _, txType := range []string{"pay", "axfer"} {
			if d.TransactionTypes.Verdict(txType) == TransactionTypeReject {
				rejected = append(rejected, txType)
			}
		}
		if len(rejected) > 0 {
			add(ConfigAdvisoryRejectedTypeRouted, "/transaction_types", fmt.Sprintf("transaction_types rejects %s, so no route can match that type", strings.Join(rejected, " and ")))
		}
	}
	if d.Role == noderole.RoleCosigner {
		// The types the document allows that transfer routing doesn't govern.
		// A "*" allow also covers any type a later release adds, which no list
		// of today's names can show.
		var unrouted []string
		for _, txType := range TransactionTypeNames {
			if !transferTransactionTypes[txType] && d.TransactionTypes.Verdict(txType) == TransactionTypeAllow {
				unrouted = append(unrouted, txType)
			}
		}
		wildcardAllows := d.TransactionTypes[TransactionTypeWildcard] == TransactionTypeAllow
		switch {
		case wildcardAllows:
			today := "none of today's types"
			if len(unrouted) > 0 {
				today = "today: " + strings.Join(unrouted, ", ")
			}
			add(ConfigAdvisoryCosignerTypeWithoutRouting, "/transaction_types", fmt.Sprintf(
				`"*" allows every type the map doesn't reject, including any type added later (%s); other than pay and axfer they have no routing behind them, and the cosigner authorizes them on type alone`, today))
		case len(unrouted) == 1:
			add(ConfigAdvisoryCosignerTypeWithoutRouting, "/transaction_types", fmt.Sprintf(
				"%s is allowed with no routing behind it; the cosigner authorizes it on type alone", unrouted[0]))
		case len(unrouted) > 1:
			add(ConfigAdvisoryCosignerTypeWithoutRouting, "/transaction_types", fmt.Sprintf(
				"%s are allowed with no routing behind them; the cosigner authorizes them on type alone", strings.Join(unrouted, ", ")))
		}
		// A cosigner has no warning review, so nothing else questions a fee.
		// It signs whenever a route permits a movement, a type is allowed
		// without routing, or a rekey rule can match.
		rekeysCanMatch := !d.RejectRekey && len(d.RekeyPolicy) > 0 && d.TransactionTypes.Verdict("pay") == TransactionTypeAllow
		if d.MaxFeeMicroAlgos == 0 && (len(d.Routes) > 0 || wildcardAllows || len(unrouted) > 0 || rekeysCanMatch) {
			add(ConfigAdvisoryCosignerNoFeeCap, "/max_fee_microalgos", "this document lets the cosigner sign, but max_fee_microalgos is 0 (no cap); a cosigner has no warning review, so a transaction it signs can carry any fee")
		}
	}
	// An advisory describes what the document does, so an open rule is only
	// reported when a rekey can reach it: reject_rekey rejects every rekey,
	// and a cosigned rekey is a payment, which transaction_types must allow.
	if !d.RejectRekey && d.TransactionTypes.Verdict("pay") == TransactionTypeAllow {
		for i, rule := range d.RekeyPolicy {
			if slices.Contains(rule.Targets, "*") {
				sender := rule.Sender
				if sender == "*" {
					sender = "any sender"
				}
				add(ConfigAdvisoryRekeyPolicyAnyTarget, fmt.Sprintf("/rekey_policy/allowed/%d/targets", i),
					fmt.Sprintf("rekey_policy lets %s rekey to any address", sender))
			}
		}
	}
	// Likewise a route's allow_close is only reported when a close-out it
	// covers can pass: reject_close_remainder stops an ALGO close-out and
	// reject_asset_close an ASA one. The overlap advisories above report a
	// route whose allow_close is overridden.
	for i, route := range d.Routes {
		if !route.AllowClose || !slices.Contains(route.Destinations, "*") {
			continue
		}
		coversAlgo, coversASA := routeAssetKinds(route.Assets)
		if (coversAlgo && !d.RejectCloseRemainder) || (coversASA && !d.RejectAssetClose) {
			add(ConfigAdvisoryRouteCloseToAnyAddress, fmt.Sprintf("/transfer_policy/routes/%d/allow_close", i),
				"this route lets any matching account be closed out to any address; a close-out moves the whole balance, and the route's limits don't bound it")
		}
	}
	return out
}

// routeAssetKinds reports whether a route's asset terms can cover ALGO and
// can cover an ASA. A wildcard or a set may cover either.
func routeAssetKinds(assets []string) (algo, asa bool) {
	for _, term := range assets {
		switch {
		case term == "*" || strings.HasPrefix(term, "@"):
			return true, true
		case term == "algo":
			algo = true
		default:
			asa = true
		}
	}
	return algo, asa
}
