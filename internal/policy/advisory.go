// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
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
	// ConfigAdvisoryCosignerNoFeeCap reports a cosigner document that allows
	// movements but caps no fee: a cosigner has no warning review, so a
	// permitted self-payment can carry any fee.
	ConfigAdvisoryCosignerNoFeeCap = "policy_fee:cosigner_routes_without_fee_cap"
)

// ConfigAdvisory is a non-fatal policy-model warning. It reports confusing or
// redundant stored policy shapes without changing load/evaluation behavior.
type ConfigAdvisory struct {
	RuleID   string
	Scope    string
	Severity string
	Message  string
}

// Advisories reports policy shapes that are valid but can surprise users
// because one policy layer cannot weaken another: a route that allows
// close-out or clawback does not override a reject_* setting, and a route
// for a transaction type the document rejects never matches.
func (d *PolicyV1) Advisories() []ConfigAdvisory {
	if d == nil {
		return nil
	}
	var out []ConfigAdvisory
	add := func(ruleID, message string) {
		out = append(out, ConfigAdvisory{RuleID: ruleID, Scope: "policy", Severity: ConfigAdvisorySeverityWarning, Message: message})
	}
	allowsClose, allowsClawback := false, false
	for _, route := range d.Routes {
		allowsClose = allowsClose || route.AllowClose
		allowsClawback = allowsClawback || route.AllowClawback
	}
	if d.RejectCloseRemainder && allowsClose {
		add(ConfigAdvisoryRejectCloseRemainderRouteOverlap, "reject_close_remainder still rejects ALGO close-out even when a route sets allow_close")
	}
	if d.RejectAssetClose && allowsClose {
		add(ConfigAdvisoryRejectAssetCloseRouteOverlap, "reject_asset_close still rejects ASA close-out even when a route sets allow_close")
	}
	if d.RejectClawback && allowsClawback {
		add(ConfigAdvisoryRejectClawbackRouteOverlap, "reject_clawback still rejects clawback even when a route sets allow_clawback")
	}
	if len(d.Routes) > 0 {
		var rejected []string
		for _, txType := range []string{"pay", "axfer"} {
			if d.TransactionTypes.Verdict(txType) == TransactionTypeReject {
				rejected = append(rejected, txType)
			}
		}
		if len(rejected) > 0 {
			add(ConfigAdvisoryRejectedTypeRouted, fmt.Sprintf("transaction_types rejects %s, so no route can match that type", strings.Join(rejected, " and ")))
		}
		if d.Role == noderole.RoleCosigner && d.MaxFeeMicroAlgos == 0 {
			add(ConfigAdvisoryCosignerNoFeeCap, "routes permit movements but max_fee_microalgos is 0 (no cap); a cosigner has no warning review, so a permitted self-payment can carry any fee")
		}
	}
	return out
}
