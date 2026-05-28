// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

const (
	ConfigAdvisorySeverityWarning = "warning"

	ConfigAdvisoryRejectCloseRemainderRouteOverlap = "policy_overlap:reject_close_remainder:route_close_allow"
	ConfigAdvisoryRejectAssetCloseRouteOverlap     = "policy_overlap:reject_asset_close:route_close_allow"
	ConfigAdvisoryRejectClawbackRouteOverlap       = "policy_overlap:reject_clawback:route_clawback_allow"
)

// ConfigAdvisory is a non-fatal policy-model warning. It reports confusing or
// redundant stored policy shapes without changing load/evaluation behavior.
type ConfigAdvisory struct {
	RuleID   string
	Scope    string
	Severity string
	Message  string
}

// CheckStoredConfigAdvisories reports policy shapes that are valid but can
// surprise users because one policy layer cannot weaken another. In particular,
// route-level close/clawback permissions do not override top-level reject
// booleans.
func CheckStoredConfigAdvisories(stored *StoredConfig) []ConfigAdvisory {
	if stored == nil || stored.TransferPolicy == nil || len(stored.TransferPolicy.Routes) == 0 {
		return nil
	}
	var out []ConfigAdvisory
	if boolPtrValue(stored.RejectCloseRemainder) && anyStoredRouteAllowsClose(stored.TransferPolicy.Routes) {
		out = append(out, ConfigAdvisory{
			RuleID:   ConfigAdvisoryRejectCloseRemainderRouteOverlap,
			Scope:    "policy",
			Severity: ConfigAdvisorySeverityWarning,
			Message:  "reject_close_remainder still rejects ALGO close-out even when a transfer route sets close.allow:true",
		})
	}
	if boolPtrValue(stored.RejectAssetClose) && anyStoredRouteAllowsClose(stored.TransferPolicy.Routes) {
		out = append(out, ConfigAdvisory{
			RuleID:   ConfigAdvisoryRejectAssetCloseRouteOverlap,
			Scope:    "policy",
			Severity: ConfigAdvisorySeverityWarning,
			Message:  "reject_asset_close still rejects ASA close-out even when a transfer route sets close.allow:true",
		})
	}
	if boolPtrValue(stored.RejectClawback) && anyStoredRouteAllowsClawback(stored.TransferPolicy.Routes) {
		out = append(out, ConfigAdvisory{
			RuleID:   ConfigAdvisoryRejectClawbackRouteOverlap,
			Scope:    "policy",
			Severity: ConfigAdvisorySeverityWarning,
			Message:  "reject_clawback still rejects clawback transactions even when a transfer route sets clawback.allow:true",
		})
	}
	return out
}

func boolPtrValue(v *bool) bool {
	return v != nil && *v
}

func anyStoredRouteAllowsClose(routes []StoredTransferRoute) bool {
	for _, route := range routes {
		if boolPtrValue(route.Close.Allow) {
			return true
		}
	}
	return false
}

func anyStoredRouteAllowsClawback(routes []StoredTransferRoute) bool {
	for _, route := range routes {
		if boolPtrValue(route.Clawback.Allow) {
			return true
		}
	}
	return false
}
