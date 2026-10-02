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

// Advisories reports signer policy shapes that are valid but can surprise
// users because one policy layer cannot weaken another: a route that allows
// close-out or clawback does not override a reject_* setting. Key overrides
// are checked with their inherited settings.
func (d *SignerPolicyV1) Advisories() []ConfigAdvisory {
	if d == nil || d.TransferPolicy == nil {
		return nil
	}
	out := routeOverlapAdvisories("policy", d.SignerSettingsV1, d.TransferPolicy.Routes)
	for _, key := range sortedKeys(d.KeyOverrides) {
		effective := d.SignerSettingsV1
		ov := d.KeyOverrides[key].SignerSettingsV1
		for _, f := range []struct{ dst, src **bool }{
			{&effective.RejectCloseRemainder, &ov.RejectCloseRemainder},
			{&effective.RejectAssetClose, &ov.RejectAssetClose},
			{&effective.RejectClawback, &ov.RejectClawback},
		} {
			if *f.src != nil {
				*f.dst = *f.src
			}
		}
		out = append(out, routeOverlapAdvisories("key_overrides/"+key, effective, d.TransferPolicy.Routes)...)
	}
	return dedupeAdvisories(out)
}

// Advisories reports cosigner policy shapes that are valid but can surprise
// users; see SignerPolicyV1.Advisories.
func (d *CosignerPolicyV1) Advisories() []ConfigAdvisory {
	if d == nil {
		return nil
	}
	return routeOverlapAdvisories("policy", SignerSettingsV1{
		RejectCloseRemainder: d.RejectCloseRemainder,
		RejectAssetClose:     d.RejectAssetClose,
		RejectClawback:       d.RejectClawback,
	}, d.Routes)
}

func routeOverlapAdvisories(scope string, settings SignerSettingsV1, routes []RouteV1) []ConfigAdvisory {
	allowsClose, allowsClawback := false, false
	for _, route := range routes {
		allowsClose = allowsClose || route.AllowClose
		allowsClawback = allowsClawback || route.AllowClawback
	}
	var out []ConfigAdvisory
	add := func(ruleID, message string) {
		out = append(out, ConfigAdvisory{RuleID: ruleID, Scope: scope, Severity: ConfigAdvisorySeverityWarning, Message: message})
	}
	if boolPtrValue(settings.RejectCloseRemainder) && allowsClose {
		add(ConfigAdvisoryRejectCloseRemainderRouteOverlap, "reject_close_remainder still rejects ALGO close-out even when a route sets allow_close")
	}
	if boolPtrValue(settings.RejectAssetClose) && allowsClose {
		add(ConfigAdvisoryRejectAssetCloseRouteOverlap, "reject_asset_close still rejects ASA close-out even when a route sets allow_close")
	}
	if boolPtrValue(settings.RejectClawback) && allowsClawback {
		add(ConfigAdvisoryRejectClawbackRouteOverlap, "reject_clawback still rejects clawback even when a route sets allow_clawback")
	}
	return out
}

// dedupeAdvisories drops override advisories identical to the document's.
func dedupeAdvisories(in []ConfigAdvisory) []ConfigAdvisory {
	base := map[string]bool{}
	var out []ConfigAdvisory
	for _, a := range in {
		if a.Scope == "policy" {
			base[a.RuleID] = true
		} else if base[a.RuleID] {
			continue
		}
		out = append(out, a)
	}
	return out
}

func boolPtrValue(v *bool) bool {
	return v != nil && *v
}
