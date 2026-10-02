// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"testing"
)

func advisorySignerDoc(t *testing.T, settings, route, overrides string) *SignerPolicyV1 {
	t.Helper()
	doc, err := DecodeSignerPolicyV1([]byte(fmt.Sprintf(`{
  "format": "aplane.signer-policy.v1"%s,
  "transfer_policy": {"enabled": true, "on_no_route": "reject", "routes": [
    {"id": "r", "networks": ["testnet"], "sources": ["*"], "assets": ["*"], "destinations": [%q]%s}
  ]}%s
}`, settings, v1Vendor.String(), route, overrides)))
	if err != nil {
		t.Fatalf("DecodeSignerPolicyV1() error = %v", err)
	}
	return doc
}

func TestSignerAdvisoriesReportCloseOverlap(t *testing.T) {
	doc := advisorySignerDoc(t, `, "reject_close_remainder": true, "reject_asset_close": true`, `, "allow_close": true`, "")
	assertAdvisoryRuleIDs(t, doc.Advisories(), []string{
		ConfigAdvisoryRejectCloseRemainderRouteOverlap,
		ConfigAdvisoryRejectAssetCloseRouteOverlap,
	})
}

func TestSignerAdvisoriesReportClawbackOverlap(t *testing.T) {
	doc := advisorySignerDoc(t, `, "reject_clawback": true`,
		fmt.Sprintf(`, "allow_clawback": true, "asset_sources": [%q]`, v1Holder.String()), "")
	got := doc.Advisories()
	assertAdvisoryRuleIDs(t, got, []string{ConfigAdvisoryRejectClawbackRouteOverlap})
	if got[0].Severity != ConfigAdvisorySeverityWarning || got[0].Scope != "policy" {
		t.Fatalf("advisory = %+v", got[0])
	}
}

func TestSignerAdvisoriesIgnoreUnsetRejects(t *testing.T) {
	doc := advisorySignerDoc(t, "", `, "allow_close": true`, "")
	if got := doc.Advisories(); len(got) != 0 {
		t.Fatalf("advisories = %+v, want none", got)
	}
}

func TestSignerAdvisoriesCheckKeyOverridesWithInheritedSettings(t *testing.T) {
	doc := advisorySignerDoc(t, "", `, "allow_close": true`,
		fmt.Sprintf(`, "key_overrides": {%q: {"reject_close_remainder": true}}`, v1Ops.String()))
	got := doc.Advisories()
	assertAdvisoryRuleIDs(t, got, []string{ConfigAdvisoryRejectCloseRemainderRouteOverlap})
	if got[0].Scope != "key_overrides/"+v1Ops.String() {
		t.Fatalf("scope = %q", got[0].Scope)
	}

	inherited := advisorySignerDoc(t, `, "reject_close_remainder": true`, `, "allow_close": true`,
		fmt.Sprintf(`, "key_overrides": {%q: {"max_fee_microalgos": "2000"}}`, v1Ops.String()))
	assertAdvisoryRuleIDs(t, inherited.Advisories(), []string{ConfigAdvisoryRejectCloseRemainderRouteOverlap})
}

func TestCosignerAdvisoriesReportCloseOverlap(t *testing.T) {
	doc, err := DecodeCosignerPolicyV1([]byte(fmt.Sprintf(`{
  "format": "aplane.cosigner-policy.v1", "key": %q, "reject_close_remainder": true,
  "transfer_policy": {"routes": [
    {"id": "r", "networks": ["testnet"], "sources": ["*"], "assets": ["algo"], "destinations": [%q], "allow_close": true}
  ]}
}`, testWitnessKeyIDV1, v1Vendor.String())), testWitnessKeyIDV1)
	if err != nil {
		t.Fatal(err)
	}
	assertAdvisoryRuleIDs(t, doc.Advisories(), []string{ConfigAdvisoryRejectCloseRemainderRouteOverlap})
}

func assertAdvisoryRuleIDs(t *testing.T, got []ConfigAdvisory, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("advisories = %+v, want %v", got, want)
	}
	for i, wantRuleID := range want {
		if got[i].RuleID != wantRuleID {
			t.Fatalf("advisories = %+v, want %v", got, want)
		}
	}
}
