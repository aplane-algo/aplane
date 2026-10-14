// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"testing"
)

func advisorySignerDoc(t *testing.T, settings, route string) *PolicyV1 {
	t.Helper()
	return mustSignerDoc(t, DefaultKey, fmt.Sprintf(`{%s "transfer_policy": {"routes": [
    {"id": "r", "networks": ["testnet"], "sources": ["*"], "assets": ["*"], "destinations": [%q]%s}
  ]}}`, settings, v1Vendor.String(), route))
}

func TestSignerAdvisoriesReportCloseOverlap(t *testing.T) {
	doc := advisorySignerDoc(t, `"reject_close_remainder": true, "reject_asset_close": true,`, `, "allow_close": true`)
	assertAdvisoryRuleIDs(t, doc.Advisories(), []string{
		ConfigAdvisoryRejectCloseRemainderRouteOverlap,
		ConfigAdvisoryRejectAssetCloseRouteOverlap,
	})
}

func TestSignerAdvisoriesReportClawbackOverlap(t *testing.T) {
	doc := advisorySignerDoc(t, `"reject_clawback": true,`,
		fmt.Sprintf(`, "allow_clawback": true, "asset_sources": [%q]`, v1Holder.String()))
	got := doc.Advisories()
	assertAdvisoryRuleIDs(t, got, []string{ConfigAdvisoryRejectClawbackRouteOverlap})
	if got[0].Severity != ConfigAdvisorySeverityWarning || got[0].Scope != "policy" {
		t.Fatalf("advisory = %+v", got[0])
	}
}

func TestSignerAdvisoriesIgnoreUnsetRejects(t *testing.T) {
	doc := advisorySignerDoc(t, "", `, "allow_close": true`)
	if got := doc.Advisories(); len(got) != 0 {
		t.Fatalf("advisories = %+v, want none", got)
	}
}

func TestAdvisoriesReportRoutesForRejectedTypes(t *testing.T) {
	doc := advisorySignerDoc(t, `"transaction_types": {"*": "allow", "pay": "reject"},`, "")
	got := doc.Advisories()
	assertAdvisoryRuleIDs(t, got, []string{ConfigAdvisoryRejectedTypeRouted})
	if want := "rejects pay, so"; !contains(got[0].Message, want) {
		t.Fatalf("message = %q, want %q", got[0].Message, want)
	}
	// Without routes there is nothing a rejected type makes unreachable.
	none := mustSignerDoc(t, DefaultKey, `{"transaction_types": {"*": "reject"}}`)
	if got := none.Advisories(); len(got) != 0 {
		t.Fatalf("advisories = %+v, want none", got)
	}
}

func TestCosignerAdvisoriesReportCloseOverlapAndMissingFeeCap(t *testing.T) {
	doc := mustCosignerDoc(t, testWitnessKeyIDV1, fmt.Sprintf(`{"reject_close_remainder": true,
  "transfer_policy": {"routes": [
    {"id": "r", "networks": ["testnet"], "sources": ["*"], "assets": ["algo"], "destinations": [%q], "allow_close": true}
  ]}}`, v1Vendor.String()))
	assertAdvisoryRuleIDs(t, doc.Advisories(), []string{ConfigAdvisoryRejectCloseRemainderRouteOverlap, ConfigAdvisoryCosignerNoFeeCap})

	capped := mustCosignerDoc(t, testWitnessKeyIDV1, fmt.Sprintf(`{"max_fee_microalgos": "5000",
  "transfer_policy": {"routes": [
    {"id": "r", "networks": ["testnet"], "sources": ["*"], "assets": ["algo"], "destinations": [%q]}
  ]}}`, v1Vendor.String()))
	if got := capped.Advisories(); len(got) != 0 {
		t.Fatalf("advisories = %+v, want none", got)
	}
	// The deny-all default permits nothing, so a missing cap is not a gap.
	if got := mustCosignerDoc(t, DefaultKey, `{"transaction_types": {"*": "reject"}}`).Advisories(); len(got) != 0 {
		t.Fatalf("advisories = %+v, want none", got)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
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
