// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import "testing"

func TestCheckStoredConfigAdvisoriesReportsLegacyCloseOverlap(t *testing.T) {
	reject := true
	allow := true
	stored := &StoredConfig{
		RejectCloseRemainder: &reject,
		RejectAssetClose:     &reject,
		TransferPolicy: &StoredTransferPolicy{
			Routes: []StoredTransferRoute{{
				ID:    "recovery_algo",
				Close: StoredRoutePermission{Allow: &allow},
			}},
		},
	}

	got := CheckStoredConfigAdvisories(stored)

	assertAdvisoryRuleIDs(t, got, []string{
		ConfigAdvisoryRejectCloseRemainderRouteOverlap,
		ConfigAdvisoryRejectAssetCloseRouteOverlap,
	})
}

func TestCheckStoredConfigAdvisoriesReportsClawbackOverlap(t *testing.T) {
	reject := true
	allow := true
	stored := &StoredConfig{
		RejectClawback: &reject,
		TransferPolicy: &StoredTransferPolicy{
			Routes: []StoredTransferRoute{{
				ID:       "clawback_recovery",
				Clawback: StoredRoutePermission{Allow: &allow},
			}},
		},
	}

	got := CheckStoredConfigAdvisories(stored)

	assertAdvisoryRuleIDs(t, got, []string{ConfigAdvisoryRejectClawbackRouteOverlap})
	if got[0].Severity != ConfigAdvisorySeverityWarning {
		t.Fatalf("Severity = %q, want warning", got[0].Severity)
	}
}

func TestCheckStoredConfigAdvisoriesIgnoresUnsetLegacyRejects(t *testing.T) {
	allow := true
	stored := &StoredConfig{
		TransferPolicy: &StoredTransferPolicy{
			Routes: []StoredTransferRoute{{
				ID:       "recovery",
				Close:    StoredRoutePermission{Allow: &allow},
				Clawback: StoredRoutePermission{Allow: &allow},
			}},
		},
	}

	if got := CheckStoredConfigAdvisories(stored); len(got) != 0 {
		t.Fatalf("advisories = %+v, want none", got)
	}
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
