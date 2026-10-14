// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"
	"testing"
)

func renderChanges(changes []PolicyChange) string {
	var lines []string
	for _, c := range changes {
		lines = append(lines, fmt.Sprintf("%s %s: %s", c.Effect, c.Path, c.Summary))
	}
	return strings.Join(lines, "\n")
}

func assertChanges(t *testing.T, got []PolicyChange, want ...string) {
	t.Helper()
	if rendered := renderChanges(got); rendered != strings.Join(want, "\n") {
		t.Fatalf("changes:\n%s\nwant:\n%s", rendered, strings.Join(want, "\n"))
	}
}

func TestDiffPolicyIgnoresFormattingAndKeyOrder(t *testing.T) {
	a := mustSignerDoc(t, DefaultKey, `{"reject_clawback":true,"max_fee_microalgos":"2000"}`)
	b := mustSignerDoc(t, DefaultKey, "{\n  \"max_fee_microalgos\": \"2000\",\n  \"reject_clawback\": true\n}\n")
	assertChanges(t, DiffPolicyV1(a, b))
}

func TestDiffPolicyComparesAcrossKeys(t *testing.T) {
	// A key's new document is compared with the default it followed; the
	// differing key is not a change.
	def := mustSignerDoc(t, DefaultKey, `{"max_fee_microalgos":"2000"}`)
	own := mustSignerDoc(t, v1Ops.String(), `{"max_fee_microalgos":"2000"}`)
	assertChanges(t, DiffPolicyV1(def, own))
}

func TestDiffPolicySettingsAndLimits(t *testing.T) {
	current := mustSignerDoc(t, DefaultKey, `{"reject_clawback":true,"max_fee_microalgos":"2000",
		"limits":{"testnet":{"algo":{"reject_above":"50000000"},"asa:7":{"review_above":"10"}}}}`)
	next := mustSignerDoc(t, DefaultKey, `{"reject_foreign_rekey":false,"auto_approve_self_noop_transfer":true,
		"limits":{"testnet":{"algo":{"reject_above":"100000000","review_above":"1000000"}}}}`)
	assertChanges(t, DiffPolicyV1(current, next),
		"loosened /auto_approve_self_noop_transfer: false → true",
		"loosened /limits/testnet/algo/reject_above: 50 ALGO → 100 ALGO",
		"tightened /limits/testnet/algo/review_above: none → 1 ALGO",
		"loosened /limits/testnet/asa:7/review_above: 10 base units → none",
		"loosened /max_fee_microalgos: 0.002 ALGO → no cap",
		"loosened /reject_clawback: true → false",
		"loosened /reject_foreign_rekey: true → false",
	)
}

func TestDiffPolicyTransactionTypesReportEffectiveVerdicts(t *testing.T) {
	current := mustSignerDoc(t, DefaultKey, `{"transaction_types":{"*":"allow"}}`)
	next := mustSignerDoc(t, DefaultKey, `{"transaction_types":{"*":"reject","pay":"allow","axfer":"allow","keyreg":"review"}}`)
	assertChanges(t, DiffPolicyV1(current, next),
		"tightened /transaction_types/acfg: allow → reject",
		"tightened /transaction_types/afrz: allow → reject",
		"tightened /transaction_types/appl: allow → reject",
		"tightened /transaction_types/hb: allow → reject",
		"tightened /transaction_types/keyreg: allow → review",
		"tightened /transaction_types/stpf: allow → reject",
	)
	assertChanges(t, DiffPolicyV1(next, current),
		"loosened /transaction_types/acfg: reject → allow",
		"loosened /transaction_types/afrz: reject → allow",
		"loosened /transaction_types/appl: reject → allow",
		"loosened /transaction_types/hb: reject → allow",
		"loosened /transaction_types/keyreg: review → allow",
		"loosened /transaction_types/stpf: reject → allow",
	)
}

func TestDiffPolicyRoutesSetsAndRouteMiss(t *testing.T) {
	doc := func(onNoRoute, blocked, opsMembers, routes string) *PolicyV1 {
		return mustSignerDoc(t, DefaultKey, fmt.Sprintf(`{
			"address_sets":{"ops":[%s],"unused":[%q]},
			"transfer_policy":{"on_no_route":%q,"blocked_destinations":[%s],"routes":[%s]}}`,
			opsMembers, v1Holder.String(), onNoRoute, blocked, routes))
	}
	route := func(id, dests, extra string) string {
		return fmt.Sprintf(`{"id":%q,"networks":["testnet"],"sources":["@ops"],"assets":["algo"],"destinations":[%s]%s}`, id, dests, extra)
	}
	q := func(a fmt.Stringer) string { return fmt.Sprintf("%q", a.String()) }
	current := doc("reject", q(v1Bad), q(v1Ops), route("pay", q(v1Vendor), `,"limits":{"testnet":{"algo":{"reject_above":"5"}}}`)+","+route("old", q(v1Vendor), ""))
	next := doc("review", "", q(v1Ops)+","+q(v1Other), route("pay", q(v1Vendor)+","+q(v1Other), `,"allow_close":true,"limits":{"testnet":{"algo":{"reject_above":"9"}}}`)+","+route("new", `"*"`, ""))
	assertChanges(t, DiffPolicyV1(current, next),
		"loosened /address_sets/ops: added "+v1Other.String(),
		"loosened /transfer_policy/blocked_destinations: removed "+v1Bad.String(),
		"loosened /transfer_policy/on_no_route: reject → review",
		"loosened /transfer_policy/routes/new: route added",
		"tightened /transfer_policy/routes/old: route removed",
		"loosened /transfer_policy/routes/pay/allow_close: false → true",
		"loosened /transfer_policy/routes/pay/destinations: added "+v1Other.String(),
		"loosened /transfer_policy/routes/pay/limits/testnet/algo/reject_above: 0.000005 ALGO → 0.000009 ALGO",
	)
}

func TestDiffCosignerPolicyRekey(t *testing.T) {
	base := mustCosignerDoc(t, testWitnessKeyIDV1, "")
	withRekey := mustCosignerDoc(t, testWitnessKeyIDV1, fmt.Sprintf(`{"reject_close_remainder":true,"rekey_policy":{"allowed":[{"sender":%q,"targets":[%q]}]}}`, v1Ops.String(), v1Vendor.String()))
	assertChanges(t, DiffPolicyV1(base, withRekey),
		"tightened /reject_close_remainder: false → true",
		"loosened /rekey_policy/allowed: added "+v1Ops.String()+" → "+v1Vendor.String(),
	)
	rejectAll := mustCosignerDoc(t, testWitnessKeyIDV1, `{"reject_rekey":true}`)
	assertChanges(t, DiffPolicyV1(base, rejectAll), "tightened /reject_rekey: false → true")
}

func TestDiffAddressSetComparesCoverageAcrossForms(t *testing.T) {
	doc := func(set string) *PolicyV1 {
		return mustSignerDoc(t, DefaultKey, fmt.Sprintf(`{"address_sets":{"ops":%s},
			"transfer_policy":{"routes":[
			{"id":"r","networks":["*"],"sources":["@ops"],"assets":["algo"],"destinations":["*"]}]}}`, set))
	}
	a := v1Ops.String()
	perNetwork, flat := doc(fmt.Sprintf(`{"testnet":[%q]}`, a)), doc(fmt.Sprintf(`[%q]`, a))
	assertChanges(t, DiffPolicyV1(perNetwork, flat), "loosened /address_sets/ops/(other networks): added "+a)
	assertChanges(t, DiffPolicyV1(flat, perNetwork), "tightened /address_sets/ops/(other networks): removed "+a)
}

func TestDiffFeeCapTreatsZeroAsNoCap(t *testing.T) {
	capped := mustSignerDoc(t, DefaultKey, `{"max_fee_microalgos":"2000"}`)
	zero := mustSignerDoc(t, DefaultKey, `{"max_fee_microalgos":"0"}`)
	assertChanges(t, DiffPolicyV1(capped, zero), "loosened /max_fee_microalgos: 0.002 ALGO → no cap")
	assertChanges(t, DiffPolicyV1(zero, capped), "tightened /max_fee_microalgos: no cap → 0.002 ALGO")
}
