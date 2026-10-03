// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"
	"testing"
)

func mustSignerDoc(t *testing.T, doc string) *SignerPolicyV1 {
	t.Helper()
	d, err := DecodeSignerPolicyV1([]byte(doc))
	if err != nil {
		t.Fatalf("DecodeSignerPolicyV1() error = %v\n%s", err, doc)
	}
	return d
}

func mustCosignerDoc(t *testing.T, doc string) *CosignerPolicyV1 {
	t.Helper()
	d, err := DecodeCosignerPolicyV1([]byte(doc), testWitnessKeyIDV1)
	if err != nil {
		t.Fatalf("DecodeCosignerPolicyV1() error = %v\n%s", err, doc)
	}
	return d
}

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

func TestDiffSignerPolicyIgnoresFormatting(t *testing.T) {
	a := mustSignerDoc(t, `{"format":"aplane.signer-policy.v1","reject_clawback":true,"max_fee_microalgos":"2000"}`)
	b := mustSignerDoc(t, "{\n  \"max_fee_microalgos\": \"2000\",\n  \"reject_clawback\": true,\n  \"format\": \"aplane.signer-policy.v1\"\n}\n")
	assertChanges(t, DiffSignerPolicyV1(a, b))
}

func TestDiffSignerPolicySettingsAndLimits(t *testing.T) {
	current := mustSignerDoc(t, `{"format":"aplane.signer-policy.v1","reject_clawback":true,"max_fee_microalgos":"2000",
		"limits":{"testnet":{"algo":{"reject_above":"50000000"},"asa:7":{"review_above":"10"}}}}`)
	next := mustSignerDoc(t, `{"format":"aplane.signer-policy.v1","reject_foreign_rekey":false,"auto_approve_self_noop_transfer":true,
		"limits":{"testnet":{"algo":{"reject_above":"100000000","review_above":"1000000"}}}}`)
	assertChanges(t, DiffSignerPolicyV1(current, next),
		"loosened /auto_approve_self_noop_transfer: false → true",
		"loosened /limits/testnet/algo/reject_above: 50 ALGO → 100 ALGO",
		"tightened /limits/testnet/algo/review_above: none → 1 ALGO",
		"loosened /limits/testnet/asa:7/review_above: 10 base units → none",
		"loosened /max_fee_microalgos: 0.002 ALGO → no cap",
		"loosened /reject_clawback: true → false",
		"loosened /reject_foreign_rekey: true → false",
	)
}

func TestDiffSignerPolicyRoutesSetsAndRouteMiss(t *testing.T) {
	doc := func(onNoRoute, blocked, opsMembers, routes string) *SignerPolicyV1 {
		return mustSignerDoc(t, fmt.Sprintf(`{"format":"aplane.signer-policy.v1",
			"address_sets":{"ops":[%s],"unused":[%q]},
			"transfer_policy":{"enabled":true,"on_no_route":%q,"blocked_destinations":[%s],"routes":[%s]}}`,
			opsMembers, v1Holder.String(), onNoRoute, blocked, routes))
	}
	route := func(id, dests, extra string) string {
		return fmt.Sprintf(`{"id":%q,"networks":["testnet"],"sources":["@ops"],"assets":["algo"],"destinations":[%s]%s}`, id, dests, extra)
	}
	q := func(a fmt.Stringer) string { return fmt.Sprintf("%q", a.String()) }
	current := doc("reject", q(v1Bad), q(v1Ops), route("pay", q(v1Vendor), `,"limits":{"testnet":{"algo":{"reject_above":"5"}}}`)+","+route("old", q(v1Vendor), ""))
	next := doc("review", "", q(v1Ops)+","+q(v1Other), route("pay", q(v1Vendor)+","+q(v1Other), `,"allow_close":true,"limits":{"testnet":{"algo":{"reject_above":"9"}}}`)+","+route("new", `"*"`, ""))
	assertChanges(t, DiffSignerPolicyV1(current, next),
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

func TestDiffSignerPolicyKeyOverridesUseEffectiveValues(t *testing.T) {
	key := v1Ops.String()
	current := mustSignerDoc(t, fmt.Sprintf(`{"format":"aplane.signer-policy.v1","max_fee_microalgos":"5000",
		"limits":{"testnet":{"algo":{"reject_above":"100"}}},
		"key_overrides":{%q:{"max_fee_microalgos":"2000"}}}`, key))
	next := mustSignerDoc(t, fmt.Sprintf(`{"format":"aplane.signer-policy.v1","max_fee_microalgos":"5000",
		"limits":{"testnet":{"algo":{"reject_above":"100"}}},
		"key_overrides":{%q:{"reject_clawback":true,"limits":{"testnet":{"algo":{"reject_above":null}}}}}}`, key))
	assertChanges(t, DiffSignerPolicyV1(current, next),
		"loosened /key_overrides/"+key+"/limits/testnet/algo/reject_above: 0.0001 ALGO → none",
		"loosened /key_overrides/"+key+"/max_fee_microalgos: 0.002 ALGO → 0.005 ALGO",
		"tightened /key_overrides/"+key+"/reject_clawback: false → true",
	)
}

func TestDiffCosignerPolicyLifecycleAndRekey(t *testing.T) {
	doc := func(extra string) *CosignerPolicyV1 {
		return mustCosignerDoc(t, fmt.Sprintf(`{"format":"aplane.cosigner-policy.v1","key":%q,
			"transfer_policy":{"routes":[]}%s}`, testWitnessKeyIDV1, extra))
	}
	base := doc("")
	assertChanges(t, DiffCosignerPolicyV1(nil, base), "loosened /: new policy; the key rejected every request without one")
	assertChanges(t, DiffCosignerPolicyV1(base, nil), "tightened /: policy removed; the key will reject every request")
	assertChanges(t, DiffCosignerPolicyV1(nil, nil))

	withRekey := doc(fmt.Sprintf(`,"reject_close_remainder":true,"rekey_policy":{"allowed":[{"sender":%q,"targets":[%q]}]}`, v1Ops.String(), v1Vendor.String()))
	assertChanges(t, DiffCosignerPolicyV1(base, withRekey),
		"tightened /reject_close_remainder: false → true",
		"loosened /rekey_policy/allowed: added "+v1Ops.String()+" → "+v1Vendor.String(),
	)
}

func TestDiffAddressSetComparesCoverageAcrossForms(t *testing.T) {
	doc := func(set string) *SignerPolicyV1 {
		return mustSignerDoc(t, fmt.Sprintf(`{"format":"aplane.signer-policy.v1","address_sets":{"ops":%s},
			"transfer_policy":{"enabled":true,"on_no_route":"reject","routes":[
			{"id":"r","networks":["*"],"sources":["@ops"],"assets":["algo"],"destinations":["*"]}]}}`, set))
	}
	a := v1Ops.String()
	perNetwork, flat := doc(fmt.Sprintf(`{"testnet":[%q]}`, a)), doc(fmt.Sprintf(`[%q]`, a))
	assertChanges(t, DiffSignerPolicyV1(perNetwork, flat), "loosened /address_sets/ops/(other networks): added "+a)
	assertChanges(t, DiffSignerPolicyV1(flat, perNetwork), "tightened /address_sets/ops/(other networks): removed "+a)
}

func TestDiffFeeCapTreatsZeroAsNoCap(t *testing.T) {
	doc := func(fee string) *SignerPolicyV1 {
		return mustSignerDoc(t, fmt.Sprintf(`{"format":"aplane.signer-policy.v1"%s}`, fee))
	}
	capped, zero, none := doc(`,"max_fee_microalgos":"2000"`), doc(`,"max_fee_microalgos":"0"`), doc("")
	assertChanges(t, DiffSignerPolicyV1(capped, zero), "loosened /max_fee_microalgos: 0.002 ALGO → no cap")
	assertChanges(t, DiffSignerPolicyV1(zero, capped), "tightened /max_fee_microalgos: no cap → 0.002 ALGO")
	assertChanges(t, DiffSignerPolicyV1(zero, none))
}

func TestDiffKeyOverrideReportsPinsWithUnchangedValues(t *testing.T) {
	key := v1Ops.String()
	doc := func(override string) *SignerPolicyV1 {
		return mustSignerDoc(t, fmt.Sprintf(`{"format":"aplane.signer-policy.v1","max_fee_microalgos":"5000","reject_clawback":true,
			"limits":{"testnet":{"algo":{"reject_above":"100"}}},"key_overrides":{%q:{%s}}}`, key, override))
	}
	inherits := doc(`"description":"ops"`)
	pinned := doc(`"description":"ops","max_fee_microalgos":"5000","reject_clawback":true,"limits":{"testnet":{"algo":{"reject_above":"100"}}}`)
	prefix := "changed /key_overrides/" + key
	assertChanges(t, DiffSignerPolicyV1(inherits, pinned),
		prefix+"/limits/testnet/algo/reject_above: inherited → set explicitly to 0.0001 ALGO",
		prefix+"/max_fee_microalgos: inherited 0.005 ALGO → set explicitly to 0.005 ALGO",
		prefix+"/reject_clawback: inherited true → set explicitly to true",
	)
	assertChanges(t, DiffSignerPolicyV1(pinned, inherits),
		prefix+"/limits/testnet/algo/reject_above: set explicitly to 0.0001 ALGO → inherited",
		prefix+"/max_fee_microalgos: set explicitly to 0.005 ALGO → inherited 0.005 ALGO",
		prefix+"/reject_clawback: set explicitly to true → inherited true",
	)
}
