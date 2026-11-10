// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/noderole"
)

func advisoryByRule(advisories []ConfigAdvisory, ruleID string) (ConfigAdvisory, bool) {
	for _, advisory := range advisories {
		if advisory.RuleID == ruleID {
			return advisory, true
		}
	}
	return ConfigAdvisory{}, false
}

// A cosigner policy may allow any transaction type, "*" included. A type
// transfer routing doesn't govern is authorized by its verdict alone, which
// the document's advisories say. Review stays refused: a cosigner has no
// operator.
func TestCosignerMayAllowAnyTransactionType(t *testing.T) {
	for name, types := range map[string]string{
		"one non-transfer type": `"transaction_types":{"*":"reject","pay":"allow","appl":"allow"}`,
		"wildcard":              `"transaction_types":{"*":"allow"}`,
	} {
		doc := mustCosignerDoc(t, testWitnessKeyIDV1, "{"+types+"}")
		cfg, err := doc.Compile(DefaultConfig())
		if err != nil {
			t.Fatalf("%s: Compile() error = %v", name, err)
		}
		if got := cfg.TransactionTypes.Verdict("appl"); got != TransactionTypeAllow {
			t.Fatalf("%s: appl verdict = %q, want allow", name, got)
		}
		for _, tc := range v1VerdictTransactions(t) {
			if tc.name == "application call" {
				if got := policyVerdicts(tc.txn, cfg); got != "" {
					t.Fatalf("%s: an allowed application call was rejected: %s", name, got)
				}
			}
		}
		advisory, ok := advisoryByRule(doc.Advisories(), ConfigAdvisoryCosignerTypeWithoutRouting)
		if !ok || advisory.Pointer != "/transaction_types" {
			t.Fatalf("%s: advisory = %+v, %v", name, advisory, ok)
		}
		want := "appl is allowed with no routing behind it; the cosigner authorizes it on type alone"
		if name == "wildcard" {
			want = `"*" allows every type the map doesn't reject, including any type added later (today: acfg, afrz, keyreg, appl, stpf, hb); other than pay and axfer they have no routing behind them, and the cosigner authorizes them on type alone`
		}
		if advisory.Message != want {
			t.Fatalf("%s: advisory message = %q, want %q", name, advisory.Message, want)
		}
	}

	// Several named types read as a plural.
	several := mustCosignerDoc(t, testWitnessKeyIDV1, `{"transaction_types":{"appl":"allow","keyreg":"allow"}}`)
	if advisory, _ := advisoryByRule(several.Advisories(), ConfigAdvisoryCosignerTypeWithoutRouting); advisory.Message != "keyreg, appl are allowed with no routing behind them; the cosigner authorizes them on type alone" {
		t.Fatalf("several types: advisory message = %q", advisory.Message)
	}
	// A wildcard allow is reported even when every type known today is
	// rejected by name: a type added later would be signed on type alone.
	future := mustCosignerDoc(t, testWitnessKeyIDV1, `{"transaction_types":{"*":"allow","acfg":"reject","afrz":"reject","keyreg":"reject","appl":"reject","stpf":"reject","hb":"reject"}}`)
	if advisory, ok := advisoryByRule(future.Advisories(), ConfigAdvisoryCosignerTypeWithoutRouting); !ok || !strings.Contains(advisory.Message, "including any type added later (none of today's types)") {
		t.Fatalf("wildcard with every known type rejected: advisory = %+v, %v", advisory, ok)
	}

	// Only transfer types allowed: nothing to advise.
	plain := mustCosignerDoc(t, testWitnessKeyIDV1, `{"transaction_types":{"pay":"allow","axfer":"allow"}}`)
	if advisory, ok := advisoryByRule(plain.Advisories(), ConfigAdvisoryCosignerTypeWithoutRouting); ok {
		t.Fatalf("unexpected advisory for a transfer-only cosigner: %+v", advisory)
	}
	// A signer's non-transfer allow is its ordinary choice, not advised.
	signer := mustSignerDoc(t, DefaultKey, `{"transaction_types":{"*":"allow"}}`)
	if advisory, ok := advisoryByRule(signer.Advisories(), ConfigAdvisoryCosignerTypeWithoutRouting); ok {
		t.Fatalf("unexpected advisory on a signer document: %+v", advisory)
	}
	// A cosigner still can't review.
	_, err := DecodePolicyV1(cosignerJSON(t, testWitnessKeyIDV1, `{"transaction_types":{"appl":"review"}}`), testWitnessKeyIDV1, noderole.RoleCosigner)
	assertDocumentError(t, err, "/transaction_types/appl", "cannot produce review verdicts")
}

// A cosigner rekey_policy may be open: "*" as a sender or a target, and "self"
// as a target, which is a rekey back to the account's own key. "self" as a
// sender is refused: a sender is always itself.
func TestCosignerRekeyPolicyMayBeOpen(t *testing.T) {
	compile := func(rule string) (*PolicyV1, *RekeyPolicy) {
		t.Helper()
		doc := mustCosignerDoc(t, testWitnessKeyIDV1, fmt.Sprintf(`{"reject_rekey":false,"rekey_policy":{"allowed":[%s]}}`, rule))
		cfg, err := doc.Compile(DefaultConfig())
		if err != nil {
			t.Fatalf("Compile(%s) error = %v", rule, err)
		}
		return doc, cfg.RekeyPolicy
	}

	doc, open := compile(`{"sender":"*","targets":["*"]}`)
	if !open.Allows(v1Ops, v1Vendor) || !open.Allows(v1Other, v1Ops) || !open.Allows(v1Ops, v1Ops) {
		t.Fatal("a fully open rekey_policy refused an edge")
	}
	advisory, ok := advisoryByRule(doc.Advisories(), ConfigAdvisoryRekeyPolicyAnyTarget)
	if !ok || advisory.Pointer != "/rekey_policy/allowed/0/targets" || advisory.Message != "rekey_policy lets any sender rekey to any address" {
		t.Fatalf("advisory = %+v, %v", advisory, ok)
	}

	doc, anyTarget := compile(fmt.Sprintf(`{"sender":%q,"targets":["*"]}`, v1Ops.String()))
	if !anyTarget.Allows(v1Ops, v1Other) || anyTarget.Allows(v1Vendor, v1Other) {
		t.Fatal(`targets ["*"] did not allow exactly the named sender`)
	}
	if advisory, _ := advisoryByRule(doc.Advisories(), ConfigAdvisoryRekeyPolicyAnyTarget); advisory.Message != "rekey_policy lets "+v1Ops.String()+" rekey to any address" {
		t.Fatalf("advisory message = %q", advisory.Message)
	}

	doc, anySender := compile(fmt.Sprintf(`{"sender":"*","targets":[%q]}`, v1Vendor.String()))
	if !anySender.Allows(v1Ops, v1Vendor) || !anySender.Allows(v1Other, v1Vendor) || anySender.Allows(v1Ops, v1Other) {
		t.Fatal(`sender "*" did not allow exactly the listed target`)
	}
	if advisory, ok := advisoryByRule(doc.Advisories(), ConfigAdvisoryRekeyPolicyAnyTarget); ok {
		t.Fatalf("unexpected any-target advisory: %+v", advisory)
	}

	// "self" as a target: only a rekey back to the sender's own address.
	_, self := compile(`{"sender":"*","targets":["self"]}`)
	if !self.Allows(v1Ops, v1Ops) || self.Allows(v1Ops, v1Vendor) {
		t.Fatal(`targets ["self"] did not allow exactly a rekey back to the sender`)
	}
	clone := self.Clone()
	if !clone.Allows(v1Ops, v1Ops) || clone.Allows(v1Ops, v1Vendor) {
		t.Fatal("Clone() lost the self target")
	}

	// The term compiler is the backstop for "self" as a sender; the decoder
	// refuses it first, with the reason.
	if _, err := compileRekeyAddressTerms("allowed[0].sender", []string{"self"}, nil, false); err == nil || !strings.Contains(err.Error(), "self is not allowed in rekey_policy.allowed[0].sender") {
		t.Fatalf("compile self sender: err = %v", err)
	}
}

// A route may allow close-out to a wildcard destination, on both node roles.
// The document's advisories say what that means.
func TestRouteMayCloseOutToAnyAddress(t *testing.T) {
	route := `{"transfer_policy":{"routes":[{"id":"r","networks":["testnet"],"sources":["*"],"assets":["algo"],"destinations":["*"],"allow_close":true}]}}`
	for name, doc := range map[string]*PolicyV1{
		"signer":   mustSignerDoc(t, DefaultKey, route),
		"cosigner": mustCosignerDoc(t, testWitnessKeyIDV1, route),
	} {
		cfg, err := doc.Compile(DefaultConfig())
		if err != nil {
			t.Fatalf("%s: Compile() error = %v", name, err)
		}
		for _, tc := range v1VerdictTransactions(t) {
			if tc.name == "close to unrouted destination" || tc.name == "close to routed destination" {
				if got := policyVerdicts(tc.txn, cfg); strings.Contains(got, "transfer_policy") {
					t.Fatalf("%s: %s was refused by routing: %s", name, tc.name, got)
				}
			}
		}
		advisory, ok := advisoryByRule(doc.Advisories(), ConfigAdvisoryRouteCloseToAnyAddress)
		if !ok || advisory.Pointer != "/transfer_policy/routes/0/allow_close" || advisory.Message != "this route lets any matching account be closed out to any address; a close-out moves the whole balance, and the route's limits don't bound it" {
			t.Fatalf("%s: advisory = %+v, %v", name, advisory, ok)
		}
	}
	// allow_close to a listed destination isn't advised.
	listed := mustSignerDoc(t, DefaultKey, fmt.Sprintf(`{"transfer_policy":{"routes":[{"id":"r","networks":["testnet"],"sources":["*"],"assets":["algo"],"destinations":[%q],"allow_close":true}]}}`, v1Vendor.String()))
	if advisory, ok := advisoryByRule(listed.Advisories(), ConfigAdvisoryRouteCloseToAnyAddress); ok {
		t.Fatalf("unexpected advisory: %+v", advisory)
	}
}

// A cosigner with no fee cap is advised whenever its document lets it sign,
// through a route or through a type allowed without routing. It has no
// warning review, so nothing else questions a fee.
func TestCosignerNoFeeCapAdvisoryCoversTypesWithoutRoutes(t *testing.T) {
	for name, tc := range map[string]struct {
		doc  string
		want bool
	}{
		"a type without routes, no cap":     {`{"max_fee_microalgos":"0","transaction_types":{"appl":"allow"}}`, true},
		"a wildcard without routes, no cap": {`{"max_fee_microalgos":"0","transaction_types":{"*":"allow"}}`, true},
		"a type without routes, capped":     {`{"max_fee_microalgos":"5000","transaction_types":{"appl":"allow"}}`, false},
		"an open rekey rule, no cap":        {`{"max_fee_microalgos":"0","transaction_types":{"pay":"allow"},"reject_rekey":false,"rekey_policy":{"allowed":[{"sender":"*","targets":["*"]}]}}`, true},
		"a rekey rule under reject_rekey":   {`{"max_fee_microalgos":"0","transaction_types":{"pay":"allow"},"reject_rekey":true,"rekey_policy":{"allowed":[{"sender":"*","targets":["*"]}]}}`, false},
		"nothing allowed, no cap":           {`{"max_fee_microalgos":"0","transaction_types":{"pay":"allow"}}`, false},
	} {
		_, got := advisoryByRule(mustCosignerDoc(t, testWitnessKeyIDV1, tc.doc).Advisories(), ConfigAdvisoryCosignerNoFeeCap)
		if got != tc.want {
			t.Errorf("%s: no-fee-cap advisory = %v, want %v", name, got, tc.want)
		}
	}
}

// An advisory describes what the document does, so it stays silent where
// another setting already rejects the thing it would describe.
func TestWideChoiceAdvisoriesFollowTheRejectSettings(t *testing.T) {
	rekey := mustCosignerDoc(t, testWitnessKeyIDV1, `{"reject_rekey":true,"rekey_policy":{"allowed":[{"sender":"*","targets":["*"]}]}}`)
	if advisory, ok := advisoryByRule(rekey.Advisories(), ConfigAdvisoryRekeyPolicyAnyTarget); ok {
		t.Fatalf("reject_rekey is on, but the open rekey rule was advised: %+v", advisory)
	}
	// A cosigned rekey is a payment, so a rule no payment can reach isn't
	// reported either.
	noPay := mustCosignerDoc(t, testWitnessKeyIDV1, `{"transaction_types":{"pay":"reject"},"reject_rekey":false,"rekey_policy":{"allowed":[{"sender":"*","targets":["*"]}]}}`)
	if advisory, ok := advisoryByRule(noPay.Advisories(), ConfigAdvisoryRekeyPolicyAnyTarget); ok {
		t.Fatalf("pay is rejected, but the open rekey rule was advised: %+v", advisory)
	}
	// An ALGO-only route under reject_close_remainder can close nothing.
	algoOnly := mustCosignerDoc(t, testWitnessKeyIDV1, `{"reject_close_remainder":true,"reject_asset_close":false,"transfer_policy":{"routes":[{"id":"r","networks":["testnet"],"sources":["*"],"assets":["algo"],"destinations":["*"],"allow_close":true}]}}`)
	if advisory, ok := advisoryByRule(algoOnly.Advisories(), ConfigAdvisoryRouteCloseToAnyAddress); ok {
		t.Fatalf("an ALGO-only route under reject_close_remainder was advised: %+v", advisory)
	}
	route := `"transfer_policy":{"routes":[{"id":"r","networks":["testnet"],"sources":["*"],"assets":["*"],"destinations":["*"],"allow_close":true}]}`
	for name, tc := range map[string]struct {
		rejects string
		want    bool
	}{
		"both close-outs rejected": {`"reject_close_remainder":true,"reject_asset_close":true`, false},
		"only ALGO close rejected": {`"reject_close_remainder":true,"reject_asset_close":false`, true},
		"neither rejected":         {`"reject_close_remainder":false,"reject_asset_close":false`, true},
	} {
		doc := mustCosignerDoc(t, testWitnessKeyIDV1, "{"+tc.rejects+","+route+"}")
		if _, got := advisoryByRule(doc.Advisories(), ConfigAdvisoryRouteCloseToAnyAddress); got != tc.want {
			t.Errorf("%s: close-to-any-address advisory = %v, want %v", name, got, tc.want)
		}
	}
}
