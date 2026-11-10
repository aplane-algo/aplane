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
		if !ok || advisory.Pointer != "/transaction_types" || !strings.Contains(advisory.Message, "appl") ||
			!strings.Contains(advisory.Message, "allowed with no routing behind it; the cosigner authorizes it on type alone") {
			t.Fatalf("%s: advisory = %+v, %v", name, advisory, ok)
		}
		if strings.Contains(advisory.Message, "pay") || strings.Contains(advisory.Message, "axfer") {
			t.Fatalf("%s: the advisory names a routed type: %s", name, advisory.Message)
		}
		if name == "wildcard" && !strings.Contains(advisory.Message, "keyreg") {
			t.Fatalf("wildcard advisory doesn't list keyreg: %s", advisory.Message)
		}
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

	// The compile-side backstop refuses "self" as a sender too.
	if _, err := compileRekeyAddressTerms("allowed[0].sender", []string{"self"}, nil, false); err == nil || !strings.Contains(err.Error(), `self is meaningless as a sender; use "*"`) {
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
		if !ok || advisory.Pointer != "/transfer_policy/routes/0/allow_close" || advisory.Message != "this route lets any matching account be closed out to any address" {
			t.Fatalf("%s: advisory = %+v, %v", name, advisory, ok)
		}
	}
	// allow_close to a listed destination isn't advised.
	listed := mustSignerDoc(t, DefaultKey, fmt.Sprintf(`{"transfer_policy":{"routes":[{"id":"r","networks":["testnet"],"sources":["*"],"assets":["algo"],"destinations":[%q],"allow_close":true}]}}`, v1Vendor.String()))
	if advisory, ok := advisoryByRule(listed.Advisories(), ConfigAdvisoryRouteCloseToAnyAddress); ok {
		t.Fatalf("unexpected advisory: %+v", advisory)
	}
}
