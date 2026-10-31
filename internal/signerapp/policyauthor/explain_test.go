// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asa"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

func explainFixture(t *testing.T, name string, lookup AssetLookup) string {
	t.Helper()
	f := LoadFile(writeFile(t, t.TempDir(), "doc.json", fixture(t, name)))
	if f.Document == nil {
		t.Fatalf("%s does not decode: %+v", name, f.Problems)
	}
	return Explain(f.Document, lookup)
}

func assertLines(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, line := range want {
		if !strings.Contains(out, line) {
			t.Errorf("explain output lacks %q:\n%s", line, out)
		}
	}
}

func TestExplainSignerDocument(t *testing.T) {
	out := explainFixture(t, "signer_key_full.json", asa.BuiltinMetadata)
	assertLines(t, out,
		"Signer key document for "+testSignerKey,
		"Rejected transaction types (always deny): acfg, afrz, stpf, hb",
		"Reviewed transaction types (always review): keyreg, appl",
		"Always denied: clawbacks; rekeys to an address this node does not hold",
		"Fee cap: rejects a fee above 0.01 ALGO (10000 microAlgos)",
		"Transfers with no matching route: reject; close-outs: review; clawbacks: reject",
		"  treasury-to-ops: from @treasury to @ops, assets algo, on mainnet",
		"    mainnet ALGO: review above 500 ALGO (500000000 microAlgos)",
		"reject above 1000 USDC (1000000000 base units; 6 decimals, builtin)",
		"Routes match a transaction's sender; this document governs whatever its key signs.",
	)
}

func TestExplainCosignerDocument(t *testing.T) {
	out := explainFixture(t, "cosigner_key_full.json", asa.BuiltinMetadata)
	assertLines(t, out,
		"Cosigner key document for "+testWitnessKeyID,
		"Transfers: allowlist; a transfer no route allows is rejected",
		"Rekeys allowed only along these edges, each as a zero-amount self-payment:",
		"  "+testSignerKey+" to @new_auth",
	)
	if strings.Contains(out, "review above") || strings.Contains(out, "Reviewed transaction types") {
		t.Fatalf("a cosigner explanation mentions review:\n%s", out)
	}
	def := explainFixture(t, "cosigner_default.json", nil)
	assertLines(t, def,
		"Cosigner default document: governs every key that has no document of its own",
		"Rekeys: every rekey is rejected",
		"Routes: none",
	)
}

func TestExplainWithoutMetadataShowsBaseUnits(t *testing.T) {
	out := explainFixture(t, "signer_key_full.json", nil)
	assertLines(t, out, "mainnet asa:31566704: reject above 5000000000 base units (decimals unknown)")
	if strings.Contains(out, "USDC") {
		t.Fatalf("a symbol appeared without metadata:\n%s", out)
	}
}

// TestExplainListsEverySetMember: a change to who a set holds changes what a
// route permits, so the explanation must show the addresses, not a count.
func TestExplainListsEverySetMember(t *testing.T) {
	for _, name := range []string{"signer_key_full.json", "cosigner_key_full.json"} {
		f := LoadFile(writeFile(t, t.TempDir(), "doc.json", fixture(t, name)))
		out := Explain(f.Document, nil)
		for set, members := range f.Document.AddressSets {
			all := append([]types.Address(nil), members.Flat...)
			for _, list := range members.ByNetwork {
				all = append(all, list...)
			}
			for _, a := range all {
				if !strings.Contains(out, a.String()) {
					t.Errorf("%s: @%s member %s missing from the explanation", name, set, a)
				}
			}
		}
	}

	original := fixture(t, "signer_key_full.json")
	changed := strings.Replace(string(original), "EIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDOHSEZI", testSignerKey2, 1)
	if changed == string(original) {
		t.Fatal("test did not change the @ops member")
	}
	before := Explain(LoadFile(writeFile(t, t.TempDir(), "a.json", original)).Document, nil)
	after := Explain(LoadFile(writeFile(t, t.TempDir(), "b.json", []byte(changed))).Document, nil)
	if before == after {
		t.Fatal("changing an address-set member left the explanation unchanged")
	}
}

// TestExplainSelfNoOpIsConditional: the flag is an Always Approve rule, so it
// is described as eligibility that deny and review rules come before, and as
// unreachable when the document rejects the types it covers.
func TestExplainSelfNoOpIsConditional(t *testing.T) {
	explain := func(sparse string) string {
		t.Helper()
		doc := policytest.Signer(t, policy.DefaultKey, sparse)
		f := LoadFile(writeFile(t, t.TempDir(), "d.json", []byte(doc)))
		if f.Document == nil {
			t.Fatalf("document does not decode: %+v", f.Problems)
		}
		return Explain(f.Document, nil)
	}
	all := explain(`{"auto_approve_self_noop_transfer": true, "transaction_types": {"*": "reject"}}`)
	assertLines(t, all, "only when no deny or review rule matched it first", "it never applies here")
	if strings.Contains(all, "is approved without review") {
		t.Fatalf("explanation promises approval the document's rejections prevent:\n%s", all)
	}
	assertLines(t, explain(`{"auto_approve_self_noop_transfer": true, "transaction_types": {"*": "reject", "pay": "allow"}}`), "only for pay here")
	open := explain(`{"auto_approve_self_noop_transfer": true, "transaction_types": {"*": "allow"}}`)
	if strings.Contains(open, "never applies") || strings.Contains(open, "only for") {
		t.Fatalf("eligible document described as limited:\n%s", open)
	}
	if strings.Contains(explain(`{"auto_approve_self_noop_transfer": false}`), "Self no-op") {
		t.Fatal("self no-op described while the flag is off")
	}
}
