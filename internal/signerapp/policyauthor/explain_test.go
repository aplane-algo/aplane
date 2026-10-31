// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/asa"
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
