// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/asaset"
	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/policycontext"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
)

func tryAddr(n byte) string { return types.Address{n}.String() }

func writeTryDoc(t *testing.T, doc string) *File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "doc.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	f := LoadFile(path)
	if f.Document == nil {
		t.Fatalf("document did not load: %+v", f.Problems)
	}
	return f
}

func shippedSignerDefault(t *testing.T, autoApprove bool) string {
	t.Helper()
	doc := policytest.EmbeddedDefault(t, noderole.RoleSigner)
	if autoApprove {
		doc = strings.Replace(doc, `"auto_approve_self_noop_transfer": false`, `"auto_approve_self_noop_transfer": true`, 1)
	}
	return doc
}

func TestTrySignerOutcomes(t *testing.T) {
	routes := `{"transfer_policy": {"routes": [{"id": "payroll", "networks": ["testnet"], "sources": ["*"], "assets": ["algo"], "destinations": ["` + tryAddr(2) + `"], "limits": {"testnet": {"algo": {"review_above": "10", "reject_above": "20"}}}}]}}`
	tests := []struct {
		name    string
		doc     string
		txn     TryTxn
		outcome policyeval.Outcome
		ruleID  string
		summary string
	}{
		{name: "route miss rejects", doc: policytest.Signer(t, policy.DefaultKey, ""), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(3), Amount: 5, Fee: 1000}, outcome: policyeval.Reject, summary: "this document rejects the transaction"},
		{name: "within the route", doc: policytest.Signer(t, policy.DefaultKey, routes), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000}, outcome: policyeval.Default, summary: "no rule in this document decides; the operator default applies"},
		{name: "above review_above", doc: policytest.Signer(t, policy.DefaultKey, routes), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 11, Fee: 1000}, outcome: policyeval.Review, ruleID: "transfer_policy:payroll:review_above", summary: "requires review (rule transfer_policy:payroll:review_above)"},
		{name: "self no-op, flag off", doc: shippedSignerDefault(t, false), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(1), Fee: 1000}, outcome: policyeval.Default},
		{name: "self no-op, flag on", doc: shippedSignerDefault(t, true), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(1), Fee: 1000}, outcome: policyeval.Approve, ruleID: policy.AutoApproveSelfNoOpTransferRuleID, summary: "approves it without review"},
		{name: "asset opt-in, flag on", doc: shippedSignerDefault(t, true), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(1), Asset: 7, Fee: 1000}, outcome: policyeval.Approve, ruleID: policy.AutoApproveSelfNoOpTransferRuleID},
		{name: "foreign rekey", doc: shippedSignerDefault(t, false), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(1), RekeyTo: tryAddr(9), Fee: 1000}, outcome: policyeval.Reject},
		{name: "rekey to a held key", doc: shippedSignerDefault(t, false), txn: TryTxn{Sender: tryAddr(1), Receiver: tryAddr(1), RekeyTo: tryAddr(9), RekeyTargetHeld: true, Fee: 1000}, outcome: policyeval.Review, ruleID: policy.AlwaysReviewWarningsRuleID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Try(writeTryDoc(t, tc.doc), tc.txn, BuiltinNetworks())
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome != tc.outcome || got.RuleID != tc.ruleID {
				t.Fatalf("Try() = %+v, want outcome %d rule %q", got, tc.outcome, tc.ruleID)
			}
			if tc.outcome == policyeval.Reject && len(got.Violations) == 0 {
				t.Fatal("a rejection carries no violations")
			}
			if !strings.Contains(got.Summary, tc.summary) {
				t.Fatalf("summary = %q, want it to contain %q", got.Summary, tc.summary)
			}
			if !strings.Contains(strings.Join(got.Assumes, "\n"), "refusals the signer makes before policy are not checked") {
				t.Fatalf("assumptions = %q", got.Assumes)
			}
		})
	}
}

func TestTryCosignerNamesTheDocument(t *testing.T) {
	anyRoute := `{"transfer_policy": {"routes": [{"id": "any", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]}]}}`
	permits := writeTryDoc(t, policytest.Cosigner(t, policy.DefaultKey, anyRoute))
	got, err := Try(permits, TryTxn{Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000}, BuiltinNetworks())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != policyeval.Approve || got.Summary != "this cosigner policy document permits the supplied transaction" {
		t.Fatalf("Try() = %+v", got)
	}
	if !strings.Contains(strings.Join(got.Assumes, "\n"), "the cosigner holds the witness key") {
		t.Fatalf("assumptions = %q", got.Assumes)
	}

	// A cosigner judges rekeys by its own rules, which the client checks
	// do not include: the role must come from the document.
	rejectsRekeys := writeTryDoc(t, policytest.Cosigner(t, policy.DefaultKey, `{"reject_rekey": true}`))
	got, err = Try(rejectsRekeys, TryTxn{Sender: tryAddr(1), Receiver: tryAddr(1), RekeyTo: tryAddr(8), RekeyTargetHeld: true, Fee: 1000}, BuiltinNetworks())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != policyeval.Reject || got.Violations[0].RuleID != policy.CosignerRekeyRuleID {
		t.Fatalf("Try(rekey) = %+v, want the cosigner rekey rejection", got)
	}
}

func TestTryNodeNetworksCompileAndResolveTogether(t *testing.T) {
	const custom = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	resolver, err := apconfig.NewGenesisHashNetworkResolver(map[string]string{custom: "devnet-x"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := policycontext.New(noderole.RoleSigner, resolver, asaset.Empty())
	if err != nil {
		t.Fatal(err)
	}
	node := &NodeContext{Context: ctx, ExportedAt: time.Now(), Path: "export/.appolicy/node.json"}
	networks, err := node.Networks(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(networks.Source, "export/.appolicy/node.json") {
		t.Fatalf("source = %q", networks.Source)
	}
	doc := writeTryDoc(t, policytest.Signer(t, policy.DefaultKey, `{"transfer_policy": {"routes": [{"id": "dev", "networks": ["devnet-x"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]}]}}`))
	txn := TryTxn{Network: "devnet-x", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5, Fee: 1000}

	got, err := Try(doc, txn, networks)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != policyeval.Default {
		t.Fatalf("Try(devnet-x) = %+v, want the devnet route to permit it", got)
	}
	if _, err := Try(doc, txn, BuiltinNetworks()); err == nil || !strings.Contains(err.Error(), `network "devnet-x" is not known`) {
		t.Fatalf("Try() with built-in networks error = %v, want unknown network", err)
	}
}

func TestTryRefusesBadInput(t *testing.T) {
	doc := writeTryDoc(t, policytest.Signer(t, policy.DefaultKey, ""))
	for name, txn := range map[string]TryTxn{
		"no sender":        {Receiver: tryAddr(2)},
		"bad receiver":     {Sender: tryAddr(1), Receiver: "nope"},
		"clawback of algo": {Sender: tryAddr(1), Receiver: tryAddr(2), ClawbackFrom: tryAddr(3)},
		"unknown network":  {Network: "nowhere", Sender: tryAddr(1), Receiver: tryAddr(2)},
	} {
		if _, err := Try(doc, txn, BuiltinNetworks()); err == nil {
			t.Errorf("%s: Try() succeeded, want an error", name)
		}
	}
	invalid := &File{Path: "broken.json"}
	if _, err := Try(invalid, TryTxn{Sender: tryAddr(1), Receiver: tryAddr(2)}, BuiltinNetworks()); err == nil {
		t.Error("Try() on an invalid document succeeded")
	}
}
