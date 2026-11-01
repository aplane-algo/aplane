// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
)

func casesWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	routes := `{"transfer_policy": {"routes": [{"id": "payroll", "networks": ["testnet"], "sources": ["*"], "assets": ["algo"], "destinations": ["` + tryAddr(2) + `"], "limits": {"testnet": {"algo": {"review_above": "10"}}}}]}}`
	if err := os.WriteFile(filepath.Join(dir, "default.json"), []byte(policytest.Signer(t, policy.DefaultKey, routes)), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCasesSaveLoadAndRun(t *testing.T) {
	dir := casesWorkspace(t)
	if _, err := LoadCases(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadCases() with none error = %v, want not exist", err)
	}
	cf := &CaseFile{}
	for _, c := range []Case{
		{Name: "small payroll payment", Document: "default.json", Txn: CaseTxn{Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 5}, Expect: CaseExpect{Outcome: "default"}},
		{Name: "large payroll payment", Document: "default.json", Txn: CaseTxn{Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 11}, Expect: CaseExpect{Outcome: "review", RuleID: "transfer_policy:payroll:review_above"}},
		{Name: "anyone else", Document: "default.json", Txn: CaseTxn{Sender: tryAddr(1), Receiver: tryAddr(3), Amount: 1}, Expect: CaseExpect{Outcome: "reject", RuleID: policy.TransferRoutingRouteMissRuleID}},
		{Name: "rejection without a rule", Document: "default.json", Txn: CaseTxn{Sender: tryAddr(1), Receiver: tryAddr(3), Amount: 1}, Expect: CaseExpect{Outcome: "reject"}},
		{Name: "a wrong expectation", Document: "default.json", Txn: CaseTxn{Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 11}, Expect: CaseExpect{Outcome: "review", RuleID: "something_else"}},
		{Name: "no such document", Document: "gone.json", Txn: CaseTxn{Sender: tryAddr(1), Receiver: tryAddr(2)}, Expect: CaseExpect{Outcome: "default"}},
	} {
		if err := cf.Add(c); err != nil {
			t.Fatal(err)
		}
	}
	if err := cf.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Cases) != len(cf.Cases) || loaded.Format != CasesFormat {
		t.Fatalf("LoadCases() = %+v", loaded)
	}

	// The cases file is not a policy document of the workspace.
	ws, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.Files) != 1 {
		t.Fatalf("workspace files = %d, want only default.json", len(ws.Files))
	}

	results := RunCases(loaded.Cases, DiskDocuments(dir), BuiltinNetworks())
	want := []string{"pass", "pass", "pass", "pass", "fail", "error"}
	for i, r := range results {
		got := "fail"
		switch {
		case r.Err != nil:
			got = "error"
		case r.Passed:
			got = "pass"
		}
		if got != want[i] {
			t.Errorf("%s: %s (%+v, %v), want %s", r.Case.Name, got, r.Got, r.Err, want[i])
		}
	}
	if !errors.Is(results[5].Err, ErrDocumentMissing) {
		t.Fatalf("missing document error = %v", results[5].Err)
	}
}

func TestCaseFileRefusesBadCases(t *testing.T) {
	ok := Case{Name: "a", Document: "default.json", Expect: CaseExpect{Outcome: "default"}}
	for name, c := range map[string]Case{
		"no name":         {Document: "default.json", Expect: CaseExpect{Outcome: "default"}},
		"no document":     {Name: "b", Expect: CaseExpect{Outcome: "default"}},
		"absolute path":   {Name: "b", Document: "/etc/x.json", Expect: CaseExpect{Outcome: "default"}},
		"escaping path":   {Name: "b", Document: "../x.json", Expect: CaseExpect{Outcome: "default"}},
		"unknown outcome": {Name: "b", Document: "default.json", Expect: CaseExpect{Outcome: "sign"}},
		"duplicate name":  {Name: "a", Document: "default.json", Expect: CaseExpect{Outcome: "default"}},
	} {
		cf := &CaseFile{}
		if err := cf.Add(ok); err != nil {
			t.Fatal(err)
		}
		if err := cf.Add(c); err == nil {
			t.Errorf("%s: Add() succeeded", name)
		}
		if len(cf.Cases) != 1 {
			t.Errorf("%s: a refused case was kept", name)
		}
	}

	dir := t.TempDir()
	path := CasesPath(dir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"wrong format":   `{"format": "aplane.policy.v1", "cases": []}`,
		"unknown member": `{"format": "aplane.policy-cases.v1", "cases": [], "extra": 1}`,
		"not json":       `{`,
		"trailing value": `{"format": "aplane.policy-cases.v1", "cases": []} {"format": "aplane.policy-cases.v1", "cases": [{"name": "x"}]}`,
		"trailing junk":  `{"format": "aplane.policy-cases.v1", "cases": []} ]`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCases(dir); err == nil || !strings.Contains(err.Error(), "cases.json") {
			t.Errorf("%s: LoadCases() error = %v", name, err)
		}
	}
}

func TestCaseOfATry(t *testing.T) {
	txn := TryTxn{Network: "testnet", Sender: tryAddr(1), Receiver: tryAddr(2), Amount: 11, Fee: 1000}
	saved := CaseTxnOf(txn)
	if saved.Network != "" || saved.Fee != nil {
		t.Fatalf("CaseTxnOf() = %+v, want the defaults left out", saved)
	}
	if back := saved.TryTxn(); back.Fee != 1000 || back.Amount != 11 {
		t.Fatalf("TryTxn() = %+v", back)
	}
	txn.Fee = 2000
	if saved := CaseTxnOf(txn); saved.Fee == nil || *saved.Fee != 2000 {
		t.Fatalf("CaseTxnOf(fee 2000) = %+v", saved)
	}
}
