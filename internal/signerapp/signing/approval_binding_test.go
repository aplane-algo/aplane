// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func bindingFixture() (signerapi.GroupSignRequest, *PlanResult) {
	txns := []types.Transaction{
		{Type: types.PaymentTx, Header: types.Header{Fee: 1000, FirstValid: 1, LastValid: 100}, PaymentTxnFields: types.PaymentTxnFields{Amount: 5}},
		{Type: types.PaymentTx, Header: types.Header{Fee: 1000, FirstValid: 1, LastValid: 100}, PaymentTxnFields: types.PaymentTxnFields{Amount: 7}},
		{Type: types.PaymentTx, Header: types.Header{FirstValid: 1, LastValid: 100}},
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "KEY-A"}, {AuthAddress: ""}}}
	plan := &PlanResult{
		AllTxns:               txns,
		PassthroughIndices:    map[int]bool{1: true},
		PassthroughSignedTxns: map[int][]byte{1: []byte("signed-bytes")},
		ForeignIndices:        map[int]bool{},
	}
	return req, plan
}

func TestApprovalBindingRefusesUnapprovedAndChangedGroups(t *testing.T) {
	req, plan := bindingFixture()
	if err := checkApprovalBinding(req, plan); err == nil || !strings.Contains(err.Message, "no approval decision") {
		t.Fatalf("unbound plan: %v", err)
	}
	plan.bindApproval(approvalDigest(req, plan))
	if err := checkApprovalBinding(req, plan); err != nil {
		t.Fatalf("unchanged plan refused: %v", err)
	}

	for name, change := range map[string]func(*signerapi.GroupSignRequest, *PlanResult){
		"amount":            func(_ *signerapi.GroupSignRequest, p *PlanResult) { p.AllTxns[0].Amount++ },
		"receiver":          func(_ *signerapi.GroupSignRequest, p *PlanResult) { p.AllTxns[0].Receiver = types.Address{9} },
		"dummy":             func(_ *signerapi.GroupSignRequest, p *PlanResult) { p.AllTxns[2].Note = []byte{1} },
		"appended slot":     func(_ *signerapi.GroupSignRequest, p *PlanResult) { p.AllTxns = append(p.AllTxns, types.Transaction{}) },
		"passthrough bytes": func(_ *signerapi.GroupSignRequest, p *PlanResult) { p.PassthroughSignedTxns[1] = []byte("other") },
		"foreign slot":      func(_ *signerapi.GroupSignRequest, p *PlanResult) { p.ForeignIndices[2] = true },
		"signing key":       func(r *signerapi.GroupSignRequest, _ *PlanResult) { r.Requests[0].AuthAddress = "KEY-B" },
	} {
		t.Run(name, func(t *testing.T) {
			req, plan := bindingFixture()
			plan.bindApproval(approvalDigest(req, plan))
			change(&req, plan)
			if err := checkApprovalBinding(req, plan); err == nil || !strings.Contains(err.Message, "changed after it was approved") {
				t.Fatalf("%s changed after approval: got %v", name, err)
			}
		})
	}
}

func TestComponentApprovalDigestCoversWhatIsSigned(t *testing.T) {
	fixture := func() *ComponentSignPlan {
		return &ComponentSignPlan{
			ComponentKey: "COMPONENT-KEY",
			Group:        &canonical.Group{GroupHash: [32]byte{1}, Entries: []canonical.Txn{{Raw: []byte("TX-a")}, {Raw: []byte("TX-b")}}},
			Targets:      []ComponentSignTarget{{TargetIndex: 0, Sender: "S", TxID: [32]byte{2}, Message: [32]byte{3}}},
		}
	}
	base := componentApprovalDigest(fixture())
	for name, change := range map[string]func(*ComponentSignPlan){
		"group bytes":   func(p *ComponentSignPlan) { p.Group.Entries[1].Raw = []byte("TX-c") },
		"group hash":    func(p *ComponentSignPlan) { p.Group.GroupHash[0] = 9 },
		"signing key":   func(p *ComponentSignPlan) { p.ComponentKey = "OTHER" },
		"target slot":   func(p *ComponentSignPlan) { p.Targets[0].TargetIndex = 1 },
		"target msg":    func(p *ComponentSignPlan) { p.Targets[0].Message[0] = 7 },
		"extra target":  func(p *ComponentSignPlan) { p.Targets = append(p.Targets, ComponentSignTarget{TargetIndex: 1}) },
		"target sender": func(p *ComponentSignPlan) { p.Targets[0].Sender = "T" },
	} {
		plan := fixture()
		change(plan)
		if componentApprovalDigest(plan) == base {
			t.Errorf("%s changed but the component approval digest did not", name)
		}
	}
	if componentApprovalDigest(fixture()) != base {
		t.Fatal("component approval digest is not deterministic")
	}
}
