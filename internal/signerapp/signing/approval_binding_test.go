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
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "KEY-A", LsigArgs: map[string]string{"secret": "ab"}}, {AuthAddress: ""}}}
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
		"lsig argument":     func(r *signerapi.GroupSignRequest, _ *PlanResult) { r.Requests[0].LsigArgs["secret"] = "cd" },
		"lsig argument name": func(r *signerapi.GroupSignRequest, _ *PlanResult) {
			r.Requests[0].LsigArgs = map[string]string{"other": "ab"}
		},
		"added lsig argument": func(r *signerapi.GroupSignRequest, _ *PlanResult) {
			r.Requests[1].LsigArgs = map[string]string{"x": "01"}
		},
		"rotation added": func(_ *signerapi.GroupSignRequest, p *PlanResult) {
			p.Rotating = &rotatingPlanItem{Stage: 1, Target: 2}
		},
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

func TestApprovalBindingCoversTheRotation(t *testing.T) {
	rotating := func() (signerapi.GroupSignRequest, *PlanResult) {
		req, plan := bindingFixture()
		plan.Rotating = &rotatingPlanItem{Stage: 4, Target: 5, TargetAddress: types.Address{7}}
		plan.bindApproval(approvalDigest(req, plan))
		return req, plan
	}
	req, plan := rotating()
	if err := checkApprovalBinding(req, plan); err != nil {
		t.Fatalf("unchanged rotating plan refused: %v", err)
	}
	for name, change := range map[string]func(*rotatingPlanItem, *PlanResult){
		"stage":          func(r *rotatingPlanItem, _ *PlanResult) { r.Stage++ },
		"target":         func(r *rotatingPlanItem, _ *PlanResult) { r.Target++ },
		"target address": func(r *rotatingPlanItem, _ *PlanResult) { r.TargetAddress = types.Address{8} },
		"removed":        func(_ *rotatingPlanItem, p *PlanResult) { p.Rotating = nil },
	} {
		t.Run(name, func(t *testing.T) {
			req, plan := rotating()
			change(plan.Rotating, plan)
			if err := checkApprovalBinding(req, plan); err == nil || !strings.Contains(err.Message, "changed after it was approved") {
				t.Fatalf("rotation %s changed after approval: got %v", name, err)
			}
		})
	}
}

func TestApprovalDigestIgnoresLsigArgumentOrder(t *testing.T) {
	req, plan := bindingFixture()
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	forward, backward := map[string]string{}, map[string]string{}
	for i, name := range names {
		forward[name] = name + "1"
		backward[names[len(names)-1-i]] = names[len(names)-1-i] + "1"
	}
	req.Requests[0].LsigArgs = forward
	want := approvalDigest(req, plan)
	for range 20 {
		req.Requests[0].LsigArgs = backward
		if approvalDigest(req, plan) != want {
			t.Fatal("approval digest depends on LogicSig argument order")
		}
	}
	// No arguments and an empty argument map sign the same transaction.
	req.Requests[0].LsigArgs = nil
	none := approvalDigest(req, plan)
	req.Requests[0].LsigArgs = map[string]string{}
	if approvalDigest(req, plan) != none {
		t.Fatal("an empty argument map binds differently from no arguments")
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
