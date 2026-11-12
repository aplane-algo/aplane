// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

func requireRotatingRefusal(t *testing.T, err *ServiceError, slot string) {
	t.Helper()
	if err == nil {
		t.Fatal("rotating account was not refused")
	}
	if err.Code() != signerapi.ErrCodeRotatingSigningRequired || err.HTTPStatus() != 400 {
		t.Fatalf("error = %q (%d), want %q", err.Code(), err.HTTPStatus(), signerapi.ErrCodeRotatingSigningRequired)
	}
	if !strings.Contains(err.Message, "/sign/rotating/prepare") {
		t.Fatalf("message %q does not name the rotating flow", err.Message)
	}
	if slot != "" && !strings.HasPrefix(err.Message, slot) {
		t.Fatalf("message %q does not start with %q", err.Message, slot)
	}
}

func TestVerifySignableKeysRefusesRotatingAccount(t *testing.T) {
	plain := types.Address{1}.String()
	rotating := types.Address{2}.String()
	requests := []signerapi.SignRequest{
		{AuthAddress: plain, TxnBytesHex: "deadbeef"},
		{AuthAddress: rotating, TxnBytesHex: "deadbeef"},
	}
	snapshot := PlannerRuntimeSnapshot{
		KeyFiles: map[string]string{plain: "a.key", rotating: "b.key"},
		KeyTypes: map[string]string{plain: "ed25519", rotating: rotatingkey.RotatingTripleWotscV1},
	}
	count, err := verifySignableKeys(nil, snapshot, requests, map[int]bool{}, map[int]bool{})
	if count != 0 {
		t.Fatalf("count = %d, want 0", count)
	}
	requireRotatingRefusal(t, err, "transaction 2:")
}

func TestExecutorRefusesRotatingSlotBeforeSessionLoad(t *testing.T) {
	plan := &PlanResult{
		AllTxns:            []types.Transaction{{}},
		PassthroughIndices: map[int]bool{},
		ForeignIndices:     map[int]bool{},
		AuthKeyTypes:       []string{rotatingkey.RotatingTripleWotscV1},
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR", TxnBytesHex: "deadbeef"}}}
	// A nil session would panic if the executor tried to load the key.
	_, err := (&Executor{}).ExecuteGroupSigning(context.Background(), plan, req, nil)
	requireRotatingRefusal(t, err, "transaction 1:")
}

func TestComponentRequestRefusesRotatingAccount(t *testing.T) {
	rotating := types.Address{2}.String()
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{rotating: rotatingkey.RotatingTripleWotscV1}}
	}}}
	req := signerapi.ComponentRequest{
		GroupBytesHex: []string{"deadbeef"},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: rotating}},
	}
	requireRotatingRefusal(t, svc.rejectRotatingComponentRequest(req), "transaction 1:")

	// A contextual position names its account outside the group request; a
	// rotating account there is refused too.
	context := signerapi.ComponentRequest{
		GroupBytesHex:       []string{"deadbeef", "deadbeef"},
		Targets:             []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: types.Address{9}.String()}},
		ContextualPositions: []signerapi.ComponentContextPosition{{TargetIndex: 1, AuthAddress: rotating}},
	}
	requireRotatingRefusal(t, svc.rejectRotatingComponentRequest(context), "transaction 2:")
}

func TestRejectRekeyToRotatingAccount(t *testing.T) {
	plain := types.Address{1}
	rotating := types.Address{2}
	stage := types.Address{3}
	other := types.Address{4}
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{
			plain.String():    "ed25519",
			rotating.String(): rotatingkey.RotatingTripleWotscV1,
		}}
	}}}
	rekey := func(sender, to types.Address) types.Transaction {
		return types.Transaction{Header: types.Header{Sender: sender, RekeyTo: to}}
	}
	err := svc.rejectRekeyToRotating([]types.Transaction{rekey(plain, other), rekey(plain, rotating)}, []int{0, 1})
	if want := "transaction 2: " + rotatingkey.RekeyTargetRefusal(rotating.String()); err == nil || err.HTTPStatus() != 403 || err.Message != want {
		t.Fatalf("rekey to a rotating account: err = %v, want 403 %q", err, want)
	}
	// Positions this signer doesn't sign are not judged.
	if err := svc.rejectRekeyToRotating([]types.Transaction{rekey(plain, rotating)}, nil); err != nil {
		t.Fatalf("an unsigned position was judged: %v", err)
	}
	// The rotating flow's own spend rekeys the account to its next stage.
	if err := svc.rejectRekeyToRotating([]types.Transaction{rekey(rotating, stage)}, []int{0}); err != nil {
		t.Fatalf("rotation to a stage address refused: %v", err)
	}
	if err := svc.rejectRekeyToRotating([]types.Transaction{rekey(plain, other), {Header: types.Header{Sender: plain}}}, []int{0, 1}); err != nil {
		t.Fatalf("ordinary rekey refused: %v", err)
	}
}

// A foreign or passthrough position isn't this signer's signature, so the
// gate sequence doesn't refuse its rekey to a rotating account.
func TestApprovalGatesSkipRotatingRekeyAtUnsignedPositions(t *testing.T) {
	sender := types.Address{1}
	rotating := types.Address{2}
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{rotating.String(): rotatingkey.RotatingTripleWotscV1}}
	}}}
	rekey := types.Transaction{Header: types.Header{Sender: sender, RekeyTo: rotating}}
	for name, in := range map[string]gateInput{
		"foreign":     {ForeignIndices: map[int]bool{0: true}},
		"passthrough": {PassthroughIndices: map[int]bool{0: true}},
	} {
		in.AllTxns = []types.Transaction{rekey}
		in.EvalCount = 1
		// No policy is loaded and the slot is not this signer's, so the policy
		// gate passes it and the operator default decides.
		in.RequestOperatorApproval = func(context.Context, string) *ServiceError { return forbidden("reached the operator") }
		_, err := svc.runApprovalGates(context.Background(), in, nil)
		if err == nil || err.Message != "reached the operator" {
			t.Fatalf("%s: err = %v, want it past the signer invariants", name, err)
		}
	}
}

func TestApprovalGatesRefuseRekeyToRotatingBeforePolicy(t *testing.T) {
	sender := types.Address{1}
	rotating := types.Address{2}
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{rotating.String(): rotatingkey.RotatingTripleWotscV1}}
	}}}
	var logged string
	// No policy is loaded, so reaching the policy gate would fail as internal.
	_, err := svc.runApprovalGates(context.Background(), gateInput{
		AllTxns:      []types.Transaction{{Header: types.Header{Sender: sender, RekeyTo: rotating}}},
		EvalCount:    1,
		LogRejection: func(reason string, _ int) { logged = reason },
		RequestOperatorApproval: func(context.Context, string) *ServiceError {
			t.Fatal("operator was asked")
			return nil
		},
	}, nil)
	if err == nil || err.HTTPStatus() != 403 || !strings.Contains(err.Message, "rotating account") {
		t.Fatalf("err = %v, want the rekey-to-rotating refusal", err)
	}
	if want := auditSignerInvariant + err.Message; logged != want {
		t.Fatalf("logged = %q, want %q: a signer invariant is audited as one on the signer role too", logged, want)
	}
}
