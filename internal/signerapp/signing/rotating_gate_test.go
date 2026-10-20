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
		KeyTypes: map[string]string{plain: "ed25519", rotating: rotatingkey.RotatingTripleWotsV1},
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
		AuthKeyTypes:       []string{rotatingkey.RotatingTripleWotsV1},
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR", TxnBytesHex: "deadbeef"}}}
	// A nil session would panic if the executor tried to load the key.
	_, err := (&Executor{}).ExecuteGroupSigning(context.Background(), plan, req, nil)
	requireRotatingRefusal(t, err, "transaction 1:")
}

func TestComponentRequestRefusesRotatingAccount(t *testing.T) {
	rotating := types.Address{2}.String()
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{rotating: rotatingkey.RotatingTripleWotsV1}}
	}}}
	req := signerapi.ComponentRequest{
		GroupBytesHex: []string{"deadbeef"},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindUser, AuthAddress: rotating}},
	}
	requireRotatingRefusal(t, svc.rejectRotatingComponentRequest(req), "transaction 1:")
}

func TestRejectRekeyToRotatingAccount(t *testing.T) {
	plain := types.Address{1}
	rotating := types.Address{2}
	stage := types.Address{3}
	other := types.Address{4}
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{
			plain.String():    "ed25519",
			rotating.String(): rotatingkey.RotatingTripleWotsV1,
		}}
	}}}
	rekey := func(sender, to types.Address) types.Transaction {
		return types.Transaction{Header: types.Header{Sender: sender, RekeyTo: to}}
	}
	none := map[int]bool{}

	err := svc.rejectRekeyToRotating([]types.Transaction{rekey(plain, other), rekey(plain, rotating)}, 2, none, none)
	if err == nil || err.HTTPStatus() != 403 || !strings.HasPrefix(err.Message, "transaction 2:") || !strings.Contains(err.Message, rotating.String()) {
		t.Fatalf("rekey to a rotating account: err = %v", err)
	}
	if err := svc.rejectRekeyToRotating([]types.Transaction{rekey(plain, rotating)}, 1, none, map[int]bool{0: true}); err != nil {
		t.Fatalf("foreign position was judged: %v", err)
	}
	// The rotating flow's own spend rekeys the account to its next stage.
	if err := svc.rejectRekeyToRotating([]types.Transaction{rekey(rotating, stage)}, 1, none, none); err != nil {
		t.Fatalf("rotation to a stage address refused: %v", err)
	}
	if err := svc.rejectRekeyToRotating([]types.Transaction{rekey(plain, other), {Header: types.Header{Sender: plain}}}, 2, none, none); err != nil {
		t.Fatalf("ordinary rekey refused: %v", err)
	}
}

func TestApprovalGatesRefuseRekeyToRotatingBeforePolicy(t *testing.T) {
	sender := types.Address{1}
	rotating := types.Address{2}
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{rotating.String(): rotatingkey.RotatingTripleWotsV1}}
	}}}
	var logged string
	// No policy is loaded, so reaching the policy gate would fail as internal.
	_, err := svc.runApprovalGates(context.Background(), gateInput{
		AllTxns:      []types.Transaction{{Header: types.Header{Sender: sender, RekeyTo: rotating}}},
		EvalCount:    1,
		LogRejection: func(reason string) { logged = reason },
		RequestOperatorApproval: func(context.Context, string) *ServiceError {
			t.Fatal("operator was asked")
			return nil
		},
	}, nil)
	if err == nil || err.HTTPStatus() != 403 || !strings.Contains(err.Message, "rotating account") {
		t.Fatalf("err = %v, want the rekey-to-rotating refusal", err)
	}
	if logged == "" {
		t.Fatal("rejection was not logged")
	}
}
