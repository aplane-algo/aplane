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
		KeyTypes: map[string]string{plain: "ed25519", rotating: rotatingkey.RotatingHybridV1},
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
		AuthKeyTypes:       []string{rotatingkey.RotatingHybridV1},
	}
	req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{{AuthAddress: "AUTHADDR", TxnBytesHex: "deadbeef"}}}
	// A nil session would panic if the executor tried to load the key.
	_, err := (&Executor{}).ExecuteGroupSigning(context.Background(), plan, req, nil)
	requireRotatingRefusal(t, err, "transaction 1:")
}

func TestComponentRequestRefusesRotatingAccount(t *testing.T) {
	rotating := types.Address{2}.String()
	svc := &Service{Planner: &Planner{Snapshot: func() PlannerRuntimeSnapshot {
		return PlannerRuntimeSnapshot{KeyTypes: map[string]string{rotating: rotatingkey.RotatingHybridV1}}
	}}}
	req := signerapi.ComponentRequest{
		GroupBytesHex: []string{"deadbeef"},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindUser, AuthAddress: rotating}},
	}
	requireRotatingRefusal(t, svc.rejectRotatingComponentRequest(req), "transaction 1:")
}
