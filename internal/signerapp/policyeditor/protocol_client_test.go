// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type fakeAdminMessageRequester struct {
	response []byte
	err      error
	message  interface{}
	timeout  time.Duration
}

func (f *fakeAdminMessageRequester) SendAndReceive(message interface{}, timeout time.Duration) ([]byte, error) {
	f.message = message
	f.timeout = timeout
	return f.response, f.err
}

func TestProtocolClientReplacePolicyMapsWireRequestAndResponse(t *testing.T) {
	response, err := json.Marshal(protocol.ReplacePolicyResultMessage{
		BaseMessage:  protocol.BaseMessage{Type: protocol.MsgTypeReplacePolicyResult, ID: "response"},
		Success:      true,
		Target:       string(TargetSentry),
		PolicyYAML:   "reject_rekey: true\n",
		PolicySHA256: "new-sha",
	})
	if err != nil {
		t.Fatal(err)
	}
	requester := &fakeAdminMessageRequester{response: response}
	client := NewProtocolClient(requester, 3*time.Second)

	snapshot, err := client.ReplacePolicy(t.Context(), TargetSentry, "reject_rekey: true\n", "old-sha")
	if err != nil {
		t.Fatalf("ReplacePolicy() error = %v", err)
	}
	request, ok := requester.message.(protocol.ReplacePolicyMessage)
	if !ok {
		t.Fatalf("message type = %T, want protocol.ReplacePolicyMessage", requester.message)
	}
	if request.Target != "sentry" || request.ExpectedCurrentSHA256 != "old-sha" {
		t.Fatalf("request = %#v, want sentry target and old-sha", request)
	}
	if requester.timeout != 3*time.Second {
		t.Fatalf("timeout = %s, want 3s", requester.timeout)
	}
	if !snapshot.Success || snapshot.Target != TargetSentry || snapshot.PolicySHA256 != "new-sha" {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}
