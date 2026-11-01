// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// auditEntries reads the audit log's entries of the given events.
func auditEntries(t *testing.T, path string, events ...string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("audit line %q: %v", line, err)
		}
		for _, e := range events {
			if entry["event"] == e {
				out = append(out, entry)
			}
		}
	}
	return out
}

// Applies through a real admin session record the session's actor, the
// request's expectations, and what the commit did: a change, a no-op, or a
// refusal, each as one outcome after one intent.
func TestPolicyApplyAuditThroughTheDaemon(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ir := server.productRuntime()
	ipcServer := &IPCServer{signer: server}
	auditPath := filepath.Join(server.dataDir, "audit.log")

	apply := func(id, document, expectedSet, expectedSnapshot string) map[string]any {
		t.Helper()
		recorder := &ipcJSONRecorderConn{}
		dispatchIPCMessage(t, newBoundTestSession(ipcServer, recorder, ir), protocol.ApplyPolicyMessage{
			BaseMessage:             protocol.BaseMessage{Type: protocol.MsgTypeApplyPolicy, ID: id},
			Documents:               []protocol.PolicyDocumentWire{{Key: policy.DefaultKey, Document: document}},
			ExpectedPolicySetSHA256: expectedSet,
			ExpectedSnapshotSHA256:  expectedSnapshot,
		})
		msgs := recorder.messages(t)
		if len(msgs) != 1 {
			t.Fatalf("%s: responses %#v", id, msgs)
		}
		return msgs[0]
	}
	context := func() adminproto.PolicyContextView {
		view := server.adminServices().adminApp().GetPolicyContext()
		if !view.Success {
			t.Fatalf("GetPolicyContext = %+v", view)
		}
		return view
	}

	stricter := policytest.MustDocument(noderole.RoleSigner, policy.DefaultKey,
		`{"max_fee_microalgos": "5000", "transfer_policy":{"on_no_route":"operator_default","close_on_no_route":"operator_default","clawback_on_no_route":"operator_default"}}`)
	before := context()
	if got := apply("apply-change", stricter, before.PolicySetSHA256, before.SnapshotSHA256); got["success"] != true {
		t.Fatalf("apply-change = %#v", got)
	}
	after := context()
	if got := apply("apply-noop", stricter, after.PolicySetSHA256, after.SnapshotSHA256); got["success"] != true {
		t.Fatalf("apply-noop = %#v", got)
	}
	if got := apply("apply-stale", stricter, before.PolicySetSHA256, before.SnapshotSHA256); got["success"] == true || got["code"] != "policy_snapshot_changed" {
		t.Fatalf("apply-stale = %#v", got)
	}

	intents := auditEntries(t, auditPath, "POLICY_APPLY_INTENT")
	outcomes := auditEntries(t, auditPath, "POLICY_APPLY_SUCCEEDED", "POLICY_APPLY_FAILED", "POLICY_APPLY_COMMIT_UNCERTAIN")
	if len(intents) != 3 || len(outcomes) != 3 {
		t.Fatalf("intents %d, outcomes %d, want 3 each", len(intents), len(outcomes))
	}
	for i, id := range []string{"apply-change", "apply-noop", "apply-stale"} {
		for _, entry := range []map[string]any{intents[i], outcomes[i]} {
			if entry["operation_id"] != id || entry["principal"] == nil || entry["admin_session_id"] == nil || entry["transport"] != "ipc" {
				t.Fatalf("%s entry lacks attribution: %#v", id, entry)
			}
		}
		if updates, _ := intents[i]["policy_updates"].([]any); len(updates) != 1 || updates[0] != "default" {
			t.Fatalf("%s intent updates: %#v", id, intents[i])
		}
		if strings.Contains(intents[i]["policy_updates"].([]any)[0].(string), "max_fee") {
			t.Fatal("an intent carries document contents")
		}
	}
	change, noop, stale := outcomes[0], outcomes[1], outcomes[2]
	if change["event"] != "POLICY_APPLY_SUCCEEDED" || change["changed"] != true || change["generation_id"] == nil ||
		change["base_policy_set_sha256"] != before.PolicySetSHA256 || change["policy_set_sha256"] != after.PolicySetSHA256 {
		t.Fatalf("change outcome: %#v (before %s after %s)", change, before.PolicySetSHA256, after.PolicySetSHA256)
	}
	if intents[0]["expected_snapshot_sha256"] != before.SnapshotSHA256 {
		t.Fatalf("intent expectations: %#v", intents[0])
	}
	if noop["event"] != "POLICY_APPLY_SUCCEEDED" || noop["changed"] != false || noop["generation_id"] != nil {
		t.Fatalf("no-op outcome: %#v", noop)
	}
	if stale["event"] != "POLICY_APPLY_FAILED" || stale["result_code"] != "policy_snapshot_changed" || stale["changed"] != nil {
		t.Fatalf("stale outcome: %#v", stale)
	}
}

func TestASASetUpdateAuditThroughTheDaemon(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ipcServer := &IPCServer{signer: server}
	recorder := &ipcJSONRecorderConn{}
	dispatchIPCMessage(t, newBoundTestSession(ipcServer, recorder, server.productRuntime()), protocol.RemoveASAMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRemoveASA, ID: "rm-1"},
		Network:     "mainnet", AssetID: 9,
	})
	if msgs := recorder.messages(t); len(msgs) != 1 || msgs[0]["success"] == true {
		t.Fatalf("remove of a missing entry = %#v", msgs)
	}
	path := filepath.Join(server.dataDir, "audit.log")
	intent := auditEntries(t, path, "ASA_SET_UPDATE_INTENT")
	failed := auditEntries(t, path, "ASA_SET_UPDATE_FAILED")
	if len(intent) != 1 || intent[0]["asa_action"] != "remove" || intent[0]["network"] != "mainnet" || intent[0]["asset_id"] != float64(9) {
		t.Fatalf("intent: %#v", intent)
	}
	if len(failed) != 1 || failed[0]["operation_id"] != "rm-1" || failed[0]["result_code"] == nil || len(auditEntries(t, path, "ASA_SET_UPDATE_SUCCEEDED")) != 0 {
		t.Fatalf("outcome: %#v", failed)
	}
}

// Without a logger the forwarders fail closed with ErrAuditUnavailable, so
// the session tells the operator to restart rather than retry.
func TestMutationIntentForwardersFailClosedWithoutALogger(t *testing.T) {
	svc := (&Signer{}).adminServices()
	if err := svc.LogPolicyApplyIntentDurableContext(adminserver.SessionContext{}, "apply-1", adminproto.ApplyPolicyRequest{}); !errors.Is(err, adminserver.ErrAuditUnavailable) {
		t.Fatalf("policy intent without a logger: %v", err)
	}
	if err := svc.LogASASetUpdateIntentDurableContext(adminserver.SessionContext{}, "add-1", "add", "mainnet", "", 9); !errors.Is(err, adminserver.ErrAuditUnavailable) {
		t.Fatalf("ASA intent without a logger: %v", err)
	}
	// Outcomes without a logger are dropped, never a panic.
	svc.LogPolicyApplyResultContext(adminserver.SessionContext{}, "apply-1", adminproto.ApplyPolicyResult{})
	svc.LogASASetAddResultContext(adminserver.SessionContext{}, "add-1", adminproto.AddASARequest{}, adminproto.AddASAResult{})
	svc.LogASASetRemoveResultContext(adminserver.SessionContext{}, "rm-1", adminproto.RemoveASARequest{}, adminproto.RemoveASAResult{})
}
