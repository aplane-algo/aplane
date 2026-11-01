// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func mutationEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		out = append(out, entry)
	}
	return out
}

func TestPolicyApplyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	ctx := adminserver.SessionContext{SessionID: "s-1", Transport: "ipc", AdminPrincipal: adminserver.SessionPrincipal{ID: "operator"}}

	docs := make([]adminproto.PolicyDocument, 70)
	for i := range docs {
		docs[i] = adminproto.PolicyDocument{Key: fmt.Sprintf("KEY%02d", i), Document: `{"secret": "contents"}`}
	}
	if err := logger.LogPolicyApplyIntentDurableContext(ctx, "apply-1", adminproto.ApplyPolicyRequest{
		Documents: docs, Remove: []string{"OLD"}, ExpectedPolicySetSHA256: "set-a", ExpectedSnapshotSHA256: "snap-a",
	}); err != nil {
		t.Fatal(err)
	}
	logger.LogPolicyApplyResultContext(ctx, "apply-1", adminproto.ApplyPolicyResult{Success: true, Changed: false, BasePolicySetSHA256: "set-a", PolicySetSHA256: "set-a"})
	logger.LogPolicyApplyResultContext(ctx, "apply-2", adminproto.ApplyPolicyResult{Success: true, Changed: true, GenerationID: "gen-2"})
	logger.LogPolicyApplyResultContext(ctx, "apply-3", adminproto.ApplyPolicyResult{CommitUncertain: true, GenerationID: "gen-3", Code: "policy_commit_uncertain", Error: "durability unknown"})
	logger.LogPolicyApplyResultContext(ctx, "apply-4", adminproto.ApplyPolicyResult{Code: "policy_validation_failed", Error: "invalid"})

	entries := mutationEntries(t, path)
	if len(entries) != 5 {
		t.Fatalf("%d entries", len(entries))
	}
	intent := entries[0]
	if intent["event"] != "POLICY_APPLY_INTENT" || intent["principal"] == nil || intent["policy_updates_omitted"] != float64(6) ||
		len(intent["policy_updates"].([]any)) != 64 || intent["expected_snapshot_sha256"] != "snap-a" {
		t.Fatalf("intent: %#v", intent)
	}
	if line, _ := os.ReadFile(path); strings.Contains(string(line), "secret") {
		t.Fatal("an entry carries document contents")
	}
	if noop := entries[1]; noop["event"] != "POLICY_APPLY_SUCCEEDED" || noop["changed"] != false {
		t.Fatalf("a no-op does not record changed false: %#v", noop)
	}
	if changed := entries[2]; changed["changed"] != true || changed["generation_id"] != "gen-2" {
		t.Fatalf("change: %#v", changed)
	}
	if uncertain := entries[3]; uncertain["event"] != "POLICY_APPLY_COMMIT_UNCERTAIN" || uncertain["changed"] != nil || uncertain["generation_id"] != "gen-3" || uncertain["result_code"] != "policy_commit_uncertain" {
		t.Fatalf("an uncertain commit: %#v", uncertain)
	}
	if failed := entries[4]; failed["event"] != "POLICY_APPLY_FAILED" || failed["changed"] != nil || failed["result_code"] != "policy_validation_failed" {
		t.Fatalf("a failure: %#v", failed)
	}
}

func TestASASetUpdateEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	ctx := adminserver.SessionContext{SessionID: "s-1"}
	if err := logger.LogASASetUpdateIntentDurableContext(ctx, "rm-1", "remove", "", "chain-b", 9); err != nil {
		t.Fatal(err)
	}
	logger.LogASASetRemoveResultContext(ctx, "rm-1", adminproto.RemoveASARequest{Network: "private-dev", AssetID: 9},
		adminproto.RemoveASAResult{Success: true, GenerationID: "gen-4", GenesisHash: "chain-a"})
	logger.LogASASetAddResultContext(ctx, "add-1", adminproto.AddASARequest{Confirmed: adminproto.ASAObservation{Network: "mainnet", GenesisHash: "chain-m", AssetID: 5}},
		adminproto.AddASAResult{Code: "asa_duplicate", Error: "already confirmed"})
	logger.LogASASetAddResultContext(ctx, "add-2", adminproto.AddASARequest{},
		adminproto.AddASAResult{CommitUncertain: true, GenerationID: "gen-5", Code: "asa_commit_uncertain"})

	entries := mutationEntries(t, path)
	if intent := entries[0]; intent["event"] != "ASA_SET_UPDATE_INTENT" || intent["asa_action"] != "remove" || intent["genesis_hash"] != "chain-b" {
		t.Fatalf("intent: %#v", intent)
	}
	if removed := entries[1]; removed["event"] != "ASA_SET_UPDATE_SUCCEEDED" || removed["changed"] != true || removed["genesis_hash"] != "chain-a" || removed["network"] != "private-dev" {
		t.Fatalf("a removal does not record the chain it resolved to: %#v", removed)
	}
	if dup := entries[2]; dup["event"] != "ASA_SET_UPDATE_FAILED" || dup["result_code"] != "asa_duplicate" || dup["asset_id"] != float64(5) {
		t.Fatalf("a duplicate add: %#v", dup)
	}
	if uncertain := entries[3]; uncertain["event"] != "ASA_SET_UPDATE_COMMIT_UNCERTAIN" || uncertain["changed"] != nil || uncertain["generation_id"] != "gen-5" {
		t.Fatalf("an uncertain add: %#v", uncertain)
	}
}

// An intent that cannot be synced is an error, so the change is refused.
func TestMutationIntentFailsWhenTheLogIsUnwritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = logger.file.Close()
	if err := logger.LogPolicyApplyIntentDurableContext(adminserver.SessionContext{}, "apply-1", adminproto.ApplyPolicyRequest{}); err == nil {
		t.Fatal("an intent on a closed log reported success")
	}
	if err := logger.LogASASetUpdateIntentDurableContext(adminserver.SessionContext{}, "add-1", "add", "mainnet", "", 1); err == nil {
		t.Fatal("an ASA intent on a closed log reported success")
	}
}
