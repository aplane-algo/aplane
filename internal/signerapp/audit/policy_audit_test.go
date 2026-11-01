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
	"unicode/utf8"

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

// Request strings are logged before validation, so each is bounded: an
// oversized request leaves small entries, and the log stays readable.
func TestMutationEntriesBoundRequestStrings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	huge := strings.Repeat("é", 128*1024) // 256 KiB, multibyte
	ctx := adminserver.SessionContext{}
	if err := logger.LogPolicyApplyIntentDurableContext(ctx, "apply-1", adminproto.ApplyPolicyRequest{
		Documents: []adminproto.PolicyDocument{{Key: huge}}, Remove: []string{huge},
		ExpectedPolicySetSHA256: huge, ExpectedSnapshotSHA256: huge,
	}); err != nil {
		t.Fatal(err)
	}
	logger.LogPolicyApplyResultContext(ctx, "apply-1", adminproto.ApplyPolicyResult{Code: huge, Error: "invalid selector " + huge})
	if err := logger.LogASASetUpdateIntentDurableContext(ctx, "add-1", "add", huge, huge, 1); err != nil {
		t.Fatal(err)
	}
	logger.LogASASetAddResultContext(ctx, "add-1", adminproto.AddASARequest{Confirmed: adminproto.ASAObservation{Network: huge, GenesisHash: huge}},
		adminproto.AddASAResult{Code: huge, Error: huge})
	logger.LogASASetRemoveResultContext(ctx, "rm-1", adminproto.RemoveASARequest{Network: huge, GenesisHash: huge},
		adminproto.RemoveASAResult{Code: huge, Error: huge})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if len(line) > 4096 {
			t.Fatalf("entry %d is %d bytes", i, len(line))
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("entry %d is not valid JSON after bounding: %v", i, err)
		}
	}
	if !strings.Contains(string(data), "(262144 bytes)") {
		t.Fatal("a bounded field does not say how long it was")
	}
}

func TestBoundTextCutsAtACharacterBoundary(t *testing.T) {
	for _, tt := range []struct {
		in    string
		limit int
	}{
		{"short", 128},
		{strings.Repeat("a", 500), 128},
		{strings.Repeat("é", 500), 128},
		{strings.Repeat("😀", 500), 33},
	} {
		got := boundText(tt.in, tt.limit)
		if len(got) > tt.limit && len(tt.in) > tt.limit {
			t.Fatalf("boundText(%d bytes, %d) = %d bytes", len(tt.in), tt.limit, len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatalf("boundText cut inside a character: %q", got)
		}
		if len(tt.in) <= tt.limit && got != tt.in {
			t.Fatalf("a short string changed: %q", got)
		}
	}
}

// One oversized line, from any event, must not hide the release history.
func TestReadRotatingReleasesSkipsAnOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := Attribution{RequesterPrincipal: "client-1", Transport: "http"}
	if err := logger.LogRotatingReleaseAttributed(attr, "ACCT1", "TX1", 3, 100, 0, 0); err != nil {
		t.Fatal(err)
	}
	logger.Log(AuditEntry{Event: "SOMETHING_LARGE", Reason: strings.Repeat("x", 3<<20)})
	if err := logger.LogRotatingReleaseAttributed(attr, "ACCT2", "TX2", 5, 200, 0, 0); err != nil {
		t.Fatal(err)
	}
	_ = logger.Close()
	// A last line with no newline is read too.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"event":"ROTATING_RELEASE","txn_auth":"ACCT3","txid":"TX3","rotating_stage":1,"rotating_last_valid":9}`); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	got, err := ReadRotatingReleases(path)
	if err != nil {
		t.Fatalf("ReadRotatingReleases after an oversized line: %v", err)
	}
	if got["ACCT1"].Stage != 3 || got["ACCT2"].Stage != 5 || got["ACCT3"].TxID != "TX3" {
		t.Fatalf("releases = %+v", got)
	}
}

// An oversized operation ID becomes a short, stable digest form, in every
// entry that carries one, so an intent and its outcome still correlate.
func TestOversizedOperationIDsAreBoundedAndStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	huge := strings.Repeat("é", 128*1024)
	ctx := adminserver.SessionContext{}
	if err := logger.LogPolicyApplyIntentDurableContext(ctx, huge, adminproto.ApplyPolicyRequest{}); err != nil {
		t.Fatal(err)
	}
	logger.LogPolicyApplyResultContext(ctx, huge, adminproto.ApplyPolicyResult{Code: "invalid_policy_request"})
	if err := logger.LogASASetUpdateIntentDurableContext(ctx, huge, "add", "mainnet", "", 1); err != nil {
		t.Fatal(err)
	}
	logger.LogASASetAddResultContext(ctx, huge, adminproto.AddASARequest{}, adminproto.AddASAResult{Code: "unknown_network"})
	if err := logger.LogCredentialRestoreIntentDurableContext(ctx, huge, "backup.tar.gz", false); err != nil {
		t.Fatal(err)
	}
	logger.LogPolicyApplyResultContext(ctx, "apply-short", adminproto.ApplyPolicyResult{Code: "x"})

	entries := mutationEntries(t, path)
	first := entries[0]["operation_id"].(string)
	if len(first) > maxAuditOperationID || !strings.Contains(first, "…sha256:") || !utf8.ValidString(first) {
		t.Fatalf("bounded operation ID %q", first)
	}
	for i, e := range entries[:5] {
		if e["operation_id"] != first {
			t.Fatalf("entry %d operation ID %v, want the same bounded form %q", i, e["operation_id"], first)
		}
	}
	if entries[5]["operation_id"] != "apply-short" {
		t.Fatalf("a short operation ID changed: %v", entries[5]["operation_id"])
	}
	if got := boundOperationID(huge + "x"); got == first {
		t.Fatal("two different IDs bounded to the same value")
	}
	if data, _ := os.ReadFile(path); len(data) > 8*1024 {
		t.Fatalf("six entries wrote %d bytes", len(data))
	}
}
