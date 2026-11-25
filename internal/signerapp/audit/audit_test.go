// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestRotateArchivesAndContinues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Log(AuditEntry{Event: "before-rotate"})
	if err := a.rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	a.Log(AuditEntry{Event: "after-rotate"})

	archived, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read archived log: %v", err)
	}
	if !strings.Contains(string(archived), "before-rotate") {
		t.Fatalf("archived log missing pre-rotate entry: %s", archived)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current log: %v", err)
	}
	if !strings.Contains(string(current), "after-rotate") {
		t.Fatalf("current log missing post-rotate entry: %s", current)
	}
}

func TestCredentialRestoreDurabilityUnknownHasDistinctEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogCredentialRestoreContext(adminserver.SessionContext{}, adminproto.RestoreBackupResult{
		OperationID:     "restore-uncertain",
		GenerationID:    "gen-1-12345678",
		CommitUncertain: true,
		Error:           "CURRENT durability unconfirmed",
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, data)
	}
	if entry.Event != AuditCredentialRestoreUncertain || entry.Outcome != "failed" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

// A rollback that may have committed is recorded as such, with the
// generation its result names.
func TestRestoreRollbackThatMayHaveCommittedNamesItsGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogCredentialRestoreRollbackContext(adminserver.SessionContext{}, adminproto.RollbackRestoreResult{
		OperationID:     "rollback-uncertain",
		GenerationID:    "gen-1-12345678",
		CommitUncertain: true,
		Error:           "rollback may have committed as generation gen-1-12345678",
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, data)
	}
	if entry.Event != AuditCredentialRestoreRollback || entry.Outcome != "commit_uncertain" || entry.GenerationID != "gen-1-12345678" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

// A rollback whose commit landed but whose reload failed is recorded as
// failed, with its generation: the commit is not in doubt.
func TestRestoreRollbackWhoseReloadFailedIsNotUncertain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogCredentialRestoreRollbackContext(adminserver.SessionContext{}, adminproto.RollbackRestoreResult{
		OperationID:  "rollback-reload-failed",
		GenerationID: "gen-1-12345678",
		Error:        "restore rollback committed as generation gen-1-12345678 but reload failed",
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("decode audit entry: %v\n%s", err, data)
	}
	if entry.Outcome != "failed" || entry.GenerationID != "gen-1-12345678" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

func TestCosignerReferenceAuditIncludesWitnessKeyID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogCosignerReferenceChangedContext(adminserver.SessionContext{}, "import", "prod-cosigner", "WITNESSKEYID", true)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Event != AuditCosignerReferenceChanged || entry.WitnessKeyID != "WITNESSKEYID" ||
		entry.Outcome != "import" {
		t.Fatalf("audit entry = %+v", entry)
	}
}

// A failed setting save is recorded with the session, the setting, the value
// it tried to save, the cause, and whether that value is in effect anyway
// (outcome "applied") or nothing changed (outcome "failed").
func TestSettingSaveErrorAuditNamesTheSettingValueAndWhetherInEffect(t *testing.T) {
	for _, inEffect := range []bool{true, false} {
		path := filepath.Join(t.TempDir(), "audit.log")
		a, err := NewAuditLogger(path)
		if err != nil {
			t.Fatal(err)
		}
		a.LogSettingSaveErrorContext(adminserver.SessionContext{
			SessionID: "admin-7", AdminPrincipal: adminserver.SessionPrincipal{ID: "system:product-admin"},
		}, "user_auto_approve", "false", inEffect, "disk full")
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var entry AuditEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			t.Fatal(err)
		}
		outcome := map[bool]string{true: "applied", false: "failed"}[inEffect]
		reason := fmt.Sprintf("setting=user_auto_approve value=false in_effect=%t: disk full", inEffect)
		if entry.Event != AuditSettingSaveError || entry.Outcome != outcome || entry.Reason != reason ||
			entry.AdminSessionID != "admin-7" || entry.Principal != "system:product-admin" {
			t.Fatalf("in effect %v: audit entry = %+v", inEffect, entry)
		}
	}
}

func TestLogRecoversAfterLostHandle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	// Simulate the state a failed rotation leaves behind: no usable handle.
	_ = a.file.Close()
	a.file = nil

	a.Log(AuditEntry{Event: "after-failure"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(data), "after-failure") {
		t.Fatalf("entry written after lost handle missing: %s", data)
	}
	if a.file == nil {
		t.Fatal("Log should have recovered a usable handle")
	}
}

func TestReopenCurrentRestoresByteCounter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = a.Close() }()

	a.Log(AuditEntry{Event: "sized-entry"})
	want := a.written
	if want == 0 {
		t.Fatal("expected non-zero written counter after a log entry")
	}

	_ = a.file.Close()
	a.file = nil
	a.reopenCurrent()

	if a.written != want {
		t.Fatalf("written = %d after reopen, want %d (rotation threshold drifts otherwise)", a.written, want)
	}
}

// A /plan slot is its own event, not a request to sign.
func TestPlanRequestIsItsOwnEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := Attribution{RequesterPrincipal: "client:SHA256:abc", Transport: "http"}
	a.LogPlanRequestAttributed(attr, "ADDR", "ADDR", "", "pay 1 ALGO")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 1 || entries[0].Event != AuditPlanRequest || entries[0].Outcome != "requested" ||
		entries[0].TxnAuth != "ADDR" || entries[0].TxnDetails != "pay 1 ALGO" || entries[0].RequesterPrincipal != "client:SHA256:abc" {
		t.Fatalf("entries = %+v, want one PLAN_REQUEST", entries)
	}
}

// A signed transaction is recorded as signed, with the request it belongs to;
// a /plan slot is its own event and records nothing as signed.
func TestSigningEntriesCarryTheRequestAndTheSignedGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := Attribution{RequesterPrincipal: "client:SHA256:abc", Transport: "http", RequestID: "req-7"}
	a.LogPlanRequestAttributed(attr, "ADDR", "ADDR", "", "pay 1 ALGO")
	a.LogSignRequestAttributed(attr, "ADDR", "ADDR", "", "pay 1 ALGO")
	a.LogSignApprovedAttributed(attr, TxnRecord{
		TxnAuth: "ADDR", TxnSender: "ADDR", TxnDetails: "txn 1/1 signed",
		TxID: "TXA", Fee: 0, GroupID: "R1JPVVA=", GroupTxIDs: []string{"TXA", "TXD"}, DummyCount: 1,
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	entries := readAuditEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("%d entries, want 3", len(entries))
	}
	plan, request, approved := entries[0], entries[1], entries[2]
	if plan.Event != AuditPlanRequest || plan.Outcome != "requested" || plan.TxID != "" || plan.Fee != nil {
		t.Fatalf("plan entry = %+v", plan)
	}
	if request.Event != AuditSignRequest {
		t.Fatalf("request entry = %+v", request)
	}
	for _, e := range entries {
		if e.OperationID != "req-7" {
			t.Fatalf("%s operation_id = %q, want the request ID", e.Event, e.OperationID)
		}
	}
	if approved.Event != AuditSignApproved || approved.TxID != "TXA" || approved.GroupID != "R1JPVVA=" ||
		len(approved.GroupTxIDs) != 2 || approved.GroupTxIDs[1] != "TXD" || approved.DummyCount != 1 {
		t.Fatalf("approved entry = %+v", approved)
	}
	// A zero fee is a fact about the signed transaction, so it is written.
	if approved.Fee == nil || *approved.Fee != 0 {
		t.Fatalf("approved fee = %v, want 0 written", approved.Fee)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"fee":0`) {
		t.Fatalf("zero fee missing from the log:\n%s", data)
	}
}

// A signature withheld after it was recorded as signed is a SIGN_FAILED under
// the same txid and group_id, so a search on either finds both entries.
func TestWithheldSignatureCarriesTheSignedTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := Attribution{RequesterPrincipal: "client:SHA256:abc", Transport: "http", RequestID: "req-8"}
	a.LogSignApprovedAttributed(attr, TxnRecord{
		TxnAuth: "ADDR", TxnSender: "ADDR", TxID: "TXA", GroupID: "R1JPVVA=", GroupTxIDs: []string{"TXA", "TXD"}, DummyCount: 1,
	})
	a.LogSignWithheldAttributed(attr, "ADDR", "ADDR", "TXA", "R1JPVVA=", "signature withheld after it was recorded as signed: signer is locked")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	entries := readAuditEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("%d entries, want 2", len(entries))
	}
	approved, withheld := entries[0], entries[1]
	if withheld.Event != AuditSignFailed || withheld.Outcome != "failed" || withheld.OperationID != "req-8" {
		t.Fatalf("withheld entry = %+v", withheld)
	}
	if withheld.TxID != approved.TxID || withheld.GroupID != approved.GroupID {
		t.Fatalf("withheld txid %q group %q, want the approved %q %q", withheld.TxID, withheld.GroupID, approved.TxID, approved.GroupID)
	}
	// It retracts the signature; it does not restate the signed group.
	if withheld.Fee != nil || withheld.GroupTxIDs != nil || withheld.DummyCount != 0 {
		t.Fatalf("withheld entry restates the signed group: %+v", withheld)
	}
}

// A refusal that names one transaction is a SIGN_REJECTED that identifies it
// as a SIGN_APPROVED would: its txid, and the group's group_id and
// group_txids, so a search on any of them finds it. txn_auth is empty for a
// position the signer does not sign.
func TestRejectionNamingATransactionIdentifiesItAsApprovalWould(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	attr := Attribution{RequesterPrincipal: "client:SHA256:abc", Transport: "http", RequestID: "req-9"}
	reason := "signer_invariant: transaction 2: rekey_target_not_valid: cannot rekey to TARGET"
	a.LogSignRejectedTxnAttributed(attr, TxnRecord{
		TxnSender: "SENDER", TxID: "TXB", Fee: 1000, GroupID: "R1JPVVA=", GroupTxIDs: []string{"TXA", "TXB"},
	}, reason)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("%d entries, want 1", len(entries))
	}
	got := entries[0]
	if got.Event != AuditSignRejected || got.Outcome != "rejected" || got.OperationID != "req-9" ||
		got.TxnAuth != "" || got.TxnSender != "SENDER" || got.TxID != "TXB" || got.Reason != reason ||
		got.GroupID != "R1JPVVA=" || len(got.GroupTxIDs) != 2 || got.GroupTxIDs[1] != "TXB" || got.Fee == nil || *got.Fee != 1000 {
		t.Fatalf("rejection entry = %+v", got)
	}
}

// One request's SIGN_APPROVED entries share its group_txids slice, so
// writing an entry never changes it, even when the entry is bounded.
func TestSignApprovedLeavesTheSharedGroupTxIDsAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	shared := make([]string, maxAuditSelectors+2)
	for i := range shared {
		shared[i] = fmt.Sprintf("TX%d", i)
	}
	shared[0] = strings.Repeat("X", maxAuditField+10)
	want := append([]string(nil), shared...)
	for i := 0; i < 2; i++ {
		a.LogSignApprovedAttributed(Attribution{RequestID: "req-9"}, TxnRecord{TxnAuth: "ADDR", TxID: "TX1", GroupID: "R1JPVVA=", GroupTxIDs: shared})
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(shared, want) {
		t.Fatal("writing the entries changed the shared group_txids")
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 2 || len(entries[1].GroupTxIDs) != maxAuditSelectors || entries[1].GroupTxIDsOmitted != 2 {
		t.Fatalf("entries = %+v, want each bounded to %d group_txids", entries, maxAuditSelectors)
	}
}

func TestSettingChangeIntentAndChangedAuditCarrySessionAndValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := adminserver.WithSessionContext(context.Background(), adminserver.SessionContext{
		SessionID:      "admin-42",
		Origin:         adminserver.OriginLocal,
		AdminPrincipal: adminserver.SessionPrincipal{ID: "system:product-admin"},
	})
	if err := a.LogSettingChangeIntentDurable(ctx, "op-9", "user_auto_approve", "false", "true"); err != nil {
		t.Fatalf("LogSettingChangeIntentDurable: %v", err)
	}
	a.LogSettingChanged(ctx, "op-9", "user_auto_approve", "false", "true")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	wantReason := "setting=user_auto_approve old=false new=true"
	if e := entries[0]; e.Event != AuditSettingChangeIntent || e.Outcome != "requested" ||
		e.OperationID != "op-9" || e.AdminSessionID != "admin-42" || e.Transport != "ipc" || e.Reason != wantReason {
		t.Fatalf("intent entry = %+v", e)
	}
	if e := entries[1]; e.Event != AuditSettingChanged || e.Outcome != "changed" ||
		e.OperationID != "op-9" || e.AdminSessionID != "admin-42" || e.Transport != "ipc" || e.Reason != wantReason {
		t.Fatalf("changed entry = %+v", e)
	}
}

func TestSSHSessionAuditUsesClientPrincipalAndSSHTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogSSHSessionConnected("10.0.0.1:5000", "SHA256:fp1", true)
	a.LogSSHSessionConnected("10.0.0.2:5001", "SHA256:fp2", false)
	a.LogSSHSessionDisconnected("10.0.0.2:5001", "SHA256:fp2", false)
	a.LogSSHSessionConnected("10.0.0.3:5002", "", false)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
	if e := entries[0]; e.Principal != "client:SHA256:fp1" || e.RequesterPrincipal != "client:SHA256:fp1" ||
		e.Transport != "ssh" || e.Reason != "ssh" || e.SSHFingerprint != "SHA256:fp1" {
		t.Fatalf("enrolled ssh connect = %+v", e)
	}
	for i, event := range map[int]AuditEventType{1: AuditSessionConnected, 2: AuditSessionDisconnected} {
		if e := entries[i]; e.Event != event || e.Principal != "" || e.RequesterPrincipal != "" ||
			e.Transport != "ssh" || e.Reason != "ssh-enroll" || e.SSHFingerprint != "SHA256:fp2" {
			t.Fatalf("enroll ssh entry %d = %+v, want %s with an empty principal and ssh-enroll", i, e, event)
		}
	}
	if e := entries[3]; e.Principal != "" || e.RequesterPrincipal != "" || e.Transport != "ssh" {
		t.Fatalf("empty-fingerprint ssh connect = %+v, want empty principal and ssh transport", e)
	}
}

type failSyncAuditFile struct {
	auditFile
	syncErr error
}

func (f *failSyncAuditFile) Sync() error { return f.syncErr }

func TestSettingChangeIntentDurableFailsOnWriteOrSyncError(t *testing.T) {
	t.Run("sync failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		a, err := NewAuditLogger(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = a.Close() }()
		a.file = &failSyncAuditFile{auditFile: a.file, syncErr: fmt.Errorf("injected sync error")}
		if err := a.LogSettingChangeIntentDurable(context.Background(), "op-sync", "user_auto_approve", "false", "true"); err == nil {
			t.Fatal("LogSettingChangeIntentDurable succeeded despite Sync error")
		}
	})

	t.Run("closed log", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.log")
		a, err := NewAuditLogger(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		if err := a.LogSettingChangeIntentDurable(context.Background(), "op-closed", "user_auto_approve", "false", "true"); err == nil {
			t.Fatal("LogSettingChangeIntentDurable succeeded on closed logger")
		}
	})
}

func TestPassphraseChangedAuditsAllFourMigrationCounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogPassphraseChanged(context.Background(), 2, 3, 4, 5)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	want := "keys_migrated=2 templates_migrated=3 policy_sidecars_migrated=4 source_token_files_migrated=5"
	if len(entries) != 1 || entries[0].Event != AuditPassphraseChanged || entries[0].Reason != want {
		t.Fatalf("entries = %+v, want PASSPHRASE_CHANGED with reason %q", entries, want)
	}
}

func TestSignApprovedCarriesApprovalSourceAndPolicyRuleID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogSignApprovedAttributed(Attribution{RequesterPrincipal: "client:SHA256:abc", Transport: "http"}, TxnRecord{
		TxnAuth: "ADDR", TxnSender: "ADDR", TxID: "TX1",
		PolicyRuleID: "auto_approve_self_noop_transfer", ApprovalSource: "always_approve",
	})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 1 || entries[0].PolicyRuleID != "auto_approve_self_noop_transfer" || entries[0].ApprovalSource != "always_approve" {
		t.Fatalf("entries = %+v", entries)
	}
}
