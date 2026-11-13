// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
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

// A setting in effect without a completed save is the only durable trace of
// that change, so the entry names the session, the setting, the result code
// and the error.
func TestSettingNotDurableAuditNamesTheSettingAndOutcome(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	a.LogSettingNotDurableContext(adminserver.SessionContext{
		SessionID: "admin-7", Transport: "ipc", AdminPrincipal: adminserver.SessionPrincipal{ID: "system:product-admin"},
	}, "user_auto_approve", "applied_not_saved", "user_auto_approve is set to false and in effect now, but it was not saved")
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
	if entry.Event != AuditSettingNotDurable || entry.Outcome != "applied" || entry.ResultCode != "applied_not_saved" ||
		entry.AdminSessionID != "admin-7" || entry.Principal != "system:product-admin" ||
		entry.Reason != "setting=user_auto_approve: user_auto_approve is set to false and in effect now, but it was not saved" {
		t.Fatalf("audit entry = %+v", entry)
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
