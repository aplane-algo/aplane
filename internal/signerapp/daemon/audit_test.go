// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func init() {
	// Register providers for tests
	RegisterProviders()
}

func TestSigningProvidersAreRegistered(t *testing.T) {
	// Verify signing providers are registered
	families := signing.GetRegisteredFamilies()
	if len(families) == 0 {
		t.Fatal("no signing providers registered")
	}
}

func TestAuditRuntimeEventsOmitProductLocator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogSignRequest("ADDR", "SENDER", "pay", "send 1 ALGO")
	logger.LogSignApproved("ADDR", "SENDER", "send 1 ALGO")
	logger.LogSignRejected("ADDR", "SENDER", "operator rejected")
	logger.LogSignFailed("ADDR", "SENDER", "key load error")
	logger.LogKeyReload(5)
	logger.LogKeyRejected("/tmp/BAD.key", "logic_sig_salt_invalid: missing salt_counter")
	logger.LogTokenProvisioned("SHA256:abc", "10.0.0.1")
	logger.LogAuthFailedAttributed("alice", "10.0.0.1", "invalid_credentials")
	logger.LogSessionConnected("10.0.0.1", "user")
	logger.LogSessionDisconnected("10.0.0.1", "user")
	logger.LogStoreInitialized("/data/identities/default")
	logger.LogStoreInitializeFailed("already initialized")
	logger.LogPassphraseChanged(2, 1)
	logger.LogPassphraseChangeFailed("invalid passphrase")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 14 {
		t.Fatalf("expected 14 audit entries, got %d", len(lines))
	}

	for i, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: unmarshal error: %v", i, err)
		}
		if _, ok := entry["identity_id"]; ok {
			t.Errorf("line %d contains identity_id: %#v", i, entry)
		}
		if _, ok := entry["target_identity_id"]; ok {
			t.Errorf("line %d contains target_identity_id: %#v", i, entry)
		}
	}

	var keyReload AuditEntry
	if err := json.Unmarshal([]byte(lines[4]), &keyReload); err != nil {
		t.Fatalf("decode key reload entry: %v", err)
	}
	if keyReload.Event != AuditKeyReload || keyReload.Principal != auth.SystemProductAdminPrincipalID || keyReload.RequesterPrincipal != auth.SystemProductAdminPrincipalID {
		t.Fatalf("key reload attribution = %#v", keyReload)
	}
}

func TestAuditKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogKeyRejected("/tmp/BAD.key", "logic_sig_salt_invalid: missing salt_counter")

	entries := readAuditEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Event != AuditKeyRejected || entry.Outcome != "rejected" {
		t.Fatalf("entry event/outcome = %s/%s, want %s/rejected", entry.Event, entry.Outcome, AuditKeyRejected)
	}
	if !strings.Contains(entry.Reason, "file=BAD.key") || !strings.Contains(entry.Reason, "logic_sig_salt_invalid") {
		t.Fatalf("entry reason = %q", entry.Reason)
	}
}

func TestAuditSigningAttributionFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogSignRequest("ADDR", "SENDER", "pay", "send 1 ALGO")
	logger.LogSignApproved("ADDR", "SENDER", "txn signed")
	logger.LogSignRejected("ADDR", "SENDER", "operator rejected")

	entries := readAuditEntries(t, path)
	if len(entries) != 3 {
		t.Fatalf("entry count = %d, want 3", len(entries))
	}

	if entries[0].RequesterPrincipal != "" || entries[0].ApproverPrincipal != "" || entries[0].Outcome != "requested" {
		t.Fatalf("request attribution = %#v", entries[0])
	}
	if entries[1].RequesterPrincipal != "" || entries[1].ApproverPrincipal != "" || entries[1].Outcome != "approved" {
		t.Fatalf("approval attribution = %#v", entries[1])
	}
	if entries[2].RequesterPrincipal != "" || entries[2].ApproverPrincipal != "" || entries[2].Outcome != "rejected" {
		t.Fatalf("rejection attribution = %#v", entries[2])
	}
}

func TestAuditSigningPolicyRuleID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogSignApprovedWithPolicyRule("ADDR", "SENDER", "txn signed", "review_algo_payment_exceeded")
	logger.LogSignRejectedWithPolicyRule("ADDR", "SENDER", "operator rejected", "always_review_warnings")

	entries := readAuditEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	if got := entries[0].PolicyRuleID; got != "review_algo_payment_exceeded" {
		t.Fatalf("approved policy_rule_id = %q", got)
	}
	if got := entries[1].PolicyRuleID; got != "always_review_warnings" {
		t.Fatalf("rejected policy_rule_id = %q", got)
	}
}

func TestAuditSessionContextAttribution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	ctx := adminserver.SessionContext{
		SessionID:  "admin-42",
		Transport:  adminserver.TransportSSH,
		RemoteAddr: "10.0.0.1:2222",
		AdminPrincipal: adminserver.SessionPrincipal{
			ID:     "alice-admin",
			Type:   "service",
			Method: "ssh-passphrase",
		},
		RequesterPrincipal: adminserver.SessionPrincipal{ID: "requester"},
		ApproverPrincipal:  adminserver.SessionPrincipal{ID: "approver"},
	}
	logger.LogSessionConnectedContext(ctx)
	logger.LogSessionDisconnectedContext(ctx)

	entries := readAuditEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if entry.Principal != "alice-admin" || entry.RequesterPrincipal != "requester" || entry.ApproverPrincipal != "approver" {
			t.Fatalf("session principal attribution = %#v", entry)
		}
		if entry.AdminSessionID != "admin-42" || entry.Transport != adminserver.TransportSSH || entry.RemoteAddr != "10.0.0.1:2222" {
			t.Fatalf("session transport attribution = %#v", entry)
		}
	}
	if entries[0].Outcome != "connected" || entries[1].Outcome != "disconnected" {
		t.Fatalf("session outcomes = %q/%q, want connected/disconnected", entries[0].Outcome, entries[1].Outcome)
	}
}

func TestAuditAuthorizationDeniedCarriesSessionAndActionContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	ctx := adminserver.SessionContext{
		SessionID:      "admin-42",
		Transport:      adminserver.TransportSSH,
		RemoteAddr:     "10.0.0.1:2222",
		AdminPrincipal: adminserver.SessionPrincipal{ID: "alice-admin"},
	}
	logger.LogAuthorizationDenied(ctx, auth.ActionKeysDelete, auth.Resource{
		Type: "key",
		ID:   "ADDR",
	}, "forbidden")

	entries := readAuditEntries(t, path)
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Event != AuditAuthorizationDenied || entry.Outcome != "denied" {
		t.Fatalf("entry event/outcome = %q/%q, want authorization denied", entry.Event, entry.Outcome)
	}
	if entry.Principal != "alice-admin" || entry.RequesterPrincipal != "alice-admin" {
		t.Fatalf("entry principal fields = %#v, want alice-admin", entry)
	}
	if entry.AdminSessionID != "admin-42" || entry.Transport != adminserver.TransportSSH || entry.RemoteAddr != "10.0.0.1:2222" {
		t.Fatalf("entry session fields = %#v", entry)
	}
	for _, want := range []string{"action=keys.delete", "resource_type=key", "resource_id=ADDR", "reason=forbidden"} {
		if !strings.Contains(entry.Reason, want) {
			t.Fatalf("entry reason = %q, want to contain %q", entry.Reason, want)
		}
	}
}

func TestHTTPSigningAuditAttributionUsesRequestIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	r := requestWithIdentityID(http.MethodPost, "/sign", nil, "alice")
	r.RemoteAddr = "203.0.113.10:4000"
	audit := &signingAuditLogger{
		log:         logger,
		attribution: signingAuditAttributionFromRequest(r),
	}

	audit.LogSignRequest("ADDR", "SENDER", "pay", "send 1 ALGO")
	audit.RecordApprovalResponse(signerapproval.SignResponse{ID: "req-1", Approved: true, ApproverPrincipal: "alice-admin"})
	audit.LogSignApprovedWithPolicyRule("ADDR", "SENDER", "txn signed", "always_review_warnings")

	entries := readAuditEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	for _, entry := range entries {
		if entry.RequesterPrincipal != "alice" {
			t.Fatalf("HTTP signing attribution = %#v", entry)
		}
		if entry.Transport != auditTransportHTTP || entry.RemoteAddr != "203.0.113.10:4000" {
			t.Fatalf("HTTP transport attribution = %#v", entry)
		}
	}
	if entries[0].ApproverPrincipal != "" {
		t.Fatalf("request approver_principal = %q, want empty", entries[0].ApproverPrincipal)
	}
	if entries[1].ApproverPrincipal != "alice-admin" {
		t.Fatalf("approval approver_principal = %q, want alice-admin", entries[1].ApproverPrincipal)
	}
	if entries[1].PolicyRuleID != "always_review_warnings" {
		t.Fatalf("approval policy_rule_id = %q, want always_review_warnings", entries[1].PolicyRuleID)
	}
}

func TestHandleSignWritesHTTPAttributedAuditEntries(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.config.UserAutoApprove = true
	server.productRuntime().Config().SetUserAutoApprove(true)

	genBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	genW := httptest.NewRecorder()
	server.handleAdminGenerate(genW, requestWithIdentity(http.MethodPost, "/admin/generate", genBody))
	if genW.Code != http.StatusOK {
		t.Fatalf("generate failed: %d: %s", genW.Code, genW.Body.String())
	}

	var genResp AdminGenerateResponse
	decodeResponse(t, genW, &genResp)

	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest() error = %v", err)
	}
	ir := server.productRuntime()
	ir.SnapshotKeySession().InitializeSession()

	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	server.auditLog = logger

	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisHash:     testnetGenesisHashBytes(t),
		GenesisID:       "testnet-v1.0",
		FirstRoundValid: 100,
		LastRoundValid:  200,
	}
	txn, err := transaction.MakePaymentTxn(
		genResp.Address,
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		12345,
		[]byte("audit-attribution"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}
	reqJSON, err := json.Marshal(signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: genResp.Address,
			TxnBytesHex: encodeTxnToHex(txn),
		}},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(reqJSON))
	r.Header.Set("Authorization", "aplane test-token")
	r.RemoteAddr = "203.0.113.12:5000"
	w := httptest.NewRecorder()
	server.requireAuth(
		auth.ActionSignRequest,
		auth.Resource{Type: "transaction"},
		server.handleSign,
	)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", w.Code, w.Body.String())
	}

	entries := readAuditEntries(t, path)
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	if entries[0].Event != AuditSignRequest || entries[1].Event != AuditSignApproved {
		t.Fatalf("audit events = %q/%q, want request/approved", entries[0].Event, entries[1].Event)
	}
	for _, entry := range entries {
		if entry.RequesterPrincipal != auth.SystemProductAdminPrincipalID {
			t.Fatalf("HTTP signing identity attribution = %#v", entry)
		}
		if entry.Transport != auditTransportHTTP || entry.RemoteAddr != "203.0.113.12:5000" {
			t.Fatalf("HTTP signing transport attribution = %#v", entry)
		}
	}
}

func TestAuditProcessLevelEventsOmitProductLocator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogServerStart(3)
	logger.LogServerStop()
	logger.LogServerStopIncomplete("SSH server: deadline exceeded")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 audit entries, got %d", len(lines))
	}

	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: unmarshal error: %v", i, err)
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(line), &fields); err != nil {
			t.Fatalf("line %d: unmarshal fields: %v", i, err)
		}
		if _, ok := fields["identity_id"]; ok {
			t.Errorf("line %d contains identity_id: %#v", i, fields)
		}
		if _, ok := fields["target_identity_id"]; ok {
			t.Errorf("line %d contains target_identity_id: %#v", i, fields)
		}
		if entry.Event == AuditServerStopIncomplete && (entry.Outcome != "failed" || entry.Reason == "") {
			t.Errorf("incomplete shutdown entry = %#v, want failed outcome and reason", entry)
		}
	}
}

func TestAuditPreAuthFailureHasNoPrincipalOrProductLocator(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogAuthFailed("10.0.0.1", "missing_credentials")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"identity_id", "target_identity_id", "principal"} {
		if _, ok := entry[field]; ok {
			t.Errorf("pre-auth failure contains %s: %#v", field, entry)
		}
	}
}

func TestAuditKeyMutationEventsCarryAddressAndReason(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()

	logger.LogKeyGenerated("ADDR1", "ed25519")
	logger.LogKeyDeleted("ADDR2", "/tmp/deleted/ADDR2.key")
	logger.LogKeyImported("ADDR4", "ed25519")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 audit entries, got %d", len(lines))
	}

	var generated AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &generated); err != nil {
		t.Fatal(err)
	}
	if generated.Event != AuditKeyGenerated || generated.TxnAuth != "ADDR1" || generated.Reason != "ed25519" {
		t.Fatalf("unexpected generated entry: %#v", generated)
	}

	var deleted AuditEntry
	if err := json.Unmarshal([]byte(lines[1]), &deleted); err != nil {
		t.Fatal(err)
	}
	if deleted.Event != AuditKeyDeleted || deleted.TxnAuth != "ADDR2" || deleted.Reason != "ADDR2.key" {
		t.Fatalf("unexpected deleted entry: %#v", deleted)
	}

	var imported AuditEntry
	if err := json.Unmarshal([]byte(lines[2]), &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Event != AuditKeyImported || imported.TxnAuth != "ADDR4" || imported.Reason != "ed25519" {
		t.Fatalf("unexpected imported entry: %#v", imported)
	}
}

func readAuditEntries(t *testing.T, path string) []AuditEntry {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	entries := make([]AuditEntry, 0, len(lines))
	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: unmarshal error: %v", i, err)
		}
		entries = append(entries, entry)
	}
	return entries
}
