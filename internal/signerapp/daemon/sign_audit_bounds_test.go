// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// The planner logs a signing request before validating it, so an oversized
// auth address or transaction field in a refused request must still leave
// small audit entries and a readable log. /plan logs its slot as a
// PLAN_REQUEST, /sign as a SIGN_REQUEST, both bounded the same way.
func TestRefusedSigningRequestsLeaveSmallAuditEntries(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	path := filepath.Join(server.dataDir, "audit.log")
	logged := 0
	// newEntries are the entries written since the last call.
	newEntries := func() []AuditEntry {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			return nil
		}
		entries := readAuditEntries(t, path)
		fresh := entries[logged:]
		logged = len(entries)
		return fresh
	}
	huge := strings.Repeat("A", 2<<20)
	sender := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	payment := func(genesisID string) string {
		t.Helper()
		txn, err := transaction.MakePaymentTxn(sender, sender, 1, nil, "", types.SuggestedParams{
			Fee: 1000, GenesisHash: testnetGenesisHashBytes(t), GenesisID: genesisID,
			FirstRoundValid: 100, LastRoundValid: 200,
		})
		if err != nil {
			t.Fatal(err)
		}
		return encodeTxnToHex(txn)
	}
	for name, req := range map[string]signerapi.SignRequest{
		"oversized auth address": {AuthAddress: huge, TxnBytesHex: payment("testnet-v1.0")},
		"oversized genesis ID":   {AuthAddress: sender, TxnBytesHex: payment(huge)},
	} {
		body, err := json.Marshal(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{req}})
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range []struct {
			path   string
			handle http.HandlerFunc
			event  AuditEventType
		}{
			{"/plan", server.handlePlan, AuditPlanRequest},
			{"/sign", server.handleSign, AuditSignRequest},
		} {
			w := httptest.NewRecorder()
			call.handle(w, requestWithIdentity(http.MethodPost, call.path, body))
			if w.Code == http.StatusOK {
				t.Fatalf("%s %s was accepted", name, call.path)
			}
			entries := newEntries()
			if len(entries) != 1 || entries[0].Event != call.event {
				t.Fatalf("%s %s wrote %+v, want one %s", name, call.path, entries, call.event)
			}
			if entry := entries[0]; len(entry.TxnAuth) > 128 || len(entry.TxnSender) > 128 || len(entry.TxnDetails) > 8<<10 {
				t.Fatalf("%s %s wrote an unbounded %s: txn_auth %d, txn_sender %d, txn_details %d bytes",
					name, call.path, call.event, len(entry.TxnAuth), len(entry.TxnSender), len(entry.TxnDetails))
			}
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 256*1024 {
		t.Fatalf("four refused signing requests wrote %d bytes of audit log", len(data))
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if len(line) > 128*1024 {
			t.Fatalf("an audit entry is %d bytes: %.200s…", len(line), line)
		}
	}
	if _, err := signeraudit.ReadRotatingReleases(path); err != nil {
		t.Fatalf("the release history no longer loads: %v", err)
	}
}
