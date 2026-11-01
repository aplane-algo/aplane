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
// small audit entries and a readable log.
func TestRefusedSigningRequestsLeaveSmallAuditEntries(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
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
		for path, handle := range map[string]http.HandlerFunc{"/plan": server.handlePlan, "/sign": server.handleSign} {
			w := httptest.NewRecorder()
			handle(w, requestWithIdentity(http.MethodPost, path, body))
			if w.Code == http.StatusOK {
				t.Fatalf("%s %s was accepted", name, path)
			}
		}
	}
	path := filepath.Join(server.dataDir, "audit.log")
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
	if !strings.Contains(string(data), "SIGN_REQUEST") {
		t.Fatal("the refused requests were not audited at all")
	}
	if _, err := signeraudit.ReadRotatingReleases(path); err != nil {
		t.Fatalf("the release history no longer loads: %v", err)
	}
}
