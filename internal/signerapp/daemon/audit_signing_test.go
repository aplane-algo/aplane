// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/pkg/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// useTestAuditLog points the server's audit log at a fresh file.
func useTestAuditLog(t *testing.T, server *Signer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	server.auditLog = logger
	return path
}

// A Falcon LogicSig payment needs a resource dummy: planning appends it,
// raises the payment's fee and sets the group ID. /plan is audited as a plan
// request and records nothing as signed; /sign records the request as it
// arrived, then the transactions as returned, tied by the request ID.
func TestAuditRecordsTheLogicSigGroupAsSigned(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()
	server.config.UserAutoApprove = true
	server.productRuntime().Config().SetUserAutoApprove(true)

	address := existingFalconCredentialForTest(t, server)
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest() error = %v", err)
	}
	server.productRuntime().SnapshotKeySession().InitializeSession()
	path := useTestAuditLog(t, server)

	requested, err := transaction.MakePaymentTxn(address, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", 2222,
		[]byte("audit-signed-group"), "", types.SuggestedParams{
			Fee: 1000, GenesisHash: testnetGenesisHashBytes(t), GenesisID: "testnet-v1.0", FirstRoundValid: 100, LastRoundValid: 200,
		})
	if err != nil {
		t.Fatal(err)
	}
	body := func(requestID string) []byte {
		data, err := json.Marshal(signerapi.GroupSignRequest{RequestID: requestID, Requests: []signerapi.SignRequest{{
			AuthAddress: address, TxnBytesHex: encodeTxnToHex(requested),
		}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", body("plan-1")))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}
	planned := readAuditEntries(t, path)
	if len(planned) != 1 || planned[0].Event != AuditPlanRequest || planned[0].OperationID != "plan-1" || planned[0].TxnAuth != address {
		t.Fatalf("/plan entries = %+v, want one PLAN_REQUEST for the request", planned)
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", body("sign-1")))
	if signW.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", signW.Code, signW.Body.String())
	}
	var signResp signerapi.GroupSignResponse
	decodeResponse(t, signW, &signResp)
	returned := make([]types.Transaction, len(signResp.Signed))
	for i, signedHex := range signResp.Signed {
		raw, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatal(err)
		}
		var stxn types.SignedTxn
		if err := msgpack.Decode(raw, &stxn); err != nil {
			t.Fatal(err)
		}
		returned[i] = stxn.Txn
	}
	if len(returned) < 2 || returned[0].Fee <= requested.Fee || returned[0].Group == (types.Digest{}) {
		t.Fatalf("returned %d transactions, fee %d; want a dummy added and the fee raised", len(returned), returned[0].Fee)
	}

	entries := readAuditEntries(t, path)[1:]
	if len(entries) != 2 || entries[0].Event != AuditSignRequest || entries[1].Event != AuditSignApproved {
		t.Fatalf("/sign entries = %+v, want SIGN_REQUEST then SIGN_APPROVED", entries)
	}
	for _, entry := range entries {
		if entry.OperationID != "sign-1" {
			t.Fatalf("%s operation_id = %q, want sign-1", entry.Event, entry.OperationID)
		}
	}
	if entries[0].TxID != "" || entries[0].Fee != nil {
		t.Fatalf("the request entry claims a signed transaction: %+v", entries[0])
	}
	signed := entries[1]
	if signed.TxID != algocrypto.GetTxID(returned[0]) || signed.TxID == algocrypto.GetTxID(requested) {
		t.Fatalf("signed txid %s, want the returned %s, not the requested %s", signed.TxID, algocrypto.GetTxID(returned[0]), algocrypto.GetTxID(requested))
	}
	if signed.Fee == nil || *signed.Fee != uint64(returned[0].Fee) {
		t.Fatalf("signed fee %v, want the returned %d", signed.Fee, returned[0].Fee)
	}
	if want := base64.StdEncoding.EncodeToString(returned[0].Group[:]); signed.GroupID != want {
		t.Fatalf("signed group %q, want %q", signed.GroupID, want)
	}
	if len(signed.GroupTxIDs) != len(returned) || signed.DummyCount != len(returned)-1 {
		t.Fatalf("signed group %v with %d dummies, want the %d returned transactions", signed.GroupTxIDs, signed.DummyCount, len(returned))
	}
	for i, txn := range returned {
		if signed.GroupTxIDs[i] != algocrypto.GetTxID(txn) {
			t.Fatalf("group txid %d = %s, want the returned %s", i, signed.GroupTxIDs[i], algocrypto.GetTxID(txn))
		}
	}
}

// A refused request records the refusal against its request ID and nothing
// as signed.
func TestAuditRecordsARefusedSignAsRejected(t *testing.T) {
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
	server.productRuntime().SnapshotKeySession().InitializeSession()
	path := useTestAuditLog(t, server)

	// The default policy refuses a rekey to an account the signer does not hold.
	txn, err := transaction.MakePaymentTxn(genResp.Address, genResp.Address, 0, nil, "", types.SuggestedParams{
		Fee: 1000, GenesisHash: testnetGenesisHashBytes(t), GenesisID: "testnet-v1.0", FirstRoundValid: 100, LastRoundValid: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	txn.RekeyTo = types.Address{7}
	reqJSON, err := json.Marshal(signerapi.GroupSignRequest{RequestID: "refused-1", Requests: []signerapi.SignRequest{{
		AuthAddress: genResp.Address, TxnBytesHex: encodeTxnToHex(txn),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	server.handleSign(w, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if w.Code != http.StatusForbidden {
		t.Fatalf("/sign = %d: %s, want a policy refusal", w.Code, w.Body.String())
	}

	entries := readAuditEntries(t, path)
	if len(entries) != 2 || entries[0].Event != AuditSignRequest || entries[1].Event != AuditSignRejected {
		t.Fatalf("entries = %+v, want SIGN_REQUEST then SIGN_REJECTED", entries)
	}
	if !strings.HasPrefix(entries[1].Reason, "policy_engine_rejected:") || entries[1].TxID != "" || entries[1].Fee != nil {
		t.Fatalf("rejection = %+v", entries[1])
	}
	for _, entry := range entries {
		if entry.OperationID != "refused-1" {
			t.Fatalf("%s operation_id = %q, want refused-1", entry.Event, entry.OperationID)
		}
	}
}
