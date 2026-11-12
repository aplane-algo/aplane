// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/policy/policytest"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
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

// A request refused because one of its positions rekeys an account to a held
// aplane key that is not a valid rekey target leaves a SIGN_REJECTED for each
// position the signer signs and one for the named position, whatever its
// kind. Each identifies its transaction as planned the way a SIGN_APPROVED
// identifies a signed one: its txid, fee, group ID and every transaction ID
// of the planned group. A passthrough-only request, which signs nothing,
// leaves the one entry. In a mixed request refused at its foreign position,
// the IDs are those of the group /plan returns for it, and the foreign
// position's entry has no txn_auth.
func TestAuditRecordsAValidTargetRefusalAtThePositionItNames(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	server.config.UserAutoApprove = true
	server.productRuntime().Config().SetUserAutoApprove(true)
	signer := generateTestKey(t, server, "ed25519")
	// A held aplane key whose record says it is not a valid rekey target.
	held := algocrypto.GenerateAccount()
	if err := server.productRuntime().WithKeyring(func(kr *crypto.Keyring) error {
		payload := apkeys.NewEd25519Payload(held.PublicKey, held.PrivateKey)
		defer payload.ZeroSecrets()
		_, err := apkeys.SaveNewPayload(mustActiveKeyPaths(t, server), payload, false, kr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := reloadKeysForTest(server); err != nil {
		t.Fatal(err)
	}
	server.productRuntime().SnapshotKeySession().InitializeSession()
	other := algocrypto.GenerateAccount().Address
	params := types.SuggestedParams{Fee: 1000, FlatFee: true, GenesisHash: testnetGenesisHashBytes(t), GenesisID: "testnet-v1.0", FirstRoundValid: 100, LastRoundValid: 200}
	rekey, err := transaction.MakePaymentTxn(other.String(), other.String(), 0, nil, "", params)
	if err != nil {
		t.Fatal(err)
	}
	rekey.RekeyTo = held.Address
	payment, err := transaction.MakePaymentTxn(signer, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", 1, nil, "", params)
	if err != nil {
		t.Fatal(err)
	}
	reason := func(position int) string {
		return "signer_invariant: transaction " + strconv.Itoa(position+1) + ": rekey_target_not_valid: cannot rekey to " + held.Address.String() +
			": this signer holds its aplane key (ed25519), which is not a valid rekey target (valid_rekey_target: false)"
	}
	post := func(t *testing.T, handler func(http.ResponseWriter, *http.Request), path string, req signerapi.GroupSignRequest) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler(w, requestWithIdentity(http.MethodPost, path, body))
		return w
	}
	wantRefused := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		var resp signerapi.ErrorResponse
		if w.Code != http.StatusForbidden || json.Unmarshal(w.Body.Bytes(), &resp) != nil || resp.Code != signerapi.ErrCodeRekeyTargetNotValid {
			t.Fatalf("/sign = %d: %s, want 403 %s", w.Code, w.Body.String(), signerapi.ErrCodeRekeyTargetNotValid)
		}
	}
	// wantRecord holds entry, for a refusal naming refused, to the planned
	// position of group, signed by auth ("" for a position the signer does
	// not sign, whose entry has no txn_auth).
	wantRecord := func(t *testing.T, entry AuditEntry, group []types.Transaction, position, refused int, auth, operationID string) {
		t.Helper()
		txn := group[position]
		if entry.Event != AuditSignRejected || entry.Outcome != "rejected" || entry.OperationID != operationID ||
			entry.TxnAuth != auth || entry.TxnSender != txn.Sender.String() || entry.Reason != reason(refused) {
			t.Fatalf("rejection = %+v", entry)
		}
		if entry.TxID != algocrypto.GetTxID(txn) || entry.Fee == nil || *entry.Fee != uint64(txn.Fee) ||
			entry.GroupID != base64.StdEncoding.EncodeToString(txn.Group[:]) || len(entry.GroupTxIDs) != len(group) || entry.DummyCount != 0 {
			t.Fatalf("rejection identifies %s fee %v group %s %v; want the planned %s in group %x of %d", entry.TxID, entry.Fee, entry.GroupID, entry.GroupTxIDs,
				algocrypto.GetTxID(txn), txn.Group, len(group))
		}
		for i, member := range group {
			if entry.GroupTxIDs[i] != algocrypto.GetTxID(member) {
				t.Fatalf("group_txids[%d] = %s, want %s", i, entry.GroupTxIDs[i], algocrypto.GetTxID(member))
			}
		}
	}

	t.Run("passthrough only", func(t *testing.T) {
		path := useTestAuditLog(t, server)
		grouped := rekey
		groupID, err := algocrypto.ComputeGroupID([]types.Transaction{grouped})
		if err != nil {
			t.Fatal(err)
		}
		grouped.Group = groupID
		signed := hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: grouped, Sig: types.Signature{7}}))
		wantRefused(t, post(t, server.handleSign, "/sign", signerapi.GroupSignRequest{RequestID: "refused-pt", Requests: []signerapi.SignRequest{{SignedTxnHex: signed}}}))
		entries := readAuditEntries(t, path)
		if len(entries) != 2 || entries[0].Event != AuditSignRequest {
			t.Fatalf("entries = %+v, want SIGN_REQUEST then one SIGN_REJECTED", entries)
		}
		wantRecord(t, entries[1], []types.Transaction{grouped}, 0, 0, "", "refused-pt")
		if raw := auditLines(t, path)[1]; strings.Contains(raw, `"txn_auth"`) {
			t.Fatalf("entry for a position the signer does not sign has txn_auth: %s", raw)
		}
	})

	t.Run("mixed, refused at the foreign position", func(t *testing.T) {
		req := signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
			{AuthAddress: signer, TxnBytesHex: encodeTxnToHex(payment)},
			{TxnBytesHex: encodeTxnToHex(rekey)},
		}}
		// /plan signs nothing and runs no signer invariant: it returns the
		// group the later /sign refuses, which the entry names.
		req.RequestID = "plan-mixed"
		planW := post(t, server.handlePlan, "/plan", req)
		if planW.Code != http.StatusOK {
			t.Fatalf("/plan = %d: %s", planW.Code, planW.Body.String())
		}
		var plan signerapi.GroupPlanResponse
		decodeResponse(t, planW, &plan)
		planned := make([]types.Transaction, len(plan.Transactions))
		for i, txnHex := range plan.Transactions {
			if planned[i], err = txnutil.DecodePrefixedHex(txnHex); err != nil {
				t.Fatal(err)
			}
		}
		if len(planned) != 2 || planned[1].Group == (types.Digest{}) {
			t.Fatalf("planned %d transactions, want the two grouped", len(planned))
		}

		path := useTestAuditLog(t, server)
		req.RequestID = "refused-mixed"
		wantRefused(t, post(t, server.handleSign, "/sign", req))
		entries := readAuditEntries(t, path)
		if len(entries) != 4 || entries[0].Event != AuditSignRequest || entries[1].Event != AuditSignRequest {
			t.Fatalf("entries = %+v, want two SIGN_REQUEST then two SIGN_REJECTED", entries)
		}
		wantRecord(t, entries[2], planned, 0, 1, signer, "refused-mixed")
		wantRecord(t, entries[3], planned, 1, 1, "", "refused-mixed")
		// The JSON line of the foreign position's entry has no txn_auth.
		if raw := auditLines(t, path)[3]; strings.Contains(raw, `"txn_auth"`) {
			t.Fatalf("entry for a position the signer does not sign has txn_auth: %s", raw)
		}
	})
}

// auditLines is the audit log at path, one JSON line per entry.
func auditLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

// promptHub is a connected apadmin that hands each approval prompt to the
// test.
type promptHub struct {
	recordingAdminHub
	prompts chan *signerapproval.SignRequest
}

func (h *promptHub) SendSignRequest(req *signerapproval.SignRequest) bool {
	h.prompts <- req
	return true
}

// HasClient and SendSignRequestCanceled are called from the request's
// goroutine and from the test's at once (a cancel notifies from both), so they
// record nothing: the embedded hub's fields are not safe for that.
func (h *promptHub) HasClient() bool { return true }

func (h *promptHub) SendSignRequestCanceled(*signerapproval.SignRequestCanceled) bool {
	return false
}

// generateTestKey generates a key of keyType through /admin/generate and
// loads it for signing.
func generateTestKey(t *testing.T, server *Signer, keyType string) string {
	t.Helper()
	body, err := json.Marshal(AdminGenerateRequest{KeyType: keyType})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	server.handleAdminGenerate(w, requestWithIdentity(http.MethodPost, "/admin/generate", body))
	if w.Code != http.StatusOK {
		t.Fatalf("generate %s failed: %d: %s", keyType, w.Code, w.Body.String())
	}
	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest() error = %v", err)
	}
	server.productRuntime().SnapshotKeySession().InitializeSession()
	return resp.Address
}

// testnetPayments are count payments from sender, grouped when there are
// several.
func testnetPayments(t *testing.T, sender string, count int) []types.Transaction {
	t.Helper()
	txns := make([]types.Transaction, count)
	for i := range txns {
		txn, err := transaction.MakePaymentTxn(sender, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", uint64(1000+i),
			nil, "", types.SuggestedParams{
				Fee: 1000, FlatFee: true, GenesisHash: testnetGenesisHashBytes(t), GenesisID: "testnet-v1.0", FirstRoundValid: 100, LastRoundValid: 200,
			})
		if err != nil {
			t.Fatal(err)
		}
		txns[i] = txn
	}
	if count > 1 {
		groupID, err := algocrypto.ComputeGroupID(txns)
		if err != nil {
			t.Fatal(err)
		}
		for i := range txns {
			txns[i].Group = groupID
		}
	}
	return txns
}

// requestIDOf is the one operation_id every entry shares, failing if any
// entry has none or another.
func requestIDOf(t *testing.T, entries []AuditEntry) string {
	t.Helper()
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	id := entries[0].OperationID
	for _, entry := range entries {
		if entry.OperationID == "" || entry.OperationID != id {
			t.Fatalf("%s operation_id = %q, want one non-empty ID for the request (first was %q)", entry.Event, entry.OperationID, id)
		}
	}
	return id
}

// A /sign sent without a request_id gets one ID from the signer: every entry
// it writes carries it, and it is the ID the request's prompt and cancel
// handle are held under.
func TestAnIDLessSignIsLoggedUnderTheIDItsPromptHas(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	hub := &promptHub{prompts: make(chan *signerapproval.SignRequest, 1)}
	server.hub = hub
	address := generateTestKey(t, server, "ed25519")
	path := useTestAuditLog(t, server)
	ir := server.productRuntime()

	sign := func(txns []types.Transaction) <-chan *httptest.ResponseRecorder {
		requests := make([]signerapi.SignRequest, len(txns))
		for i, txn := range txns {
			requests[i] = signerapi.SignRequest{AuthAddress: address, TxnBytesHex: encodeTxnToHex(txn)}
		}
		body, err := json.Marshal(signerapi.GroupSignRequest{Requests: requests})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			w := httptest.NewRecorder()
			server.handleSign(w, requestWithIdentity(http.MethodPost, "/sign", body))
			done <- w
		}()
		return done
	}
	awaitPrompt := func(done <-chan *httptest.ResponseRecorder) *signerapproval.SignRequest {
		t.Helper()
		select {
		case prompt := <-hub.prompts:
			return prompt
		case w := <-done:
			t.Fatalf("/sign ended without a prompt: %d: %s", w.Code, w.Body.String())
		case <-time.After(30 * time.Second):
			t.Fatal("no approval prompt")
		}
		return nil
	}

	// Approved: the request's entries, from what was asked to what was
	// signed, share the signer's ID.
	done := sign(testnetPayments(t, address, 2))
	prompt := awaitPrompt(done)
	ir.HandleSignApprovalResponse(&signerapproval.SignResponse{ID: prompt.ID, Approved: true})
	if w := <-done; w.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", w.Code, w.Body.String())
	}
	approved := readAuditEntries(t, path)
	if len(approved) != 4 || approved[0].Event != AuditSignRequest || approved[3].Event != AuditSignApproved {
		t.Fatalf("entries = %+v, want two SIGN_REQUEST then two SIGN_APPROVED", approved)
	}
	approvedID := requestIDOf(t, approved)
	if !strings.HasPrefix(approvedID, "req-") {
		t.Fatalf("operation_id = %q, want an ID the signer minted", approvedID)
	}

	// Cancelled with the ID its entries carry: that is the ID the live
	// request and its prompt are held under.
	done = sign(testnetPayments(t, address, 1))
	awaitPrompt(done)
	pending := readAuditEntries(t, path)[len(approved):]
	pendingID := requestIDOf(t, pending)
	if pendingID == approvedID || pending[0].Event != AuditSignRequest {
		t.Fatalf("pending entries = %+v, want a SIGN_REQUEST under a new ID", pending)
	}
	if result := ir.CancelSigningApproval(pendingID, signerapproval.SignRequestCancelReasonClientCanceled); result.State != signerapproval.SignRequestCancelStateCanceled {
		t.Fatalf("cancel by the logged ID = %v, want the pending request cancelled", result.State)
	}
	if w := <-done; w.Code == http.StatusOK {
		t.Fatalf("the cancelled /sign was signed: %s", w.Body.String())
	}
}

// A /plan sent without a request_id writes its slots under one ID.
func TestAnIDLessPlanIsLoggedUnderOneID(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	address := generateTestKey(t, server, "ed25519")
	path := useTestAuditLog(t, server)

	txns := testnetPayments(t, address, 2)
	body, err := json.Marshal(signerapi.GroupSignRequest{Requests: []signerapi.SignRequest{
		{AuthAddress: address, TxnBytesHex: encodeTxnToHex(txns[0])},
		{AuthAddress: address, TxnBytesHex: encodeTxnToHex(txns[1])},
	}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	server.handlePlan(w, requestWithIdentity(http.MethodPost, "/plan", body))
	if w.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", w.Code, w.Body.String())
	}
	entries := readAuditEntries(t, path)
	if len(entries) != 2 || entries[0].Event != AuditPlanRequest || entries[1].Event != AuditPlanRequest {
		t.Fatalf("entries = %+v, want two PLAN_REQUEST", entries)
	}
	requestIDOf(t, entries)
}

// A /sign/component sent without a request_id is logged under the ID its
// response returns.
func TestAnIDLessComponentIsLoggedUnderTheIDItReturns(t *testing.T) {
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, policytest.MustDocument(noderole.RoleCosigner, policy.DefaultKey,
		`{"transfer_policy": {"routes": [{"id": "any", "networks": ["*"], "sources": ["*"], "assets": ["*"], "destinations": ["*"]}]}}`))
	defer cleanup()
	witnessKeyID := generateTestKey(t, server, witness.Falcon1024V1)
	path := useTestAuditLog(t, server)

	txns := testnetPayments(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", 2)
	body, err := json.Marshal(signerapi.ComponentRequest{
		GroupBytesHex: []string{txnutil.EncodeWithPrefixHex(txns[0]), txnutil.EncodeWithPrefixHex(txns[1])},
		Targets: []signerapi.ComponentTarget{
			{TargetIndex: 0, Kind: signerapi.ComponentTargetKindCosigner, ComponentKey: witnessKeyID},
			{TargetIndex: 1, Kind: signerapi.ComponentTargetKindCosigner, ComponentKey: witnessKeyID},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	server.handleSignComponent(w, requestWithIdentity(http.MethodPost, "/sign/component", body))
	if w.Code != http.StatusOK {
		t.Fatalf("/sign/component failed: %d: %s", w.Code, w.Body.String())
	}
	var resp signerapi.ComponentResponse
	decodeResponse(t, w, &resp)
	entries := readAuditEntries(t, path)
	if len(entries) != 2 || entries[0].Event != AuditSignApproved || entries[1].Event != AuditSignApproved {
		t.Fatalf("entries = %+v, want a SIGN_APPROVED per target", entries)
	}
	if id := requestIDOf(t, entries); resp.RequestID == "" || id != resp.RequestID {
		t.Fatalf("operation_id = %q, response request_id = %q; want the same ID", id, resp.RequestID)
	}
}
