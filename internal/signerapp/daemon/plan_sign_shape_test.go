// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapi"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestPlanAndSignSuccessResponseShapes(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	server.config.UserAutoApprove = true
	server.registry.Get(auth.DefaultIdentityID).Config().SetUserAutoApprove(true)

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
	ir := server.registry.Get(auth.DefaultIdentityID)
	ir.SnapshotKeySession().InitializeSession()

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
		[]byte("plan-sign-shape"),
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

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}

	var planResp map[string]any
	if err := json.NewDecoder(planW.Body).Decode(&planResp); err != nil {
		t.Fatalf("decode /plan response: %v", err)
	}
	if !reflect.DeepEqual(sortedTopLevelKeys(planResp), []string{"transactions"}) &&
		!reflect.DeepEqual(sortedTopLevelKeys(planResp), []string{"mutations", "transactions"}) {
		t.Fatalf("/plan top-level keys = %#v", sortedTopLevelKeys(planResp))
	}
	if txns, ok := planResp["transactions"].([]any); !ok || len(txns) != 1 {
		t.Fatalf("/plan transactions = %#v", planResp["transactions"])
	}
	if _, exists := planResp["error"]; exists {
		t.Fatalf("/plan unexpectedly included error field: %#v", planResp)
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", signW.Code, signW.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signW.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode /sign response: %v", err)
	}
	if !reflect.DeepEqual(sortedTopLevelKeys(signResp), []string{"signed"}) &&
		!reflect.DeepEqual(sortedTopLevelKeys(signResp), []string{"mutations", "signed"}) {
		t.Fatalf("/sign top-level keys = %#v", sortedTopLevelKeys(signResp))
	}
	if signed, ok := signResp["signed"].([]any); !ok || len(signed) != 1 {
		t.Fatalf("/sign signed = %#v", signResp["signed"])
	}
	if _, exists := signResp["error"]; exists {
		t.Fatalf("/sign unexpectedly included error field: %#v", signResp)
	}
}

func TestSignRejectsForeignModeWithStableErrorShape(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	ir.SnapshotKeySession().InitializeSession()

	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisHash:     testnetGenesisHashBytes(t),
		GenesisID:       "testnet-v1.0",
		FirstRoundValid: 100,
		LastRoundValid:  200,
	}

	foreignTxn, err := transaction.MakePaymentTxn(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		12345,
		[]byte("foreign-on-sign"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	reqJSON, err := json.Marshal(signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			TxnBytesHex: encodeTxnToHex(foreignTxn),
		}},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusBadRequest {
		t.Fatalf("/sign status = %d, want %d; body=%s", signW.Code, http.StatusBadRequest, signW.Body.String())
	}

	var signResp map[string]any
	if err := json.NewDecoder(signW.Body).Decode(&signResp); err != nil {
		t.Fatalf("decode /sign response: %v", err)
	}
	if !reflect.DeepEqual(sortedTopLevelKeys(signResp), []string{"code", "error"}) {
		t.Fatalf("/sign top-level keys = %#v, want code and error", sortedTopLevelKeys(signResp))
	}
	if got, _ := signResp["code"].(string); got != signerapi.ErrCodeBadRequest {
		t.Fatalf("/sign code = %q, want %q", got, signerapi.ErrCodeBadRequest)
	}
	if got, _ := signResp["error"].(string); got != "no signable transactions: all entries are foreign. Build and submit this group locally instead of using apsigner" {
		t.Fatalf("/sign error = %q", got)
	}
}

func TestPlanRejectsMalformedRequestShapeWithStableErrorShape(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	badReqJSON, err := json.Marshal(signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: "ADDR",
		}},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", badReqJSON))
	if planW.Code != http.StatusBadRequest {
		t.Fatalf("/plan status = %d, want %d; body=%s", planW.Code, http.StatusBadRequest, planW.Body.String())
	}

	var planResp map[string]any
	if err := json.NewDecoder(planW.Body).Decode(&planResp); err != nil {
		t.Fatalf("decode /plan response: %v", err)
	}
	if !reflect.DeepEqual(sortedTopLevelKeys(planResp), []string{"code", "error"}) {
		t.Fatalf("/plan top-level keys = %#v, want code and error", sortedTopLevelKeys(planResp))
	}
	if got, _ := planResp["code"].(string); got != signerapi.ErrCodeBadRequest {
		t.Fatalf("/plan code = %q, want %q", got, signerapi.ErrCodeBadRequest)
	}
	if got, _ := planResp["error"].(string); got != "transaction 1: txn_bytes_hex is required for sign mode" {
		t.Fatalf("/plan error = %q", got)
	}
}

func TestPlanRejectsMixedPassthroughAndForeignWithStableErrorShape(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	sp := types.SuggestedParams{
		Fee:             types.MicroAlgos(1000),
		GenesisHash:     testnetGenesisHashBytes(t),
		GenesisID:       "testnet-v1.0",
		FirstRoundValid: 100,
		LastRoundValid:  200,
	}

	txnA, err := transaction.MakePaymentTxn(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		1111,
		[]byte("mixed-passthrough-foreign-a"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(a) error = %v", err)
	}

	txnB, err := transaction.MakePaymentTxn(
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ",
		2222,
		[]byte("mixed-passthrough-foreign-b"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(b) error = %v", err)
	}

	groupID, err := algocrypto.ComputeGroupID([]types.Transaction{txnA, txnB})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txnA.Group = groupID
	txnB.Group = groupID

	var fakeSig types.Signature
	for i := range fakeSig {
		fakeSig[i] = byte(i + 1)
	}
	passthroughSigned := types.SignedTxn{
		Txn: txnA,
		Sig: fakeSig,
	}

	reqJSON, err := json.Marshal(signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{
				SignedTxnHex: encodeSignedTxnToHex(passthroughSigned),
			},
			{
				TxnBytesHex: encodeTxnToHex(txnB),
			},
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusBadRequest {
		t.Fatalf("/plan status = %d, want %d; body=%s", planW.Code, http.StatusBadRequest, planW.Body.String())
	}

	var planResp map[string]any
	if err := json.NewDecoder(planW.Body).Decode(&planResp); err != nil {
		t.Fatalf("decode /plan response: %v", err)
	}
	if !reflect.DeepEqual(sortedTopLevelKeys(planResp), []string{"code", "error"}) {
		t.Fatalf("/plan top-level keys = %#v, want code and error", sortedTopLevelKeys(planResp))
	}
	if got, _ := planResp["code"].(string); got != signerapi.ErrCodeBadRequest {
		t.Fatalf("/plan code = %q, want %q", got, signerapi.ErrCodeBadRequest)
	}
	if got, _ := planResp["error"].(string); got != "cannot mix passthrough and foreign transactions: passthrough requires pre-grouped, foreign requires server-computed group ID" {
		t.Fatalf("/plan error = %q", got)
	}
}

func encodeSignedTxnToHex(stxn types.SignedTxn) string {
	return hex.EncodeToString(msgpack.Encode(stxn))
}

func sortedTopLevelKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
