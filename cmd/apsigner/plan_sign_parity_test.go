// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signerrest "github.com/aplane-algo/aplane/internal/signerapp/rest"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"

	algocrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestPlanAndSignProduceMatchingCanonicalTransactionForEd25519(t *testing.T) {
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
		[]byte("plan-sign-parity"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: genResp.Address,
			TxnBytesHex: encodeTxnToHex(txn),
		}},
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}

	var planResp signerapi.GroupPlanResponse
	decodeResponse(t, planW, &planResp)
	if planResp.Error != "" {
		t.Fatalf("/plan returned error: %s", planResp.Error)
	}
	if len(planResp.Transactions) != 1 {
		t.Fatalf("/plan transactions = %d, want 1", len(planResp.Transactions))
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", signW.Code, signW.Body.String())
	}

	var signResp signerapi.GroupSignResponse
	decodeResponse(t, signW, &signResp)
	if signResp.Error != "" {
		t.Fatalf("/sign returned error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 1 {
		t.Fatalf("/sign signed count = %d, want 1", len(signResp.Signed))
	}

	signedBytes, err := hex.DecodeString(signResp.Signed[0])
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}

	var stxn types.SignedTxn
	if err := msgpack.Decode(signedBytes, &stxn); err != nil {
		t.Fatalf("msgpack.Decode() error = %v", err)
	}

	if got := encodeTxnToHex(stxn.Txn); got != planResp.Transactions[0] {
		t.Fatalf("signed canonical txn mismatch:\nplan=%s\nsign=%s", planResp.Transactions[0], got)
	}
}

func TestPlanAndSimulateProduceMatchingCanonicalTransactionsForEd25519(t *testing.T) {
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
		[]byte("plan-simulate-parity"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: genResp.Address,
			TxnBytesHex: encodeTxnToHex(txn),
		}},
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}

	var planResp signerapi.GroupPlanResponse
	decodeResponse(t, planW, &planResp)
	if planResp.Error != "" {
		t.Fatalf("/plan returned error: %s", planResp.Error)
	}

	svc := signerrest.Service{
		Deps: signerrest.Dependencies{
			NewSigningService: func(got *identity.Runtime) signerrest.SigningService {
				if got != ir {
					t.Fatalf("runtime = %p, want %p", got, ir)
				}
				return server.newSigningServiceForIdentityWithAudit(got, nil)
			},
			EncodeTxnHex: encodeTxnToHex,
			SimulateSignedGroup: func(ctx context.Context, got []types.SignedTxn) ([]string, string, bool, *signersigning.ServiceError) {
				if len(got) != 1 {
					t.Fatalf("SimulateSignedGroup signed count = %d, want 1", len(got))
				}
				return []string{algocrypto.GetTxID(got[0].Txn)}, "simulation stub\n", false, nil
			},
		},
	}
	simResp, simErr := svc.Simulate(context.Background(), ir, reqBody)
	if simErr != nil {
		t.Fatalf("Simulate() error = %v", simErr)
	}
	if simResp.Error != "" {
		t.Fatalf("Simulate() response error = %q", simResp.Error)
	}
	if !reflect.DeepEqual(planResp.Transactions, simResp.Transactions) {
		t.Fatalf("transactions mismatch:\n/plan     = %#v\n/simulate = %#v", planResp.Transactions, simResp.Transactions)
	}
	if !reflect.DeepEqual(planResp.Mutations, simResp.Mutations) {
		t.Fatalf("mutations mismatch:\n/plan     = %#v\n/simulate = %#v", planResp.Mutations, simResp.Mutations)
	}
}

func TestPlanAndSignPreserveCanonicalTransactionsForMixedSignAndPassthroughGroup(t *testing.T) {
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

	payer := genResp.Address
	receiver := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	txnToSign, err := transaction.MakePaymentTxn(
		payer,
		receiver,
		12345,
		[]byte("mixed-group-sign"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(sign): %v", err)
	}

	passthroughTxn, err := transaction.MakePaymentTxn(
		receiver,
		payer,
		54321,
		[]byte("mixed-group-passthrough"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(passthrough): %v", err)
	}

	groupID, err := algocrypto.ComputeGroupID([]types.Transaction{txnToSign, passthroughTxn})
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	txnToSign.Group = groupID
	passthroughTxn.Group = groupID

	var fakeSig types.Signature
	for i := range fakeSig {
		fakeSig[i] = byte(i + 1)
	}
	passthroughSigned := types.SignedTxn{
		Txn: passthroughTxn,
		Sig: fakeSig,
	}

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{
				AuthAddress: payer,
				TxnBytesHex: encodeTxnToHex(txnToSign),
			},
			{
				SignedTxnHex: hex.EncodeToString(msgpack.Encode(passthroughSigned)),
			},
		},
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}

	var planResp signerapi.GroupPlanResponse
	decodeResponse(t, planW, &planResp)
	if planResp.Error != "" {
		t.Fatalf("/plan returned error: %s", planResp.Error)
	}
	if len(planResp.Transactions) != 2 {
		t.Fatalf("/plan transactions = %d, want 2", len(planResp.Transactions))
	}

	if planResp.Mutations == nil || planResp.Mutations.PassthroughCount != 1 {
		t.Fatalf("/plan mutations passthrough_count = %#v, want 1 passthrough", planResp.Mutations)
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", signW.Code, signW.Body.String())
	}

	var signResp signerapi.GroupSignResponse
	decodeResponse(t, signW, &signResp)
	if signResp.Error != "" {
		t.Fatalf("/sign returned error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 2 {
		t.Fatalf("/sign signed count = %d, want 2", len(signResp.Signed))
	}

	for i, signedHex := range signResp.Signed {
		signedBytes, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatalf("DecodeString(%d) error = %v", i, err)
		}

		var stxn types.SignedTxn
		if err := msgpack.Decode(signedBytes, &stxn); err != nil {
			t.Fatalf("msgpack.Decode(%d) error = %v", i, err)
		}

		if got := encodeTxnToHex(stxn.Txn); got != planResp.Transactions[i] {
			t.Fatalf("signed canonical txn mismatch at index %d:\nplan=%s\nsign=%s", i, planResp.Transactions[i], got)
		}
	}

	if signResp.Mutations == nil || signResp.Mutations.PassthroughCount != 1 {
		t.Fatalf("/sign mutations passthrough_count = %#v, want 1 passthrough", signResp.Mutations)
	}
}

func TestPlanAllowsMixedSignAndForeignGroupAndPreservesCanonicalTransactions(t *testing.T) {
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

	signerAddr := genResp.Address
	foreignSender := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	receiver := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"

	txnToSign, err := transaction.MakePaymentTxn(
		signerAddr,
		receiver,
		1111,
		[]byte("mixed-group-sign-foreign-sign"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(sign): %v", err)
	}

	foreignTxn, err := transaction.MakePaymentTxn(
		foreignSender,
		receiver,
		2222,
		[]byte("mixed-group-sign-foreign-foreign"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(foreign): %v", err)
	}

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{
			{
				AuthAddress: signerAddr,
				TxnBytesHex: encodeTxnToHex(txnToSign),
			},
			{
				TxnBytesHex: encodeTxnToHex(foreignTxn),
			},
		},
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}

	var planResp signerapi.GroupPlanResponse
	decodeResponse(t, planW, &planResp)
	if planResp.Error != "" {
		t.Fatalf("/plan returned error: %s", planResp.Error)
	}
	if len(planResp.Transactions) != 2 {
		t.Fatalf("/plan transactions = %d, want 2", len(planResp.Transactions))
	}
	if planResp.Mutations == nil || planResp.Mutations.ForeignCount != 1 {
		t.Fatalf("/plan mutations foreign_count = %#v, want 1 foreign", planResp.Mutations)
	}

	var plannedSignTxn types.Transaction
	if err := msgpack.Decode(mustDecodeTxnBytesHex(t, planResp.Transactions[0])[2:], &plannedSignTxn); err != nil {
		t.Fatalf("Decode planned sign txn: %v", err)
	}
	var plannedForeignTxn types.Transaction
	if err := msgpack.Decode(mustDecodeTxnBytesHex(t, planResp.Transactions[1])[2:], &plannedForeignTxn); err != nil {
		t.Fatalf("Decode planned foreign txn: %v", err)
	}

	if plannedSignTxn.Sender.String() != signerAddr {
		t.Fatalf("planned sign txn sender = %q, want %q", plannedSignTxn.Sender.String(), signerAddr)
	}
	if plannedForeignTxn.Sender.String() != foreignSender {
		t.Fatalf("planned foreign txn sender = %q, want %q", plannedForeignTxn.Sender.String(), foreignSender)
	}
	if plannedSignTxn.Group != plannedForeignTxn.Group {
		t.Fatal("planned transactions should share the same computed group ID")
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", signW.Code, signW.Body.String())
	}

	var signResp signerapi.GroupSignResponse
	decodeResponse(t, signW, &signResp)
	if signResp.Error != "" {
		t.Fatalf("/sign returned error: %s", signResp.Error)
	}
	if len(signResp.Signed) != 2 {
		t.Fatalf("/sign signed count = %d, want 2", len(signResp.Signed))
	}
	if signResp.Signed[0] == "" {
		t.Fatal("/sign signed[0] empty, want signer-owned slot signed")
	}
	if signResp.Signed[1] != "" {
		t.Fatalf("/sign signed[1] = %q, want empty string for foreign slot", signResp.Signed[1])
	}
	if signResp.Mutations == nil || signResp.Mutations.ForeignCount != 1 {
		t.Fatalf("/sign mutations foreign_count = %#v, want 1 foreign", signResp.Mutations)
	}
}

func mustDecodeTxnBytesHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return data
}

func TestPlanAndSignAgreeOnDummyAndFeeMutationsForSingleFalconGroup(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	algodCleanup := configureMockAlgod(t, server)
	defer algodCleanup()

	server.config.UserAutoApprove = true
	server.registry.Get(auth.DefaultIdentityID).Config().SetUserAutoApprove(true)

	receiver := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	falconBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "aplane.falcon1024.v1"})
	falconW := httptest.NewRecorder()
	server.handleAdminGenerate(falconW, requestWithIdentity(http.MethodPost, "/admin/generate", falconBody))
	if falconW.Code != http.StatusOK {
		t.Fatalf("generate falcon failed: %d: %s", falconW.Code, falconW.Body.String())
	}
	var falconResp AdminGenerateResponse
	decodeResponse(t, falconW, &falconResp)

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

	falconTxn, err := transaction.MakePaymentTxn(
		falconResp.Address,
		receiver,
		2222,
		[]byte("single-falcon-dummy-budget"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn(falcon): %v", err)
	}

	reqJSON, err := json.Marshal(signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: falconResp.Address,
			TxnBytesHex: encodeTxnToHex(falconTxn),
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

	var planResp signerapi.GroupPlanResponse
	decodeResponse(t, planW, &planResp)
	if planResp.Error != "" {
		t.Fatalf("/plan returned error: %s", planResp.Error)
	}
	if planResp.Mutations == nil {
		t.Fatal("/plan expected mutations for single falcon group")
	}
	if planResp.Mutations.DummiesAdded <= 0 {
		t.Fatalf("/plan mutations dummies_added = %#v, want > 0", planResp.Mutations)
	}
	if !reflect.DeepEqual(planResp.Mutations.FeesModified, []int{0}) {
		t.Fatalf("/plan fees_modified = %#v, want [0]", planResp.Mutations.FeesModified)
	}
	if want := planResp.Mutations.DummiesAdded * 1000; planResp.Mutations.TotalFeesDelta != want {
		t.Fatalf("/plan total_fees_delta = %d, want %d", planResp.Mutations.TotalFeesDelta, want)
	}
	if planResp.Mutations.OriginalCount != 1 || planResp.Mutations.FinalCount != len(planResp.Transactions) {
		t.Fatalf("/plan mutations counts = %#v, want original=1 final=%d", planResp.Mutations, len(planResp.Transactions))
	}
	if planResp.Mutations.Reason != "lsig_budget" {
		t.Fatalf("/plan reason = %q, want lsig_budget", planResp.Mutations.Reason)
	}

	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusOK {
		t.Fatalf("/sign failed: %d: %s", signW.Code, signW.Body.String())
	}

	var signResp signerapi.GroupSignResponse
	decodeResponse(t, signW, &signResp)
	if signResp.Error != "" {
		t.Fatalf("/sign returned error: %s", signResp.Error)
	}
	if signResp.Mutations == nil {
		t.Fatal("/sign expected mutations for single falcon group")
	}
	if signResp.Mutations.DummiesAdded != planResp.Mutations.DummiesAdded ||
		signResp.Mutations.TotalFeesDelta != planResp.Mutations.TotalFeesDelta ||
		!reflect.DeepEqual(signResp.Mutations.FeesModified, planResp.Mutations.FeesModified) {
		t.Fatalf("/sign mutations = %#v, want parity with /plan %#v", signResp.Mutations, planResp.Mutations)
	}
	if len(signResp.Signed) != len(planResp.Transactions) {
		t.Fatalf("/sign signed count = %d, want %d", len(signResp.Signed), len(planResp.Transactions))
	}

	var planFalconTxn, planDummyTxn types.Transaction
	if err := msgpack.Decode(mustDecodeTxnBytesHex(t, planResp.Transactions[0])[2:], &planFalconTxn); err != nil {
		t.Fatalf("decode planned falcon txn: %v", err)
	}
	if err := msgpack.Decode(mustDecodeTxnBytesHex(t, planResp.Transactions[1])[2:], &planDummyTxn); err != nil {
		t.Fatalf("decode planned dummy txn: %v", err)
	}

	if want := falconTxn.Fee + types.MicroAlgos(planResp.Mutations.TotalFeesDelta); planFalconTxn.Fee != want {
		t.Fatalf("planned falcon fee = %d, want %d", planFalconTxn.Fee, want)
	}
	if planDummyTxn.Fee != 0 {
		t.Fatalf("planned dummy fee = %d, want 0", planDummyTxn.Fee)
	}
	if planFalconTxn.Group == (types.Digest{}) || planDummyTxn.Group == (types.Digest{}) || planFalconTxn.Group != planDummyTxn.Group {
		t.Fatalf("planned group IDs not canonicalized together: falcon=%x dummy=%x", planFalconTxn.Group, planDummyTxn.Group)
	}

	for i, signedHex := range signResp.Signed {
		signedBytes, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatalf("DecodeString(%d) error = %v", i, err)
		}
		var stxn types.SignedTxn
		if err := msgpack.Decode(signedBytes, &stxn); err != nil {
			t.Fatalf("msgpack.Decode(%d) error = %v", i, err)
		}
		if got := encodeTxnToHex(stxn.Txn); got != planResp.Transactions[i] {
			t.Fatalf("signed canonical txn mismatch at index %d:\nplan=%s\nsign=%s", i, planResp.Transactions[i], got)
		}
	}
}

// TestSignReplansAgainstCurrentSnapshotAfterKeyRemoval verifies the
// cross-endpoint snapshot-divergence rule from FORMAL_TXN_PLANNING_MODEL.md:
// /plan and /sign are independent HTTP requests, and /sign re-plans against
// its own current snapshot rather than treating any prior /plan response as
// authoritative. There is no "plan token" in GroupSignRequest, so the
// no-token aspect is structurally enforced by the request grammar; what
// this test asserts is the runtime aspect: a snapshot change between /plan
// and /sign is observable to /sign.
func TestSignReplansAgainstCurrentSnapshotAfterKeyRemoval(t *testing.T) {
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
		[]byte("plan-sign-snapshot-divergence"),
		"",
		sp,
	)
	if err != nil {
		t.Fatalf("MakePaymentTxn() error = %v", err)
	}

	reqBody := signerapi.GroupSignRequest{
		Requests: []signerapi.SignRequest{{
			AuthAddress: genResp.Address,
			TxnBytesHex: encodeTxnToHex(txn),
		}},
	}
	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// /plan succeeds against snapshot A (key present).
	planW := httptest.NewRecorder()
	server.handlePlan(planW, requestWithIdentity(http.MethodPost, "/plan", reqJSON))
	if planW.Code != http.StatusOK {
		t.Fatalf("/plan failed: %d: %s", planW.Code, planW.Body.String())
	}
	var planResp signerapi.GroupPlanResponse
	decodeResponse(t, planW, &planResp)
	if planResp.Error != "" {
		t.Fatalf("/plan returned error: %s", planResp.Error)
	}

	// Move to snapshot B: remove the key file from disk and reload the index.
	keyPath := server.keyPaths.KeyFilePath(auth.DefaultIdentityID, genResp.Address)
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("os.Remove(%q) error = %v", keyPath, err)
	}
	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest() after key removal error = %v", err)
	}

	// /sign with the byte-identical request must observe snapshot B and reject.
	signW := httptest.NewRecorder()
	server.handleSign(signW, requestWithIdentity(http.MethodPost, "/sign", reqJSON))
	if signW.Code != http.StatusBadRequest {
		t.Fatalf("/sign status = %d, want %d; body = %s", signW.Code, http.StatusBadRequest, signW.Body.String())
	}
	body := signW.Body.String()
	if !strings.Contains(body, "no key found for address") {
		t.Fatalf("/sign body = %q, want 'no key found for address' substring", body)
	}
	if !strings.Contains(body, genResp.Address) {
		t.Fatalf("/sign body = %q, want generated address %q substring", body, genResp.Address)
	}
}
