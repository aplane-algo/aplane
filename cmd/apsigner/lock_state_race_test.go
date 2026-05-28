// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

func TestHandleSignReturnsForbiddenWhenKeySessionLocksMidRequest(t *testing.T) {
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
	ir.SnapshotKeySession().Destroy()

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
		[]byte("lock-race"),
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

	w := httptest.NewRecorder()
	server.handleSign(w, requestWithIdentity(http.MethodPost, "/sign", reqJSON))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp signerapi.GroupSignResponse
	decodeResponse(t, w, &resp)
	if resp.Error != "signer is locked" {
		t.Fatalf("error = %q, want signer is locked", resp.Error)
	}
}

func TestHandleAdminGenerateReturnsForbiddenWhenMasterKeyClearedMidRequest(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.DefaultIdentityID)
	ir.KeyStore().ClearMasterKey()

	reqBody, _ := json.Marshal(AdminGenerateRequest{KeyType: "ed25519"})
	w := httptest.NewRecorder()
	server.handleAdminGenerate(w, requestWithIdentity(http.MethodPost, "/admin/generate", reqBody))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp AdminGenerateResponse
	decodeResponse(t, w, &resp)
	if resp.Error != "signer is locked" {
		t.Fatalf("error = %q, want signer is locked", resp.Error)
	}
}
