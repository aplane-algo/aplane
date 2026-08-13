// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

func consensusTestAlgod(t *testing.T, version string, unexpectedCalls *atomic.Int32) (*algod.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/params" {
			if unexpectedCalls != nil {
				unexpectedCalls.Add(1)
			}
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{ConsensusVersion: version})
	}))
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		server.Close()
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client, server
}

func TestValidateAlgodConsensusAcceptsV42WithNilContext(t *testing.T) {
	client, server := consensusTestAlgod(t, string(protocol.ConsensusV42), nil)
	defer server.Close()
	var ctx context.Context
	if err := ValidateAlgodConsensus(ctx, client); err != nil {
		t.Fatalf("ValidateAlgodConsensus() error = %v", err)
	}
}

func TestSignAndSubmitTransactionsRejectsUnsupportedConsensusBeforeSigner(t *testing.T) {
	client, algodServer := consensusTestAlgod(t, string(protocol.ConsensusV41), nil)
	defer algodServer.Close()

	var signerCalls atomic.Int32
	signerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerCalls.Add(1)
		http.Error(w, "signer must not be called", http.StatusInternalServerError)
	}))
	defer signerServer.Close()

	eng, err := NewEngine("test", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")
	txn := presignTestTxn(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ", "prebuilt")

	_, err = eng.SignAndSubmitTransactions(context.Background(), []types.Transaction{txn}, false)
	if err == nil || !strings.Contains(err.Error(), "network consensus") {
		t.Fatalf("SignAndSubmitTransactions() error = %v, want unsupported-consensus rejection", err)
	}
	if signerCalls.Load() != 0 {
		t.Fatalf("signer calls = %d, want 0", signerCalls.Load())
	}
}

func TestGroupPlanningValidatesConsensusBeforeSigner(t *testing.T) {
	client, algodServer := consensusTestAlgod(t, string(protocol.ConsensusV41), nil)
	defer algodServer.Close()

	var signerCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerCalls.Add(1)
		http.Error(w, "signer must not be called", http.StatusInternalServerError)
	}))
	defer server.Close()

	eng, err := NewEngine("test", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")
	_, err = eng.RequestGroupPlanWithContext(context.Background(), []signerapi.SignRequest{{
		AuthAddress: "ADDR",
		TxnBytesHex: "545801",
	}})
	if err == nil || !strings.Contains(err.Error(), "network consensus") {
		t.Fatalf("RequestGroupPlanWithContext() error = %v, want unsupported-consensus rejection", err)
	}
	if signerCalls.Load() != 0 {
		t.Fatalf("signer calls = %d, want 0", signerCalls.Load())
	}
}

func TestGroupPlanningForwardsAfterConsensusValidation(t *testing.T) {
	client, algodServer := consensusTestAlgod(t, string(protocol.ConsensusV42), nil)
	defer algodServer.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plan" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{Transactions: []string{"545801"}})
	}))
	defer server.Close()

	eng, err := NewEngine("test", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")
	response, err := eng.RequestGroupPlanWithContext(context.Background(), []signerapi.SignRequest{{
		AuthAddress: "ADDR",
		TxnBytesHex: "545801",
	}})
	if err != nil {
		t.Fatalf("RequestGroupPlanWithContext() error = %v", err)
	}
	if len(response.Transactions) != 1 {
		t.Fatalf("planned transactions = %v, want one", response.Transactions)
	}
}
