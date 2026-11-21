// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A transaction file that rekeys its sender is confirmed, and the node then
// cannot answer the auth-cache refresh. The command still succeeds, and says
// that the cache is stale and how to mend it, as the rekey command does.
func TestSignedTransactionsWarnWhenTheRefreshAfterARekeyFails(t *testing.T) {
	account, target := crypto.GenerateAccount(), crypto.GenerateAccount().Address
	genesis, err := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			keys := []signerapi.KeyInfo{{Address: account.Address.String(), KeyType: "ed25519", AuthorizationKind: "ed25519", ValidRekeyTarget: true}}
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: keys})
		case r.Method == http.MethodGet && r.URL.Path == "/status":
			_ = json.NewEncoder(w).Encode(signerapi.StatusResponse{State: "unlocked", KeyCount: 1})
		case r.Method == http.MethodPost && r.URL.Path == "/sign":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			signed := make([]string, len(req.Requests))
			for i, item := range req.Requests {
				txn, err := txnutil.DecodePrefixedHex(item.TxnBytesHex)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				_, raw, err := signing.SignTransactionWithKey(account.PrivateKey, txn)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				signed[i] = hex.EncodeToString(raw)
			}
			_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(signer.Close)
	var submitted atomic.Bool
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 100,
				GenesisId: "testnet-v1.0", GenesisHash: genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			if submitted.Load() {
				http.Error(w, `{"message":"node unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			_ = json.NewEncoder(w).Encode(models.Account{Address: address, Amount: 10_000_000, MinBalance: 100_000, Status: "Offline"})
		case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions":
			submitted.Store(true)
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "SUBMITTED"})
		case r.URL.Path == "/v2/status":
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 100})
		case strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 101})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(models.PendingTransactionInfoResponse{ConfirmedRound: 101}))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng := engine.NewEngine("testnet", engine.WithAlgodClient(client))
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	app := New(eng, config.DefaultConfig(), t.TempDir())

	rekey, err := transaction.MakePaymentTxn(account.Address.String(), account.Address.String(), 0, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 100, LastRoundValid: 1100, GenesisHash: genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatalf("make rekey: %v", err)
	}
	rekey.RekeyTo = target

	summary, err := app.signTransactions(context.Background(), []types.Transaction{rekey}, true)
	if err != nil {
		t.Fatalf("signTransactions() error = %v, want the confirmed submission to succeed", err)
	}
	if !summary.Confirmed {
		t.Fatal("summary.Confirmed = false, want the submission confirmed")
	}
	var found *Warning
	for i := range summary.Warnings {
		if summary.Warnings[i].Code == "auth_cache_refresh_failed" {
			found = &summary.Warnings[i]
		}
	}
	if found == nil {
		t.Fatalf("warnings = %+v, want auth_cache_refresh_failed", summary.Warnings)
	}
	if !strings.Contains(found.Message, account.Address.String()) || !strings.Contains(found.Message, "rekey refresh") {
		t.Fatalf("warning = %q, want the account named and rekey refresh suggested", found.Message)
	}
}
