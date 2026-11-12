// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
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
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

// A plugin builds its transactions, genesis included. On a testnet shell, a
// raw intent for mainnet is refused before the signer is asked to plan or
// sign it, in both group modes that send plugin drafts to the signer.
func TestSubmitPluginTransactionsRefusesADraftForAnotherNetwork(t *testing.T) {
	decode := func(encoded string) []byte {
		hash, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode genesis hash: %v", err)
		}
		return hash
	}
	testnet := decode(config.AlgorandTestnetGenesisHash)
	mainnet := decode(config.AlgorandMainnetGenesisHash)
	plugin := crypto.GenerateAccount().Address.String()
	managed := crypto.GenerateAccount().Address.String()
	intent := func(sender string) jsonrpc.TransactionIntent {
		txn, err := transaction.MakePaymentTxn(sender, sender, 0, nil, "", types.SuggestedParams{
			Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 2000,
			GenesisHash: mainnet, GenesisID: "mainnet-v1.0", FlatFee: true,
		})
		if err != nil {
			t.Fatalf("make txn: %v", err)
		}
		return jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
	}

	results := map[string]*jsonrpc.ExecuteResult{
		"default": {Transactions: []jsonrpc.TransactionIntent{intent(managed)}},
		"presign-plan": {
			GroupMode:     jsonrpc.GroupModePresignPlan,
			Transactions:  []jsonrpc.TransactionIntent{intent(plugin), intent(managed)},
			PluginSigners: []jsonrpc.PluginSigner{{Address: plugin, SignerRef: "ref", Kind: jsonrpc.PluginSignerKindCallback}},
		},
	}
	for mode, result := range results {
		t.Run(mode, func(t *testing.T) {
			algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/transactions/params" {
					http.Error(w, "unexpected algod call", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
					ConsensusVersion: string(protocol.ConsensusV42), MinFee: 1000, LastRound: 1000,
					GenesisHash: testnet, GenesisId: "testnet-v1.0",
				})
			}))
			t.Cleanup(algodServer.Close)
			var signerCalls atomic.Int32
			signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				signerCalls.Add(1)
				http.Error(w, "signer must not be called", http.StatusInternalServerError)
			}))
			t.Cleanup(signer.Close)
			client, err := algod.MakeClient(algodServer.URL, "")
			if err != nil {
				t.Fatalf("algod.MakeClient() error = %v", err)
			}
			eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(client))
			if err != nil {
				t.Fatalf("NewEngine() error = %v", err)
			}
			eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
			app := New(eng, config.DefaultConfig(), t.TempDir())

			_, err = app.SubmitPluginTransactions(context.Background(), "plugin", result, nil)
			if err == nil || !strings.Contains(err.Error(), "transaction at index 0 is for another network") ||
				!strings.Contains(err.Error(), "(mainnet)") || !strings.Contains(err.Error(), "(testnet)") {
				t.Fatalf("SubmitPluginTransactions() error = %v, want the mainnet draft refused on testnet", err)
			}
			if got := signerCalls.Load(); got != 0 {
				t.Fatalf("signer calls = %d, want 0", got)
			}
		})
	}
}
