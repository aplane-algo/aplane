// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
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
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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

			group, err := app.CheckPluginGroup(context.Background(), result, interactive)
			if err != nil {
				t.Fatalf("CheckPluginGroup() error = %v", err)
			}
			_, err = app.SubmitPluginTransactions(context.Background(), "plugin", group, nil)
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

// A wrong-network group that rekeys an account to an address the signer holds
// a valid-rekey-target aplane key for passes the rekey rule, at the check and
// again at submission, which each fetch the signer's key list, and is then
// refused for its network: before /plan or /sign in the default and
// presign-plan modes, and before broadcast for pregrouped-signed.
func TestSubmitPluginTransactionsRefusesARekeyingGroupForAnotherNetwork(t *testing.T) {
	decode := func(encoded string) []byte {
		hash, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode genesis hash: %v", err)
		}
		return hash
	}
	testnet := decode(config.AlgorandTestnetGenesisHash)
	mainnet := decode(config.AlgorandMainnetGenesisHash)
	target := crypto.GenerateAccount().Address
	keys := []signerapi.KeyInfo{{Address: target.String(), KeyType: "ed25519", ValidRekeyTarget: true}}

	mainnetTxn := func(sender types.Address, note string, rekey bool) types.Transaction {
		txn, err := transaction.MakePaymentTxn(sender.String(), sender.String(), 0, []byte(note), "", types.SuggestedParams{
			Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 2000,
			GenesisHash: mainnet, GenesisID: "mainnet-v1.0", FlatFee: true,
		})
		if err != nil {
			t.Fatalf("make txn: %v", err)
		}
		if rekey {
			txn.RekeyTo = target
		}
		return txn
	}
	raw := func(txn types.Transaction) jsonrpc.TransactionIntent {
		return jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
	}
	pluginAccount := crypto.GenerateAccount()
	managed := crypto.GenerateAccount().Address

	// A signed, grouped pair whose second transaction rekeys the account.
	pregrouped := func() []jsonrpc.TransactionIntent {
		txns := []types.Transaction{mainnetTxn(pluginAccount.Address, "a", false), mainnetTxn(pluginAccount.Address, "b", true)}
		gid, err := crypto.ComputeGroupID(txns)
		if err != nil {
			t.Fatalf("compute group id: %v", err)
		}
		intents := make([]jsonrpc.TransactionIntent, len(txns))
		for i := range txns {
			txns[i].Group = gid
			_, signed, err := signing.SignTransactionWithKey(pluginAccount.PrivateKey, txns[i])
			if err != nil {
				t.Fatalf("sign txn: %v", err)
			}
			intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentSigned, Encoded: base64.StdEncoding.EncodeToString(signed)}
		}
		return intents
	}

	results := map[string]*jsonrpc.ExecuteResult{
		"default": {Transactions: []jsonrpc.TransactionIntent{raw(mainnetTxn(managed, "m", true))}},
		"presign-plan": {
			GroupMode:     jsonrpc.GroupModePresignPlan,
			Transactions:  []jsonrpc.TransactionIntent{raw(mainnetTxn(pluginAccount.Address, "p", false)), raw(mainnetTxn(managed, "m", true))},
			PluginSigners: []jsonrpc.PluginSigner{{Address: pluginAccount.Address.String(), SignerRef: "ref", Kind: jsonrpc.PluginSignerKindCallback}},
		},
		"pregrouped-signed": {GroupMode: jsonrpc.GroupModePregroupedSigned, Transactions: pregrouped()},
	}
	for mode, result := range results {
		t.Run(mode, func(t *testing.T) {
			var algodOther atomic.Int32
			algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v2/transactions/params" {
					algodOther.Add(1)
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
			var mu sync.Mutex
			var signerPaths []string
			signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				signerPaths = append(signerPaths, r.URL.Path)
				mu.Unlock()
				if r.Method != http.MethodGet || r.URL.Path != "/keys" {
					http.Error(w, "the signer must only be asked for its keys", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
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

			group, err := app.CheckPluginGroup(context.Background(), result, interactive)
			if err != nil {
				t.Fatalf("CheckPluginGroup() error = %v, want the rekey to a held valid target to pass", err)
			}
			_, err = app.SubmitPluginTransactions(context.Background(), "plugin", group, nil)
			if err == nil || !strings.HasPrefix(err.Error(), "transaction at index 0 is for another network") {
				t.Fatalf("SubmitPluginTransactions() error = %v, want the group refused for its network", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(signerPaths, []string{"/keys", "/keys"}) {
				t.Fatalf("signer paths = %v, want the key list twice (check and submission) and nothing else", signerPaths)
			}
			if got := algodOther.Load(); got != 0 {
				t.Fatalf("algod calls other than suggested parameters = %d, want 0", got)
			}
		})
	}
}
