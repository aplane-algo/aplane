// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

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
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
)

func testGenesisHash(t *testing.T, encoded string) []byte {
	t.Helper()
	hash, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode genesis hash: %v", err)
	}
	return hash
}

// networkTestAlgod is an algod for the network with genesis hash and ID. It
// answers suggested parameters, counting them, and counts every other call.
func networkTestAlgod(t *testing.T, genesisHash []byte, genesisID string) (*algod.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var paramsCalls, otherCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/params" {
			otherCalls.Add(1)
			http.Error(w, "unexpected algod call", http.StatusInternalServerError)
			return
		}
		paramsCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
			ConsensusVersion: string(protocol.ConsensusV42),
			Fee:              0,
			MinFee:           1000,
			LastRound:        1000,
			GenesisHash:      genesisHash,
			GenesisId:        genesisID,
		})
	}))
	t.Cleanup(server.Close)
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	return client, &paramsCalls, &otherCalls
}

func networkTestTxn(t *testing.T, sender string, genesisHash []byte, genesisID string) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(sender, sender, 0, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 2000,
		GenesisHash: genesisHash, GenesisID: genesisID, FlatFee: true,
	})
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	return txn
}

func TestCheckActiveNetworkComparesEachTransactionsGenesis(t *testing.T) {
	testnet := testGenesisHash(t, config.AlgorandTestnetGenesisHash)
	mainnet := testGenesisHash(t, config.AlgorandMainnetGenesisHash)
	unknown := make([]byte, 32)
	sender := crypto.GenerateAccount().Address.String()

	tests := []struct {
		name  string
		txns  []types.Transaction
		wants []string // empty: accepted
	}{
		{"same hash and ID", []types.Transaction{networkTestTxn(t, sender, testnet, "testnet-v1.0")}, nil},
		{"same hash, no ID", []types.Transaction{networkTestTxn(t, sender, testnet, "")}, nil},
		{"another known network", []types.Transaction{networkTestTxn(t, sender, mainnet, "mainnet-v1.0")}, []string{
			"transaction at index 0 is for another network",
			config.AlgorandMainnetGenesisHash + " (mainnet)",
			config.AlgorandTestnetGenesisHash + " (testnet)",
		}},
		{"a later position", []types.Transaction{
			networkTestTxn(t, sender, testnet, "testnet-v1.0"),
			networkTestTxn(t, sender, unknown, ""),
		}, []string{"transaction at index 1 is for another network: genesis hash " + base64.StdEncoding.EncodeToString(unknown) + ","}},
		{"same hash, other ID", []types.Transaction{networkTestTxn(t, sender, testnet, "mainnet-v1.0")}, []string{
			`transaction at index 0 is for another network: genesis ID "mainnet-v1.0", the active algod's is "testnet-v1.0"`,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _, _ := networkTestAlgod(t, testnet, "testnet-v1.0")
			eng, err := NewEngine("testnet", WithAlgodClient(client))
			if err != nil {
				t.Fatalf("NewEngine() error = %v", err)
			}
			err = eng.checkActiveNetwork(context.Background(), tt.txns)
			if len(tt.wants) == 0 {
				if err != nil {
					t.Fatalf("checkActiveNetwork() error = %v, want accepted", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkActiveNetwork() accepted a transaction for another network")
			}
			for _, want := range tt.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

// An algod that names no genesis cannot vouch for any transaction's network.
func TestCheckActiveNetworkRefusesAnAlgodWithoutAGenesisHash(t *testing.T) {
	client, _, _ := networkTestAlgod(t, nil, "")
	eng, err := NewEngine("testnet", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	txn := networkTestTxn(t, crypto.GenerateAccount().Address.String(), make([]byte, 32), "")
	err = eng.checkActiveNetwork(context.Background(), []types.Transaction{txn})
	if err == nil || !strings.Contains(err.Error(), "algod reported a genesis hash of 0 bytes, want 32") {
		t.Fatalf("checkActiveNetwork() error = %v, want the missing genesis refused", err)
	}
}

// The check costs no algod call of its own: it reuses the suggested
// parameters a transaction was built from, and one read serves the
// consensus check and the genesis check.
func TestCheckActiveNetworkReusesTheSuggestedParamsRead(t *testing.T) {
	testnet := testGenesisHash(t, config.AlgorandTestnetGenesisHash)
	client, paramsCalls, _ := networkTestAlgod(t, testnet, "testnet-v1.0")
	eng, err := NewEngine("testnet", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	sp, err := eng.getSuggestedParamsWithFee(context.Background(), 0, false)
	if err != nil {
		t.Fatalf("getSuggestedParamsWithFee() error = %v", err)
	}
	sender := crypto.GenerateAccount().Address.String()
	txn, err := transaction.MakePaymentTxn(sender, sender, 0, nil, "", sp)
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := eng.checkActiveNetwork(context.Background(), []types.Transaction{txn}); err != nil {
			t.Fatalf("checkActiveNetwork() error = %v", err)
		}
		if err := eng.validateAlgodConsensus(context.Background()); err != nil {
			t.Fatalf("validateAlgodConsensus() error = %v", err)
		}
	}
	if got := paramsCalls.Load(); got != 1 {
		t.Fatalf("SuggestedParams calls = %d, want 1", got)
	}
}

// A transaction for another network is refused before the signer sees it on
// every path whose transactions apshell did not build: a transaction file
// (sign) and a plugin draft in the default group mode, both through
// checkReadyToSign, and a presign-plan draft. A pregrouped-signed group, which
// no signer signs, is refused before it is sent to algod.
func TestPathsRefuseATransactionForAnotherNetworkBeforeSigning(t *testing.T) {
	testnet := testGenesisHash(t, config.AlgorandTestnetGenesisHash)
	mainnet := testGenesisHash(t, config.AlgorandMainnetGenesisHash)
	plugin := crypto.GenerateAccount().Address.String()
	managed := crypto.GenerateAccount().Address.String()
	mainnetTxns := []types.Transaction{
		networkTestTxn(t, plugin, mainnet, "mainnet-v1.0"),
		networkTestTxn(t, managed, mainnet, "mainnet-v1.0"),
	}

	paths := []struct {
		name string
		run  func(*Engine) error
	}{
		{"sign file", func(eng *Engine) error {
			_, err := eng.SignAndSubmitTransactions(context.Background(), mainnetTxns[1:], false)
			return err
		}},
		{"default plugin group", func(eng *Engine) error {
			_, err := eng.SignAndSubmitGroup(context.Background(), mainnetTxns, nil)
			return err
		}},
		{"presign-plan", func(eng *Engine) error {
			_, err := eng.SignAndSubmitWithPluginSigners(context.Background(), mainnetTxns,
				map[string]string{plugin: "plugin-ref"}, nil,
				func([]PluginSlotSignRequest) ([]PluginSlotSigned, error) {
					t.Error("the plugin was asked to sign a slot for another network")
					return nil, nil
				}, nil)
			return err
		}},
		{"pregrouped-signed", func(eng *Engine) error {
			// signedGroup builds for an unknown network, not the active one.
			encoded, _ := signedGroup(t, "a", "b")
			group, err := DecodePregroupedSigned(encoded)
			if err != nil {
				t.Fatalf("DecodePregroupedSigned() error = %v", err)
			}
			_, err = eng.SubmitPregroupedSigned(context.Background(), group)
			return err
		}},
	}
	for _, path := range paths {
		t.Run(path.name, func(t *testing.T) {
			var signerCalls atomic.Int32
			signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				signerCalls.Add(1)
				http.Error(w, "signer must not be called", http.StatusInternalServerError)
			}))
			t.Cleanup(signer.Close)
			client, _, otherAlgodCalls := networkTestAlgod(t, testnet, "testnet-v1.0")
			eng, err := NewEngine("testnet", WithAlgodClient(client))
			if err != nil {
				t.Fatalf("NewEngine() error = %v", err)
			}
			eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)

			err = path.run(eng)
			if err == nil || !strings.Contains(err.Error(), "transaction at index 0 is for another network") {
				t.Fatalf("error = %v, want the transaction at index 0 refused as for another network", err)
			}
			if got := signerCalls.Load(); got != 0 {
				t.Fatalf("signer calls = %d, want 0", got)
			}
			if got := otherAlgodCalls.Load(); got != 0 {
				t.Fatalf("algod calls other than suggested parameters = %d, want 0", got)
			}
		})
	}
}
