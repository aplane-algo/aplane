// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestSignFileRejectsInvalidFile(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	if _, err := app.SignFile(context.Background(), SignFileRequest{
		FilePath: filepath.Join(t.TempDir(), "missing.txn"),
		Wait:     true,
	}); err == nil {
		t.Fatal("SignFile() error = nil, want failure")
	}
}

func TestSignFileLoadsTransactionsBeforeSubmission(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), dir)
	_, err = app.SignFile(context.Background(), SignFileRequest{
		FilePath: path,
		Wait:     true,
	})
	if err == nil {
		t.Fatal("SignFile() error = nil, want failure")
	}
}

func TestSubmitPluginTransactionsRequiresConnection(t *testing.T) {
	eng, err := engine.NewEngine("testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	app := New(eng, config.DefaultConfig(), t.TempDir())
	_, err = app.SubmitPluginTransactions(context.Background(), "plugin", &jsonrpc.ExecuteResult{}, nil)
	if err == nil || err.Error() != "not connected to signer" {
		t.Fatalf("SubmitPluginTransactions() error = %v, want not connected", err)
	}
}

// rekeySubmitTestTxn is a payment from sender that rekeys it to target.
func rekeySubmitTestTxn(sender, target types.Address) types.Transaction {
	return types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1000, FirstValid: 1, LastValid: 10, RekeyTo: target},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: sender},
	}
}

func rawPluginIntents(txns ...types.Transaction) []jsonrpc.TransactionIntent {
	intents := make([]jsonrpc.TransactionIntent, len(txns))
	for i, txn := range txns {
		intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
	}
	return intents
}

func signedPluginIntents(t *testing.T, txns ...types.Transaction) []jsonrpc.TransactionIntent {
	t.Helper()
	gid, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("ComputeGroupID() error = %v", err)
	}
	intents := make([]jsonrpc.TransactionIntent, len(txns))
	for i, txn := range txns {
		txn.Group = gid
		raw := msgpack.Encode(types.SignedTxn{Sig: types.Signature{1}, Txn: txn})
		intents[i] = jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentSigned, Encoded: base64.StdEncoding.EncodeToString(raw)}
	}
	return intents
}

// Submission of a plugin-built group, in every mode, refuses a transaction at
// any position that rekeys an account to a held aplane key that is not a valid
// rekey target, the account's own address included, before anything is sent
// to the signer or the node. A held aplane key that is a valid rekey target,
// and a foreign address, are not refused: the group goes on to the signer or
// the node. The REPL, MCP and JavaScript all submit through this function.
func TestSubmitPluginTransactionsRefusesARekeyToAHeldInvalidTarget(t *testing.T) {
	var signerRequests, algodRequests atomic.Int32
	signerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signerRequests.Add(1)
		http.Error(w, "test signer", http.StatusServiceUnavailable)
	}))
	defer signerServer.Close()
	algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		algodRequests.Add(1)
		http.Error(w, "test node", http.StatusServiceUnavailable)
	}))
	defer algodServer.Close()
	algodClient, err := algod.MakeClient(algodServer.URL, "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(algodClient))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signerServer.URL)

	native, rotating, htlc, foreign, other := types.Address{20}, types.Address{21}, types.Address{22}, types.Address{25}, types.Address{1}
	if err := eng.PopulateSignerCache([]signerapi.KeyInfo{
		{Address: native.String(), KeyType: "ed25519", ValidRekeyTarget: true},
		{Address: rotating.String(), KeyType: "aplane.rotating-triple-wotsc.v1", SigningFlow: signerapi.SigningFlowRotating1},
		{Address: htlc.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true},
	}); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	app := New(eng, config.DefaultConfig(), t.TempDir())

	refusal := func(position string, target types.Address, keyType string) string {
		return "transaction " + position + ": cannot rekey to " + target.String() +
			": this signer holds its aplane key (" + keyType + "), which is not a valid rekey target"
	}
	for _, tc := range []struct {
		name    string
		txn     types.Transaction
		keyType string // set when the rekey is refused
	}{
		{name: "held rotating account", txn: rekeySubmitTestTxn(other, rotating), keyType: "aplane.rotating-triple-wotsc.v1"},
		{name: "held generic LogicSig that is not a valid rekey target", txn: rekeySubmitTestTxn(other, htlc), keyType: "aplane.htlc.v1"},
		{name: "own address that is not a valid rekey target", txn: rekeySubmitTestTxn(rotating, rotating), keyType: "aplane.rotating-triple-wotsc.v1"},
		{name: "held aplane key that is a valid rekey target", txn: rekeySubmitTestTxn(other, native)},
		{name: "foreign address", txn: rekeySubmitTestTxn(other, foreign)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filler := rekeySubmitTestTxn(types.Address{7}, types.Address{})
			for mode, c := range map[string]struct {
				result   *jsonrpc.ExecuteResult
				position string
			}{
				"default": {result: &jsonrpc.ExecuteResult{Transactions: rawPluginIntents(tc.txn)}, position: "1"},
				// The plugin signs the rekey.
				"presign-plan": {result: &jsonrpc.ExecuteResult{
					GroupMode:     jsonrpc.GroupModePresignPlan,
					Transactions:  rawPluginIntents(filler, tc.txn),
					PluginSigners: []jsonrpc.PluginSigner{{Address: tc.txn.Sender.String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
				}, position: "2"},
				"pregrouped-signed": {result: &jsonrpc.ExecuteResult{
					GroupMode:    jsonrpc.GroupModePregroupedSigned,
					Transactions: signedPluginIntents(t, filler, tc.txn),
				}, position: "2"},
			} {
				signerRequests.Store(0)
				algodRequests.Store(0)
				_, err := app.SubmitPluginTransactions(context.Background(), "plugin", c.result, nil)
				sent := signerRequests.Load() + algodRequests.Load()
				if tc.keyType != "" {
					if want := refusal(c.position, tc.txn.RekeyTo, tc.keyType); err == nil || err.Error() != want {
						t.Errorf("%s: error = %v, want %q", mode, err, want)
					}
					if sent != 0 {
						t.Errorf("%s: a refused group sent %d request(s) to the signer or the node", mode, sent)
					}
					continue
				}
				if err != nil && strings.Contains(err.Error(), "not a valid rekey target") {
					t.Errorf("%s: refused a rekey the signer allows: %v", mode, err)
				}
				if sent == 0 {
					t.Errorf("%s: the group reached neither the signer nor the node (error %v)", mode, err)
				}
			}
		})
	}
}
