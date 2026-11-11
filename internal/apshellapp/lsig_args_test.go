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
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	argsNative = types.Address{11}.String()
	argsHTLC   = types.Address{12}.String()
	argsPlugin = types.Address{13}.String()
	argsTo     = types.Address{14}.String()
)

// signRecorder keeps each /plan and /sign request the fake signer received.
type signRecorder struct {
	mu       sync.Mutex
	paths    []string
	requests []signerapi.GroupSignRequest
}

func (r *signRecorder) recorded() ([]string, []signerapi.GroupSignRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.paths...), append([]signerapi.GroupSignRequest(nil), r.requests...)
}

// lsigArgsTestApp is an app on a fake network whose signer holds an ed25519
// key and an HTLC LogicSig taking a preimage. The signer records each /plan
// and /sign request and refuses it, so a test sees what LogicSig arguments
// every position would have carried.
func lsigArgsTestApp(t *testing.T) (*App, *signRecorder) {
	t.Helper()
	network := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), Fee: 0, MinFee: 1000, LastRound: 100,
				GenesisId: "testnet-v1.0", GenesisHash: make([]byte, 32),
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			_ = json.NewEncoder(w).Encode(models.Account{
				Address: strings.TrimPrefix(r.URL.Path, "/v2/accounts/"), Amount: 5_000_000, MinBalance: 100_000, Status: "Offline",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(network.Close)

	recorder := &signRecorder{}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/plan" && r.URL.Path != "/sign" {
			// The client may ask for /status after a refused request.
			http.NotFound(w, r)
			return
		}
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode %s request: %v", r.URL.Path, err)
		}
		recorder.mu.Lock()
		recorder.paths = append(recorder.paths, r.URL.Path)
		recorder.requests = append(recorder.requests, req)
		recorder.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(signerapi.ErrorResponse{Error: "recorded by the test"})
	}))
	t.Cleanup(signer.Close)

	client, err := algod.MakeClient(network.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(client), engine.WithCacheStore(cache.NewStore(t.TempDir())))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	eng.SignerCache.Keys = map[string]string{argsNative: "ed25519", argsHTLC: "aplane.htlc.v1"}
	eng.SignerCache.SetGenericLsig(argsHTLC, true)
	eng.SignerCache.SetSigningArgs(argsHTLC, []cache.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}})
	eng.SignerCache.SetLogicSigResourceProfile(argsHTLC, lsigresource.Profile{
		ProgramBytes: 100, Default: &lsigresource.PathProfile{ArgumentBytes: 32, MaxOpcodeCost: 100},
	})
	eng.AuthCache = cache.NewAuthAddressCache()
	eng.AuthCache.AuthAddresses[argsNative] = ""
	eng.AuthCache.AuthAddresses[argsHTLC] = ""
	eng.SetCache.Sets = map[string][]string{"mixed": {argsNative, argsHTLC}}
	return New(eng, config.DefaultConfig(), t.TempDir()), recorder
}

func rawPaymentIntent(t *testing.T, from string) jsonrpc.TransactionIntent {
	t.Helper()
	sender, err := types.DecodeAddress(from)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := types.DecodeAddress(argsTo)
	if err != nil {
		t.Fatal(err)
	}
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1000, FirstValid: 100, LastValid: 1100, GenesisID: "testnet-v1.0", GenesisHash: types.Digest{}},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: 1},
	}
	return jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
}

// requireArgsByPosition checks the LogicSig arguments each position of a
// recorded request carried, by sender.
func requireArgsByPosition(t *testing.T, req signerapi.GroupSignRequest, want map[string]string) {
	t.Helper()
	for i, position := range req.Requests {
		sender := position.TxnSender
		if sender == "" {
			continue
		}
		wantArgs, declared := want[sender]
		switch {
		case !declared && len(position.LsigArgs) != 0:
			t.Errorf("position %d (%s) carried %v, want no LogicSig arguments", i+1, sender, position.LsigArgs)
		case declared && position.LsigArgs["preimage"] != wantArgs:
			t.Errorf("position %d (%s) carried %v, want preimage %s", i+1, sender, position.LsigArgs, wantArgs)
		}
	}
}

func TestPluginLsigArgsGoOnlyToPositionsWhoseKeyDeclaresThem(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	result := &jsonrpc.ExecuteResult{Transactions: []jsonrpc.TransactionIntent{
		rawPaymentIntent(t, argsNative), rawPaymentIntent(t, argsHTLC),
	}}
	if _, err := app.SubmitPluginTransactions(context.Background(), "plugin", result, map[string][]byte{"preimage": []byte("open")}); err == nil {
		t.Fatal("SubmitPluginTransactions() succeeded against a signer that refuses")
	}
	paths, requests := recorder.recorded()
	if len(requests) != 1 || paths[0] != "/sign" {
		t.Fatalf("signer requests = %v, want one /sign", paths)
	}
	requireArgsByPosition(t, requests[0], map[string]string{argsHTLC: hex.EncodeToString([]byte("open"))})
}

func TestPresignPluginLsigArgsGoOnlyToManagedPositionsWhoseKeyDeclaresThem(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	result := &jsonrpc.ExecuteResult{
		GroupMode: jsonrpc.GroupModePresignPlan,
		Transactions: []jsonrpc.TransactionIntent{
			rawPaymentIntent(t, argsPlugin), rawPaymentIntent(t, argsNative), rawPaymentIntent(t, argsHTLC),
		},
		PluginSigners: []jsonrpc.PluginSigner{{Address: argsPlugin, Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
	}
	if _, err := app.SubmitPluginTransactions(context.Background(), "plugin", result, map[string][]byte{"preimage": []byte("open")}); err == nil {
		t.Fatal("SubmitPluginTransactions() succeeded against a signer that refuses")
	}
	paths, requests := recorder.recorded()
	if len(requests) != 1 || paths[0] != "/plan" {
		t.Fatalf("signer requests = %v, want one /plan", paths)
	}
	if len(requests[0].Requests[0].LsigArgs) != 0 {
		t.Fatalf("plugin-signed slot carried %v", requests[0].Requests[0].LsigArgs)
	}
	requireArgsByPosition(t, requests[0], map[string]string{argsHTLC: hex.EncodeToString([]byte("open"))})
}

// A name no position's key declares would be dropped without a word, so it is
// refused before anything is sent to the signer.
func TestPluginLsigArgsRefuseANameNoPositionDeclares(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	result := &jsonrpc.ExecuteResult{Transactions: []jsonrpc.TransactionIntent{
		rawPaymentIntent(t, argsNative), rawPaymentIntent(t, argsHTLC),
	}}
	_, err := app.SubmitPluginTransactions(context.Background(), "plugin", result, map[string][]byte{
		"preimage": []byte("open"), "preimge": []byte("typo"),
	})
	if err == nil || !strings.Contains(err.Error(), "arg:preimge: no transaction here is signed by a key that declares this LogicSig argument") {
		t.Fatalf("SubmitPluginTransactions() error = %v, want the undeclared name refused", err)
	}
	if paths, _ := recorder.recorded(); len(paths) != 0 {
		t.Fatalf("signer requests = %v, want none", paths)
	}
}
