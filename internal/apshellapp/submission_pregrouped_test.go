// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestSubmitPluginTransactionsUnsupportedGroupMode(t *testing.T) {
	app := &App{}
	_, err := app.CheckPluginGroup(context.Background(), &jsonrpc.ExecuteResult{GroupMode: "bogus"}, interactive)
	if err == nil || !strings.Contains(err.Error(), "unsupported plugin groupMode") {
		t.Fatalf("want unsupported groupMode error, got %v", err)
	}
}

// A plugin result that carries the retired top-level localSigners, here with
// the secret key of the account whose transaction it returns, decodes without
// it, so it is no third path past the gates (PS7). The transaction takes the
// default flow: it goes to the signer, which holds no aplane key for the
// account and refuses it. The secret is sent nowhere, nothing is signed, and
// nothing reaches the node's submit endpoint.
func TestSubmitPluginTransactionsIgnoresRetiredLocalSigners(t *testing.T) {
	account := crypto.GenerateAccount()
	sender := account.Address.String()
	secret := base64.StdEncoding.EncodeToString(account.PrivateKey)
	genesis, err := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	txn, err := transaction.MakePaymentTxn(sender, sender, 0, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 100, LastRoundValid: 1100, GenesisHash: genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	wire := fmt.Sprintf(`{"success":true,"transactions":[{"type":"raw","encoded":%q}],"localSigners":[{"address":%q,"secretKey":%q}]}`,
		base64.StdEncoding.EncodeToString(msgpack.Encode(txn)), sender, secret)
	var result jsonrpc.ExecuteResult
	if err := json.Unmarshal([]byte(wire), &result); err != nil {
		t.Fatalf("decode the plugin result: %v", err)
	}

	var mu sync.Mutex
	var sent []string // every request to the signer and the node, path and body
	var signRequests, submits atomic.Int32
	record := func(r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, r.Method+" "+r.URL.Path+" "+string(body))
	}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{})
		case r.Method == http.MethodPost && r.URL.Path == "/sign":
			signRequests.Add(1)
			// The signer's answer for an account it holds no aplane key for.
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(signerapi.ErrorResponse{
				Error: "transaction 1: no key found for address: " + sender, Code: signerapi.ErrCodeBadRequest,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(signer.Close)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 100,
				GenesisId: "testnet-v1.0", GenesisHash: genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			_ = json.NewEncoder(w).Encode(models.Account{Address: strings.TrimPrefix(r.URL.Path, "/v2/accounts/"), Amount: 10_000_000, Status: "Offline"})
		case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions":
			submits.Add(1)
			http.Error(w, "must not be submitted", http.StatusInternalServerError)
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

	err = checkAndSubmit(context.Background(), app, &result, nil)
	if err == nil || !strings.Contains(err.Error(), "no key found for address: "+sender) {
		t.Fatalf("error = %v, want the signer's refusal of an account it holds no key for", err)
	}
	if signRequests.Load() != 1 {
		t.Fatalf("/sign requests = %d, want the transaction sent to the signer once", signRequests.Load())
	}
	if submits.Load() != 0 {
		t.Fatalf("submissions = %d, want none", submits.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for _, request := range sent {
		if strings.Contains(request, secret) {
			t.Fatalf("the plugin's secret key was sent: %s", request)
		}
	}
}

// TestSubmitPregroupedSignedRejections drives the dispatch with a nil engine.
// Every case here must reject before any signer/engine access — which both
// verifies the fail-closed rules and proves the pregrouped-signed path does not
// require a signer connection (a nil engine would panic if it did).
func TestSubmitPregroupedSignedRejections(t *testing.T) {
	app := &App{}
	ctx := context.Background()
	group := signedPluginIntents(t, rekeySubmitTestTxn(types.Address{1}, types.Address{}), rekeySubmitTestTxn(types.Address{2}, types.Address{}))

	tests := []struct {
		name    string
		result  *jsonrpc.ExecuteResult
		lsig    cmdspec.LsigArgs
		wantSub string
	}{
		{
			name: "lsig args rejected",
			result: &jsonrpc.ExecuteResult{
				GroupMode:    jsonrpc.GroupModePregroupedSigned,
				Transactions: group,
			},
			lsig:    cmdspec.LsigArgs{{Name: "k", Value: []byte("v")}},
			wantSub: `groupMode "pregrouped-signed" does not allow LogicSig arguments`,
		},
		{
			name:    "empty transactions rejected",
			result:  &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePregroupedSigned},
			wantSub: "requires transactions",
		},
		{
			name: "raw type rejected",
			result: &jsonrpc.ExecuteResult{
				GroupMode:    jsonrpc.GroupModePregroupedSigned,
				Transactions: []jsonrpc.TransactionIntent{{Type: jsonrpc.TransactionIntentRaw, Encoded: "AA=="}},
			},
			wantSub: `type "signed"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAndSubmit(ctx, app, tc.result, tc.lsig)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}

// TestSubmitPresignPlanRejections drives presign-plan input validation with a nil
// engine; every case must reject before any engine/signer access.
func TestSubmitPresignPlanRejections(t *testing.T) {
	app := &App{}
	ctx := context.Background()

	tests := []struct {
		name    string
		signers []jsonrpc.PluginSigner
		wantSub string
	}{
		{
			name:    "no pluginSigners",
			signers: nil,
			wantSub: "requires pluginSigners",
		},
		{
			name:    "unsupported kind",
			signers: []jsonrpc.PluginSigner{{Address: "A", Kind: "bogus", SignerRef: "r"}},
			wantSub: "unsupported kind",
		},
		{
			name:    "missing signerRef",
			signers: []jsonrpc.PluginSigner{{Address: "A", Kind: jsonrpc.PluginSignerKindCallback}},
			wantSub: "missing address or signerRef",
		},
		{
			name: "duplicate address",
			signers: []jsonrpc.PluginSigner{
				{Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r1"},
				{Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r2"},
			},
			wantSub: "duplicate address",
		},
		{
			name: "LogicSig and native PQ are mutually exclusive",
			signers: []jsonrpc.PluginSigner{{
				Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r",
				LsigResources: &jsonrpc.PluginLogicSigResources{ProgramBytes: 1, MaxOpcodeCost: 1},
				PQScheme:      "f1",
			}},
			wantSub: "cannot specify both pq_scheme and lsig_resources",
		},
		{
			name: "unsupported native PQ scheme",
			signers: []jsonrpc.PluginSigner{{
				Address: "A", Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "r", PQScheme: "f2",
			}},
			wantSub: `unsupported pq_scheme "f2"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &jsonrpc.ExecuteResult{GroupMode: jsonrpc.GroupModePresignPlan, PluginSigners: tc.signers}
			err := checkAndSubmit(ctx, app, result, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("want error containing %q, got %v", tc.wantSub, err)
			}
		})
	}
}
