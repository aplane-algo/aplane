// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
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

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	pluginArgsNative = types.Address{21}.String()
	pluginArgsHTLC   = types.Address{22}.String()
	pluginArgsTo     = types.Address{23}.String()
)

// stepRuntime is a plugin runtime whose continuation step returns next.
type stepRuntime struct {
	next *jsonrpc.ExecuteResult
}

func (s *stepRuntime) SetConfig(string, string, string, string)            {}
func (s *stepRuntime) DiscoverPluginsCached() ([]*discovery.Plugin, error) { return nil, nil }
func (s *stepRuntime) FindByCommand(string) (*discovery.Plugin, error)     { return nil, nil }
func (s *stepRuntime) FindByName(string) (*discovery.Plugin, error)        { return nil, nil }
func (s *stepRuntime) ListCommands() ([]string, error)                     { return nil, nil }
func (s *stepRuntime) StopAll()                                            {}
func (s *stepRuntime) ExecuteCommand(string, string, []string, jsonrpc.Context) (*jsonrpc.ExecuteResult, error) {
	return s.next, nil
}
func (s *stepRuntime) SignTransactions(string, jsonrpc.SignTransactionsParams) (*jsonrpc.SignTransactionsResult, error) {
	return nil, nil
}

// signRequests keeps each /plan and /sign request the fake signer received.
type signRequests struct {
	mu       sync.Mutex
	requests []signerapi.GroupSignRequest
}

func (r *signRequests) recorded() []signerapi.GroupSignRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]signerapi.GroupSignRequest(nil), r.requests...)
}

// pluginArgsTestState is a REPL on a fake network whose signer holds an
// ed25519 key and an HTLC LogicSig taking a preimage. The signer records each
// /plan and /sign request and refuses it.
func pluginArgsTestState(t *testing.T, runtime apshellapp.PluginRuntime) (*REPLState, *signRequests) {
	t.Helper()
	network := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 100,
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

	recorder := &signRequests{}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/keys":
			keys := []signerapi.KeyInfo{
				{Address: pluginArgsNative, KeyType: "ed25519"},
				{Address: pluginArgsHTLC, KeyType: "aplane.htlc.v1", IsGenericLsig: true,
					LogicSigResources: &signerapi.LogicSigResourceProfile{
						Default: &signerapi.LogicSigResourceUsage{ProgramBytes: 100, ArgumentBytes: 32, MaxOpcodeCost: 100},
					},
					SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}}},
			}
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
		case "/plan", "/sign":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode %s request: %v", r.URL.Path, err)
			}
			recorder.mu.Lock()
			recorder.requests = append(recorder.requests, req)
			recorder.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(signerapi.ErrorResponse{Error: "recorded by the test"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(signer.Close)

	client, err := algod.MakeClient(network.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := engine.NewEngine("testnet", engine.WithAlgodClient(client), engine.WithCacheStore(cache.NewStore(t.TempDir())))
	if err != nil {
		t.Fatal(err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	if _, err := eng.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("RefreshKeys() error = %v", err)
	}
	eng.AuthCache = cache.NewAuthAddressCache()
	eng.AuthCache.AuthAddresses[pluginArgsNative] = ""
	eng.AuthCache.AuthAddresses[pluginArgsHTLC] = ""
	app := apshellapp.New(eng, config.DefaultConfig(), t.TempDir())
	app.Plugins = runtime
	state := &REPLState{
		Out: &bytes.Buffer{}, App: app,
		LineReader: func() (string, error) {
			t.Fatal("the review prompt was reached")
			return "", nil
		},
	}
	return state, recorder
}

func pluginPaymentIntent(t *testing.T, from string) jsonrpc.TransactionIntent {
	t.Helper()
	sender, err := types.DecodeAddress(from)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := types.DecodeAddress(pluginArgsTo)
	if err != nil {
		t.Fatal(err)
	}
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: sender, Fee: 1000, FirstValid: 100, LastValid: 1100, GenesisID: "testnet-v1.0"},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: receiver, Amount: 1},
	}
	return jsonrpc.TransactionIntent{Type: jsonrpc.TransactionIntentRaw, Encoded: base64.StdEncoding.EncodeToString(msgpack.Encode(txn))}
}

var testPlugin = &discovery.Plugin{Manifest: &manifest.Manifest{Name: "test-plugin"}}

// A plugin whose first step returns no transactions gives the arg: values to
// the step that does, not to no step at all.
func TestPluginLsigArgsGoToTheFirstStepWithTransactions(t *testing.T) {
	runtime := &stepRuntime{next: &jsonrpc.ExecuteResult{Success: true, Transactions: []jsonrpc.TransactionIntent{
		pluginPaymentIntent(t, pluginArgsNative), pluginPaymentIntent(t, pluginArgsHTLC),
	}}}
	state, recorder := pluginArgsTestState(t, runtime)
	state.AutoConfirm = true
	first := &jsonrpc.ExecuteResult{Success: true, Continuation: &jsonrpc.Continuation{Command: "step2"}}
	err := processPluginResultStructured(state, &PluginResult{}, first, map[string][]byte{"preimage": []byte("open")}, testPlugin)
	if err == nil || !strings.Contains(err.Error(), "recorded by the test") {
		t.Fatalf("error = %v, want the second step sent to the signer", err)
	}
	requests := recorder.recorded()
	if len(requests) != 1 || len(requests[0].Requests) != 2 {
		t.Fatalf("signer requests = %+v, want one /sign of the second step", requests)
	}
	for _, position := range requests[0].Requests {
		want := ""
		if position.TxnSender == pluginArgsHTLC {
			want = hex.EncodeToString([]byte("open"))
		}
		if position.LsigArgs["preimage"] != want || (want == "" && len(position.LsigArgs) != 0) {
			t.Fatalf("%s carried %v, want preimage %q", position.TxnSender, position.LsigArgs, want)
		}
	}
}

// arg: values for a plugin command none of whose steps returns transactions
// are said to have gone nowhere.
func TestPluginLsigArgsWithNoTransactionsAreReportedNotSent(t *testing.T) {
	state, _ := pluginArgsTestState(t, &stepRuntime{})
	result := &jsonrpc.ExecuteResult{Success: true, Message: "done"}
	err := processPluginResultStructured(state, &PluginResult{}, result, map[string][]byte{"preimage": []byte("open")}, testPlugin)
	if want := "arg:preimage: the plugin returned no transactions for APlane to sign, so it was not sent"; err == nil || err.Error() != want {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if err := processPluginResultStructured(state, &PluginResult{}, result, nil, testPlugin); err != nil {
		t.Fatalf("error = %v, want none without arg: values", err)
	}
}

// An arg: name the group would not send is refused before the user is asked
// to review the group, and nothing is sent to the signer.
func TestPluginLsigArgsTheGroupWouldNotSendAreRefusedBeforeReview(t *testing.T) {
	for name, tc := range map[string]struct {
		result *jsonrpc.ExecuteResult
		want   string
	}{
		"a mistyped name": {
			&jsonrpc.ExecuteResult{Success: true, RequiresApproval: true, Transactions: []jsonrpc.TransactionIntent{pluginPaymentIntent(t, pluginArgsHTLC)}},
			"arg:preimge: no transaction here is signed by a key that declares this LogicSig argument",
		},
		"a pregrouped-signed group": {
			&jsonrpc.ExecuteResult{Success: true, GroupMode: jsonrpc.GroupModePregroupedSigned, Transactions: []jsonrpc.TransactionIntent{{Type: jsonrpc.TransactionIntentSigned, Encoded: "AA=="}}},
			`groupMode "pregrouped-signed" does not allow lsig args`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			state, recorder := pluginArgsTestState(t, &stepRuntime{})
			err := processPluginResultStructured(state, &PluginResult{}, tc.result, map[string][]byte{"preimge": []byte("typo")}, testPlugin)
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if requests := recorder.recorded(); len(requests) != 0 {
				t.Fatalf("signer requests = %+v, want none", requests)
			}
		})
	}
}
