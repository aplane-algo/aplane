// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

// Every apshell surface that signs gives LogicSig arguments to positions
// through the engine's one placement (engine/lsig_args.go) and adds no rule of
// its own: these tests drive each caller against a test signer that lists
// keys and records what /sign and /plan are sent, and check that each
// position got what its signing key declares, and that a refusal is the
// placement's own, made before anything is sent.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	argsNative   = types.Address{41}.String() // ed25519: declares nothing
	argsHTLC     = types.Address{42}.String() // generic LogicSig: preimage, optional
	argsSecret   = types.Address{43}.String() // composed LogicSig: secret, optional
	argsRequired = types.Address{44}.String() // composed LogicSig: secret, required
	argsDest     = types.Address{45}.String() // a receiver the signer holds no key for
	argsPlugin   = types.Address{46}.String() // a presign-plan slot the plugin signs
	argsRekeyed  = types.Address{47}.String() // an ed25519-less account rekeyed to argsHTLC
)

func argsTestKeys() []signerapi.KeyInfo {
	return []signerapi.KeyInfo{
		{Address: argsNative, KeyType: "ed25519"},
		{Address: argsHTLC, KeyType: "aplane.htlc.v1", IsGenericLsig: true,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", MaxSize: 64}}},
		{Address: argsSecret, KeyType: "example.falcon1024-hashlock.v1",
			SigningArgs: []signerapi.SigningArgInfo{{Name: "secret", Type: "bytes", MaxSize: 32}}},
		{Address: argsRequired, KeyType: "example.falcon1024-strict-hashlock.v1",
			SigningArgs: []signerapi.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true, MaxSize: 32}}},
	}
}

// argsFixture is an app on a test network and a test signer. The signer
// lists argsTestKeys and records each /sign and /plan request, answering
// 503: what matters is what it was sent.
type argsFixture struct {
	app   *App
	eng   *engine.Engine
	mu    sync.Mutex
	signs [][]signerapi.SignRequest
	plans [][]signerapi.SignRequest
}

func newArgsFixture(t *testing.T) *argsFixture {
	t.Helper()
	f := &argsFixture{}
	genesis, err := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			keys := argsTestKeys()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
		case r.Method == http.MethodPost && (r.URL.Path == "/sign" || r.URL.Path == "/plan"):
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode %s request: %v", r.URL.Path, err)
			}
			f.mu.Lock()
			if r.URL.Path == "/sign" {
				f.signs = append(f.signs, req.Requests)
			} else {
				f.plans = append(f.plans, req.Requests)
			}
			f.mu.Unlock()
			http.Error(w, "test signer", http.StatusServiceUnavailable)
		default:
			http.Error(w, "test signer", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(signer.Close)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 1000,
				GenesisId: "testnet-v1.0", GenesisHash: genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v2/accounts/"), "/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			account := models.Account{Address: address, Amount: 5_000_000, MinBalance: 100_000, Status: "Offline"}
			if address == argsRekeyed {
				account.AuthAddr = argsHTLC
			}
			_ = json.NewEncoder(w).Encode(account)
		default:
			http.Error(w, "test node", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	f.eng, err = engine.NewEngine("testnet", engine.WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	f.eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	if err := f.eng.PopulateSignerCache(argsTestKeys()); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	f.app = New(f.eng, config.DefaultConfig(), t.TempDir())
	return f
}

// sent returns each request entry's lsig_args, decoded, from the recorded
// /sign (or /plan) requests, in order: one list per request.
func (f *argsFixture) sent(plans bool) [][]map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	requests := f.signs
	if plans {
		requests = f.plans
	}
	out := make([][]map[string]string, len(requests))
	for i, entries := range requests {
		out[i] = make([]map[string]string, len(entries))
		for j, entry := range entries {
			if len(entry.LsigArgs) == 0 {
				continue
			}
			out[i][j] = make(map[string]string, len(entry.LsigArgs))
			for name, value := range entry.LsigArgs {
				raw, err := hex.DecodeString(value)
				if err != nil {
					raw = []byte("bad hex " + value)
				}
				out[i][j][name] = string(raw)
			}
		}
	}
	return out
}

func (f *argsFixture) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.signs) + len(f.plans)
}

func args(pairs ...string) map[string][]byte {
	out := make(map[string][]byte, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = []byte(pairs[i+1])
	}
	return out
}

func sentArgs(pairs ...string) map[string]string {
	out := make(map[string]string, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = pairs[i+1]
	}
	return out
}

// wantPlacementRefusal checks that err is the placement's refusal of names,
// unwrapped from whatever the caller added around it, and that nothing was
// sent to the signer.
func wantPlacementRefusal(t *testing.T, f *argsFixture, err error, names ...string) {
	t.Helper()
	var undeclared *engine.UndeclaredLsigArgsError
	if !errors.As(err, &undeclared) || !reflect.DeepEqual(undeclared.Names, names) {
		t.Fatalf("error = %v, want the placement's refusal of %q", err, names)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("%d request(s) went to /sign or /plan, want none", n)
	}
}

func argsTxn(t *testing.T, sender, note string) types.Transaction {
	t.Helper()
	genesis, err := base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	from, err := types.DecodeAddress(sender)
	if err != nil {
		t.Fatal(err)
	}
	txn := types.Transaction{
		Type:             types.PaymentTx,
		Header:           types.Header{Sender: from, Fee: 1000, FirstValid: 1000, LastValid: 2000, GenesisID: "testnet-v1.0", Note: []byte(note)},
		PaymentTxnFields: types.PaymentTxnFields{Receiver: from},
	}
	copy(txn.GenesisHash[:], genesis)
	return txn
}

// A single command is one submission: its position gets what its signing key
// declares, its auth address's key when it is rekeyed, and a name that key
// does not declare is refused before anything is sent: here a native key's.
func TestShellCommandPlacesLsigArgsByDeclaredName(t *testing.T) {
	f := newArgsFixture(t)
	_, err := f.app.Close(context.Background(), CloseRequest{Account: argsHTLC, CloseTo: argsDest, LsigArgs: args("preimage", "open")})
	if err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("Close() error = %v, want the test signer's refusal", err)
	}
	if got := f.sent(false); !reflect.DeepEqual(got, [][]map[string]string{{sentArgs("preimage", "open")}}) {
		t.Fatalf("sent %v, want the HTLC's preimage", got)
	}

	f = newArgsFixture(t)
	_, err = f.app.Close(context.Background(), CloseRequest{Account: argsRekeyed, CloseTo: argsDest, LsigArgs: args("preimage", "open")})
	if err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("Close(rekeyed) error = %v", err)
	}
	if got := f.sent(false); !reflect.DeepEqual(got, [][]map[string]string{{sentArgs("preimage", "open")}}) {
		t.Fatalf("sent %v, want the authorizer's preimage", got)
	}

	f = newArgsFixture(t)
	_, err = f.app.Close(context.Background(), CloseRequest{Account: argsNative, CloseTo: argsDest, LsigArgs: args("premage", "open")})
	wantPlacementRefusal(t, f, err, "premage")
}

// A set command is a submission per item. The names are checked once against
// every item's account, before anything is prepared or sent; each item then
// gets what its own key declares, and one whose key declares none gets none.
func TestSetCommandsPlaceLsigArgsByDeclaredName(t *testing.T) {
	commands := map[string]func(*App, map[string][]byte) error{
		"sweep": func(app *App, values map[string][]byte) error {
			_, err := app.Sweep(context.Background(), SweepRequest{
				AssetRef: "algo", FromRaw: []string{argsNative, argsHTLC, argsSecret}, ToRaw: argsDest, LsigArgs: values,
			})
			return err
		},
		"validate": func(app *App, values map[string][]byte) error {
			app.eng.SetCache.Sets = map[string][]string{"accounts": {argsNative, argsHTLC, argsSecret}}
			_, err := app.Validate(context.Background(), ValidateRequest{Account: "@accounts", LsigArgs: values})
			return err
		},
		"send": func(app *App, values map[string][]byte) error {
			app.eng.SetCache.Sets = map[string][]string{"accounts": {argsNative, argsHTLC, argsSecret}}
			_, err := app.ExecuteSend(context.Background(), SendRequest{
				AmountText: "0.5", AssetRef: "algo", FromRaw: []string{"@accounts"}, ToRaw: []string{argsDest}, LsigArgs: values,
			})
			return err
		},
	}
	for name, run := range commands {
		t.Run(name, func(t *testing.T) {
			f := newArgsFixture(t)
			_ = run(f.app, args("preimage", "open"))
			want := [][]map[string]string{{nil}, {sentArgs("preimage", "open")}, {nil}}
			if got := f.sent(false); !reflect.DeepEqual(got, want) {
				t.Fatalf("sent %v, want %v", got, want)
			}

			f = newArgsFixture(t)
			wantPlacementRefusal(t, f, run(f.app, args("preimage", "open", "premage", "open")), "premage")
		})
	}
}

// An atomic send is one submission, a group: each position gets what its own
// signing key declares.
func TestAtomicSendPlacesLsigArgsByDeclaredName(t *testing.T) {
	f := newArgsFixture(t)
	f.app.eng.SetCache.Sets = map[string][]string{"accounts": {argsNative, argsHTLC}}
	_, err := f.app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "0.5", AssetRef: "algo", FromRaw: []string{"@accounts"}, ToRaw: []string{argsDest}, Atomic: true,
		LsigArgs: args("preimage", "open"),
	})
	if err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("ExecuteSend(atomic) error = %v", err)
	}
	if got := f.sent(false); !reflect.DeepEqual(got, [][]map[string]string{{nil, sentArgs("preimage", "open")}}) {
		t.Fatalf("sent %v, want the preimage on the HTLC position only", got)
	}

	f = newArgsFixture(t)
	f.app.eng.SetCache.Sets = map[string][]string{"accounts": {argsNative, argsSecret}}
	_, err = f.app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "0.5", AssetRef: "algo", FromRaw: []string{"@accounts"}, ToRaw: []string{argsDest}, Atomic: true,
		LsigArgs: args("preimage", "open"),
	})
	wantPlacementRefusal(t, f, err, "preimage")
}

// A plugin's default-flow draft with two LogicSig accounts of different types
// and a native one: each position gets only its own key's arguments. A name
// none declares is refused by the check, before the review, and submission
// places the same arguments with the same placement.
func TestDefaultPluginDraftPlacesLsigArgsByDeclaredName(t *testing.T) {
	result := &jsonrpc.ExecuteResult{Transactions: rawPluginIntents(
		argsTxn(t, argsHTLC, "htlc"), argsTxn(t, argsSecret, "secret"), argsTxn(t, argsNative, "native"),
	)}
	f := newArgsFixture(t)
	err := checkAndSubmit(context.Background(), f.app, result, args("preimage", "open", "secret", "shh"))
	if err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("checkAndSubmit() error = %v", err)
	}
	want := [][]map[string]string{{sentArgs("preimage", "open"), sentArgs("secret", "shh"), nil}}
	if got := f.sent(false); !reflect.DeepEqual(got, want) {
		t.Fatalf("sent %v, want %v", got, want)
	}

	f = newArgsFixture(t)
	_, err = f.app.CheckPluginGroup(context.Background(), result, PluginCheckOptions{Interactive: true, LsigArgs: args("premage", "open")})
	wantPlacementRefusal(t, f, err, "premage")
}

// A presign-plan group: the managed slots get what their keys declare, on
// /plan, and the plugin's slots get none and declare none, so a name only a
// plugin-signed account's key would declare is refused, by the check.
func TestPresignPlanGroupPlacesLsigArgsByDeclaredName(t *testing.T) {
	presign := func(owned string, txns ...types.Transaction) *jsonrpc.ExecuteResult {
		return &jsonrpc.ExecuteResult{
			GroupMode:     jsonrpc.GroupModePresignPlan,
			Transactions:  rawPluginIntents(txns...),
			PluginSigners: []jsonrpc.PluginSigner{{Address: owned, Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
		}
	}
	f := newArgsFixture(t)
	result := presign(argsPlugin, argsTxn(t, argsPlugin, "plugin"), argsTxn(t, argsHTLC, "htlc"), argsTxn(t, argsNative, "native"))
	err := checkAndSubmit(context.Background(), f.app, result, args("preimage", "open"))
	if err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("checkAndSubmit() error = %v", err)
	}
	if got := f.sent(true); !reflect.DeepEqual(got, [][]map[string]string{{nil, sentArgs("preimage", "open"), nil}}) {
		t.Fatalf("planned %v, want the preimage on the managed HTLC slot only", got)
	}

	// The HTLC's own slot is the plugin's here: nothing apsigner signs
	// declares the preimage.
	f = newArgsFixture(t)
	result = presign(argsHTLC, argsTxn(t, argsHTLC, "htlc"), argsTxn(t, argsNative, "native"))
	_, err = f.app.CheckPluginGroup(context.Background(), result, PluginCheckOptions{Interactive: true, LsigArgs: args("preimage", "open")})
	wantPlacementRefusal(t, f, err, "preimage")
}

// A script's close() is one submission through the engine: the HTLC gets its
// preimage, and a native account's name is refused before anything is sent.
func TestScriptPlacesLsigArgsByDeclaredName(t *testing.T) {
	run := func(f *argsFixture, from, args string) error {
		_, err := f.app.Scripts.EnsureRunner(func(string) {}, nil).Run(
			`close("` + from + `", "` + argsDest + `", {lsigArgs: ` + args + `})`)
		return err
	}
	f := newArgsFixture(t)
	if err := run(f, argsHTLC, `{preimage: "text:open"}`); err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("close() error = %v", err)
	}
	if got := f.sent(false); !reflect.DeepEqual(got, [][]map[string]string{{sentArgs("preimage", "open")}}) {
		t.Fatalf("sent %v, want the HTLC's preimage", got)
	}

	f = newArgsFixture(t)
	err := run(f, argsNative, `{premage: "text:open"}`)
	// The script sees the placement's words; JavaScript carries no Go error.
	want := (&engine.UndeclaredLsigArgsError{Names: []string{"premage"}}).Error()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("close() error = %v, want %q", err, want)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("%d request(s) sent, want none", n)
	}
}

// A transaction file carries no arguments, and is placed like any other
// submission: a key that requires one is refused before anything is sent,
// and a key whose argument is optional is sent none.
func TestTransactionFilePlacesLsigArgsByDeclaredName(t *testing.T) {
	write := func(t *testing.T, txn types.Transaction) string {
		path := filepath.Join(t.TempDir(), "txn.b64")
		if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(msgpack.Encode(txn))), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	f := newArgsFixture(t)
	_, err := f.app.SignFile(context.Background(), SignFileRequest{FilePath: write(t, argsTxn(t, argsRequired, "required"))})
	if err == nil || !strings.Contains(err.Error(), "transaction 1: invalid LogicSig arguments: missing required argument: secret") {
		t.Fatalf("SignFile(required) error = %v", err)
	}
	if n := f.requestCount(); n != 0 {
		t.Fatalf("%d request(s) sent, want none", n)
	}

	f = newArgsFixture(t)
	_, err = f.app.SignFile(context.Background(), SignFileRequest{FilePath: write(t, argsTxn(t, argsHTLC, "optional"))})
	if err == nil || !strings.Contains(err.Error(), "test signer") {
		t.Fatalf("SignFile(optional) error = %v", err)
	}
	if got := f.sent(false); !reflect.DeepEqual(got, [][]map[string]string{{nil}}) {
		t.Fatalf("sent %v, want no arguments", got)
	}
}
