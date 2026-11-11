// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/aplane-algo/aplane/internal/jsapi"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	argsNative = types.Address{11}.String()
	argsHTLC   = types.Address{12}.String()
	argsPlugin = types.Address{13}.String()
	argsTo     = types.Address{14}.String()
	// argsLsigToNative is a LogicSig whose own template requires "secret",
	// rekeyed to argsNative.
	argsLsigToNative = types.Address{15}.String()
	// argsBoundedToHTLC is a bounded account whose own runtime argument is
	// "x", rekeyed to argsHTLC.
	argsBoundedToHTLC = types.Address{16}.String()
	// argsBroken is an account the fake network cannot look up.
	argsBroken = types.Address{17}.String()
)

// lsigArgsTestKeys is the fake signer's key list.
func lsigArgsTestKeys() signerapi.KeysResponse {
	profile := &signerapi.LogicSigResourceProfile{
		Default: &signerapi.LogicSigResourceUsage{ProgramBytes: 100, ArgumentBytes: 32, MaxOpcodeCost: 100},
	}
	keys := []signerapi.KeyInfo{
		{Address: argsNative, KeyType: "ed25519"},
		{Address: argsHTLC, KeyType: "aplane.htlc.v1", IsGenericLsig: true, LogicSigResources: profile,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true}}},
		{Address: argsLsigToNative, KeyType: "aplane.htlc.v1", IsGenericLsig: true, LogicSigResources: profile,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true}}},
		{Address: argsBoundedToHTLC, KeyType: "example.bounded-hashlock.v1",
			BoundedAuthorization: &signerapi.BoundedAuthorizationInfo{
				Contract:    signerapi.BoundedContractPlain1,
				RuntimeArgs: []signerapi.RuntimeArgInfo{{Name: "x", Type: "bytes"}},
			}},
	}
	return signerapi.KeysResponse{Count: len(keys), Keys: keys}
}

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
// key, an HTLC LogicSig taking a preimage, and two accounts rekeyed to them
// (lsigArgsTestKeys). The signer records each /plan and /sign request and
// refuses it, so a test sees what LogicSig arguments every position would
// have carried.
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
		case r.URL.Path == "/v2/accounts/"+argsBroken:
			http.Error(w, "lookup failed", http.StatusInternalServerError)
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
		if r.URL.Path == "/keys" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(lsigArgsTestKeys())
			return
		}
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
	if _, err := eng.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("RefreshKeys() error = %v", err)
	}
	eng.AuthCache = cache.NewAuthAddressCache()
	eng.AuthCache.AuthAddresses[argsNative] = ""
	eng.AuthCache.AuthAddresses[argsHTLC] = ""
	eng.AuthCache.AuthAddresses[argsLsigToNative] = argsNative
	eng.AuthCache.AuthAddresses[argsBoundedToHTLC] = argsHTLC
	eng.SetCache.Sets = map[string][]string{
		"mixed":          {argsNative, argsHTLC},
		"rekeyedlsig":    {argsLsigToNative, argsHTLC},
		"rekeyedbounded": {argsBoundedToHTLC, argsNative},
		"withbroken":     {argsBroken, argsHTLC},
	}
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

// requireUndeclared checks that err is the engine's refusal of exactly these
// argument names.
func requireUndeclared(t *testing.T, err error, names ...string) {
	t.Helper()
	var undeclared *engine.UndeclaredLsigArgsError
	if !errors.As(err, &undeclared) || strings.Join(undeclared.Names, ",") != strings.Join(names, ",") {
		t.Fatalf("error = %v, want the names %v refused as declared by no key", err, names)
	}
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
	requireUndeclared(t, err, "preimge")
	if paths, _ := recorder.recorded(); len(paths) != 0 {
		t.Fatalf("signer requests = %v, want none", paths)
	}
}

// The shell words the refusal as the arg: tokens that were typed, a script
// as the keys of its lsigArgs option; neither sees the other's syntax.
func TestUndeclaredLsigArgsAreWordedInTheCallersTerms(t *testing.T) {
	refusal := &engine.UndeclaredLsigArgsError{Names: []string{"other", "preimge"}}
	shell := ShellLsigArgsError(refusal)
	if want := "arg:other, arg:preimge: no transaction here is signed by a key that declares this LogicSig argument, so it would not be sent; check the name, or run keys refresh if the key is new"; shell.Error() != want {
		t.Fatalf("shell wording = %q, want %q", shell, want)
	}
	script := scriptLsigArgsError(refusal)
	if want := `lsigArgs "other", "preimge": no account here is signed by a key that declares this LogicSig argument, so it would not be sent; check the name`; script.Error() != want {
		t.Fatalf("script wording = %q, want %q", script, want)
	}
	for _, worded := range []error{shell, script} {
		requireUndeclared(t, worded, "other", "preimge")
	}
	// When an account's key could not be looked up, the refusal says so, and
	// that a retry may differ.
	unresolved := &engine.UndeclaredLsigArgsError{Names: []string{"preimge"}, Unresolved: 1}
	if want := "arg:preimge: none of the keys that could be looked up declares this LogicSig argument, so it would not be sent; 1 account could not be looked up, and a retry may differ; check the name"; ShellLsigArgsError(unresolved).Error() != want {
		t.Fatalf("shell wording = %q, want %q", ShellLsigArgsError(unresolved), want)
	}
	if want := `lsigArgs "preimge": none of the keys that could be looked up declares this LogicSig argument, so it would not be sent; 1 account could not be looked up, and a retry may differ; check the name`; scriptLsigArgsError(unresolved).Error() != want {
		t.Fatalf("script wording = %q, want %q", scriptLsigArgsError(unresolved), want)
	}
	other := errors.New("other failure")
	if ShellLsigArgsError(other) != other || scriptLsigArgsError(other) != other || ShellLsigArgsError(nil) != nil {
		t.Fatal("an error that is not the refusal must pass through unchanged")
	}

	// sweep() is the shell's sweep workflow, and a script sees its own terms.
	app, _ := lsigArgsTestApp(t)
	_, err := jsSweeper{app: app}.Sweep(context.Background(), jsapi.SweepRequest{
		From: []string{argsHTLC}, To: argsTo, LsigArgs: map[string][]byte{"preimge": []byte("typo")},
	})
	if err == nil || !strings.HasPrefix(err.Error(), `lsigArgs "preimge": `) || strings.Contains(err.Error(), "arg:") || strings.Contains(err.Error(), "keys refresh") {
		t.Fatalf("sweep() error = %v, want the refusal in a script's terms", err)
	}
}

// requireOneRequestPerSender checks that each account of a set command was
// signed on its own and carried only the arguments its key declares.
func requireOneRequestPerSender(t *testing.T, recorder *signRecorder, want map[string]string) {
	t.Helper()
	paths, requests := recorder.recorded()
	if len(requests) != 2 {
		t.Fatalf("signer requests = %v, want one /sign per account", paths)
	}
	senders := map[string]bool{}
	for _, req := range requests {
		if len(req.Requests) != 1 {
			t.Fatalf("request has %d positions, want 1", len(req.Requests))
		}
		senders[req.Requests[0].TxnSender] = true
		requireArgsByPosition(t, req, want)
	}
	if !senders[argsNative] || !senders[argsHTLC] {
		t.Fatalf("signed senders = %v, want both accounts", senders)
	}
}

// Over a set, each account gets the arguments its key declares: the native
// account in the set is sent none, the LogicSig its preimage.
func TestSendFromASetGivesEachAccountTheArgumentsItsKeyDeclares(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	_, _ = app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "0.1", AssetRef: "algo", FromRaw: []string{"@mixed"}, ToRaw: []string{argsTo},
		LsigArgs: map[string][]byte{"preimage": []byte("open")},
	})
	requireOneRequestPerSender(t, recorder, map[string]string{argsHTLC: hex.EncodeToString([]byte("open"))})
}

func TestSweepFromASetGivesEachAccountTheArgumentsItsKeyDeclares(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	_, _ = app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{"@mixed"}, ToRaw: argsTo,
		LsigArgs: map[string][]byte{"preimage": []byte("open")},
	})
	requireOneRequestPerSender(t, recorder, map[string]string{argsHTLC: hex.EncodeToString([]byte("open"))})
}

func TestValidateASetGivesEachAccountTheArgumentsItsKeyDeclares(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	_, _ = app.Validate(context.Background(), ValidateRequest{
		Account: "@mixed", LsigArgs: map[string][]byte{"preimage": []byte("open")},
	})
	requireOneRequestPerSender(t, recorder, map[string]string{argsHTLC: hex.EncodeToString([]byte("open"))})
}

// A name no account's key declares is refused, over a set or one account:
// over one account, a native key's or a typo for the LogicSig's.
func TestSendSweepValidateRefuseANameNoAccountDeclares(t *testing.T) {
	for _, tc := range []struct {
		account string
		args    map[string][]byte
		refused string
	}{
		{"@mixed", map[string][]byte{"preimge": []byte("typo")}, "preimge"},
		{argsNative, map[string][]byte{"preimage": []byte("open")}, "preimage"},
		{argsHTLC, map[string][]byte{"preimage": []byte("open"), "preimge": []byte("typo")}, "preimge"},
	} {
		for name, run := range map[string]func(*App) error{
			"send": func(app *App) error {
				_, err := app.ExecuteSend(context.Background(), SendRequest{
					AmountText: "0.1", AssetRef: "algo", FromRaw: []string{tc.account}, ToRaw: []string{argsTo}, LsigArgs: tc.args,
				})
				return err
			},
			"sweep": func(app *App) error {
				_, err := app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", FromRaw: []string{tc.account}, ToRaw: argsTo, LsigArgs: tc.args})
				return err
			},
			"validate": func(app *App) error {
				_, err := app.Validate(context.Background(), ValidateRequest{Account: tc.account, LsigArgs: tc.args})
				return err
			},
		} {
			t.Run(name+" from "+tc.account, func(t *testing.T) {
				app, recorder := lsigArgsTestApp(t)
				requireUndeclared(t, run(app), tc.refused)
				if paths, _ := recorder.recorded(); len(paths) != 0 {
					t.Fatalf("signer requests = %v, want none", paths)
				}
			})
		}
	}
}

// A sweep whose source list also names the destination sweeps the same
// accounts as one that leaves it out, and is refused the same way.
func TestSweepNamingTheDestinationAmongTheSourcesIsRefusedTheSameWay(t *testing.T) {
	args := map[string][]byte{"preimage": []byte("open")}
	var messages []string
	for _, from := range [][]string{{argsNative}, {argsNative, argsTo}} {
		app, recorder := lsigArgsTestApp(t)
		_, err := app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", FromRaw: from, ToRaw: argsTo, LsigArgs: args})
		requireUndeclared(t, err, "preimage")
		messages = append(messages, ShellLsigArgsError(err).Error())
		if paths, _ := recorder.recorded(); len(paths) != 0 {
			t.Fatalf("sweep from %v: signer requests = %v, want none", from, paths)
		}
	}
	if messages[0] != messages[1] {
		t.Fatalf("refusals differ:\n%s\n%s", messages[0], messages[1])
	}
}

// requireSignedWith checks that the fake signer was asked to sign for sender
// with exactly these LogicSig arguments (hex), by its effective signer.
func requireSignedWith(t *testing.T, recorder *signRecorder, sender, authAddress string, want map[string]string) {
	t.Helper()
	_, requests := recorder.recorded()
	for _, req := range requests {
		for _, position := range req.Requests {
			if position.TxnSender != sender {
				continue
			}
			if position.AuthAddress != authAddress {
				t.Fatalf("%s signed by %s, want %s", sender, position.AuthAddress, authAddress)
			}
			if len(position.LsigArgs) != len(want) {
				t.Fatalf("%s carried %v, want %v", sender, position.LsigArgs, want)
			}
			for name, value := range want {
				if position.LsigArgs[name] != value {
					t.Fatalf("%s carried %v, want %v", sender, position.LsigArgs, want)
				}
			}
			return
		}
	}
	t.Fatalf("no signer request for %s", sender)
}

// Arguments are matched and checked on the key that signs: a LogicSig
// rekeyed to a native key signs with none, though its own template requires
// one, and a bounded account rekeyed to a LogicSig takes that LogicSig's
// arguments, not its own. Over one account and over a set.
func TestRekeyedAccountsTakeTheArgumentsOfTheKeyThatSigns(t *testing.T) {
	preimage := map[string][]byte{"preimage": []byte("open")}
	openHex := map[string]string{"preimage": hex.EncodeToString([]byte("open"))}
	for name, tc := range map[string]struct {
		account string
		args    map[string][]byte
		sender  string
		auth    string
		want    map[string]string
	}{
		"LogicSig rekeyed to a native key":        {argsLsigToNative, nil, argsLsigToNative, argsNative, nil},
		"LogicSig rekeyed to a native key, a set": {"@rekeyedlsig", preimage, argsLsigToNative, argsNative, nil},
		"bounded rekeyed to a LogicSig":           {argsBoundedToHTLC, preimage, argsBoundedToHTLC, argsHTLC, openHex},
		"bounded rekeyed to a LogicSig, a set":    {"@rekeyedbounded", preimage, argsBoundedToHTLC, argsHTLC, openHex},
	} {
		t.Run(name, func(t *testing.T) {
			app, recorder := lsigArgsTestApp(t)
			result, _ := app.Validate(context.Background(), ValidateRequest{Account: tc.account, LsigArgs: tc.args})
			if result == nil {
				t.Fatal("Validate() returned no result")
			}
			for _, item := range result.Items {
				if item.Address == tc.sender && strings.Contains(item.Error, "invalid LogicSig arguments") {
					t.Fatalf("%s refused before signing: %s", tc.sender, item.Error)
				}
			}
			requireSignedWith(t, recorder, tc.sender, tc.auth, tc.want)
		})
	}
}

// An account whose signing key cannot be looked up fails alone; the rest of
// a set command goes ahead, each with the arguments its key declares.
func TestSetCommandsKeepALookupFailureToItsAccount(t *testing.T) {
	preimage := map[string][]byte{"preimage": []byte("open")}
	openHex := map[string]string{"preimage": hex.EncodeToString([]byte("open"))}
	lookupFailed := "failed to refresh auth address for " + argsBroken

	t.Run("validate", func(t *testing.T) {
		app, recorder := lsigArgsTestApp(t)
		result, _ := app.Validate(context.Background(), ValidateRequest{Account: "@withbroken", LsigArgs: preimage})
		if result == nil || len(result.Items) != 2 || !strings.Contains(result.Items[0].Error, lookupFailed) {
			t.Fatalf("Validate() result = %+v, want the broken account failed on its item", result)
		}
		requireSignedWith(t, recorder, argsHTLC, argsHTLC, openHex)
	})
	t.Run("send", func(t *testing.T) {
		app, recorder := lsigArgsTestApp(t)
		result, err := app.ExecuteSend(context.Background(), SendRequest{
			AmountText: "0.1", AssetRef: "algo", FromRaw: []string{"@withbroken"}, ToRaw: []string{argsTo}, LsigArgs: preimage,
		})
		if err != nil || result.NonAtomic == nil || len(result.NonAtomic.Items) != 2 ||
			!strings.Contains(result.NonAtomic.Items[0].Error, lookupFailed) {
			t.Fatalf("ExecuteSend() = %+v, %v; want the broken account failed on its item", result, err)
		}
		requireSignedWith(t, recorder, argsHTLC, argsHTLC, openHex)
	})
	t.Run("sweep", func(t *testing.T) {
		app, recorder := lsigArgsTestApp(t)
		result, _ := app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", FromRaw: []string{"@withbroken"}, ToRaw: argsTo, LsigArgs: preimage})
		if result == nil || len(result.Items) != 2 || result.Items[0].Error == "" {
			t.Fatalf("Sweep() result = %+v, want the broken account failed on its item", result)
		}
		requireSignedWith(t, recorder, argsHTLC, argsHTLC, openHex)
	})
}

// A name no account that could be looked up declares is refused for the
// whole command, though another account's lookup failed: the accounts that go
// on would otherwise be signed without it. Nothing is signed.
func TestSetCommandsRefuseANameNoLookedUpAccountDeclares(t *testing.T) {
	typo := map[string][]byte{"preimge": []byte("typo")}
	for name, run := range map[string]func(*App) error{
		"send": func(app *App) error {
			_, err := app.ExecuteSend(context.Background(), SendRequest{
				AmountText: "0.1", AssetRef: "algo", FromRaw: []string{"@withbroken"}, ToRaw: []string{argsTo}, LsigArgs: typo,
			})
			return err
		},
		"sweep": func(app *App) error {
			_, err := app.Sweep(context.Background(), SweepRequest{AssetRef: "algo", FromRaw: []string{"@withbroken"}, ToRaw: argsTo, LsigArgs: typo})
			return err
		},
		"validate": func(app *App) error {
			_, err := app.Validate(context.Background(), ValidateRequest{Account: "@withbroken", LsigArgs: typo})
			return err
		},
		"plugin": func(app *App) error {
			result := &jsonrpc.ExecuteResult{Transactions: []jsonrpc.TransactionIntent{
				rawPaymentIntent(t, argsBroken), rawPaymentIntent(t, argsHTLC),
			}}
			_, err := app.SubmitPluginTransactions(context.Background(), "plugin", result, typo)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			app, recorder := lsigArgsTestApp(t)
			err := run(app)
			requireUndeclared(t, err, "preimge")
			var undeclared *engine.UndeclaredLsigArgsError
			if !errors.As(err, &undeclared) || undeclared.Unresolved != 1 {
				t.Fatalf("error = %#v, want 1 account not looked up", err)
			}
			if paths, _ := recorder.recorded(); len(paths) != 0 {
				t.Fatalf("signer requests = %v, want none", paths)
			}
		})
	}
}

// An app call's companion payment is from the call's own account. From a
// native account, with no arguments typed, neither position carries any.
func TestAppCallCompanionFromANativeAccountCarriesNoLsigArgs(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	if _, err := app.AppCallRaw(context.Background(), AppCallRawRequest{AppID: 123, From: argsNative, PayAmount: 1000}); err == nil {
		t.Fatal("AppCallRaw() succeeded against a signer that refuses")
	}
	paths, requests := recorder.recorded()
	if len(requests) != 1 || len(requests[0].Requests) != 2 {
		t.Fatalf("signer requests = %v, want one /sign of the payment and the call", paths)
	}
	for i, position := range requests[0].Requests {
		if len(position.LsigArgs) != 0 {
			t.Fatalf("position %d carried %v, want no LogicSig arguments", i+1, position.LsigArgs)
		}
	}
}

// From a LogicSig account, the companion payment carries the call's
// arguments, since the same program authorizes both.
func TestAppCallCompanionFromALogicSigCarriesTheCallsArgs(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	if _, err := app.AppCallRaw(context.Background(), AppCallRawRequest{
		AppID: 123, From: argsHTLC, PayAmount: 1000, LsigArgs: map[string][]byte{"preimage": []byte("open")},
	}); err == nil {
		t.Fatal("AppCallRaw() succeeded against a signer that refuses")
	}
	paths, requests := recorder.recorded()
	if len(requests) != 1 || len(requests[0].Requests) != 2 {
		t.Fatalf("signer requests = %v, want one /sign of the payment and the call", paths)
	}
	for i, position := range requests[0].Requests {
		if position.LsigArgs["preimage"] != hex.EncodeToString([]byte("open")) {
			t.Fatalf("position %d carried %v, want the preimage", i+1, position.LsigArgs)
		}
	}
}

// LogicSig arguments typed for a command whose account signs with a native
// key are refused by the client before anything is sent: the key has no
// program to pass them to. An app call checks them on the key that signs.
func TestLsigArgsForANativeAccountAreRefusedBeforeSigning(t *testing.T) {
	app, recorder := lsigArgsTestApp(t)
	_, err := app.AppCallRaw(context.Background(), AppCallRawRequest{
		AppID: 123, From: argsNative, PayAmount: 1000, LsigArgs: map[string][]byte{"preimage": []byte("open")},
	})
	if err == nil || !strings.Contains(err.Error(), "the ed25519 key of "+argsNative+" is not a LogicSig and takes no arguments") {
		t.Fatalf("error = %v, want the arguments refused", err)
	}
	if paths, _ := recorder.recorded(); len(paths) != 0 {
		t.Fatalf("signer requests = %v, want none", paths)
	}
}
