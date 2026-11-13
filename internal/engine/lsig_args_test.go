// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// A transaction gets the untargeted arguments and those for its sender, and
// nothing addressed to another account; two transactions from one sender get
// the same. The value is a copy: nothing done to the maps it was made from,
// or to a map it returned, changes it.
func TestLsigArgsGiveEachTransactionItsSendersArguments(t *testing.T) {
	alice, bob, carol := testAddress(1), testAddress(2), testAddress(3)
	untargeted := map[string][]byte{"shared": []byte("s")}
	bySender := map[string]map[string][]byte{
		alice.String(): {"preimage": []byte("a")},
		bob.String():   {"preimage": []byte("b"), "secret": []byte("c")},
		carol.String(): {},
	}
	args := NewLsigArgs(untargeted, bySender)
	untargeted["shared"][0] = 'X'
	bySender[alice.String()]["preimage"] = []byte("changed")

	txn := func(sender types.Address) types.Transaction {
		return types.Transaction{Type: types.PaymentTx, Header: types.Header{Sender: sender}}
	}
	got := args.place([]types.Transaction{txn(alice), txn(bob), txn(carol), txn(alice)})
	str := func(m map[string][]byte) map[string]string {
		out := make(map[string]string, len(m))
		for name, value := range m {
			out[name] = string(value)
		}
		return out
	}
	want := []map[string]string{
		{"shared": "s", "preimage": "a"},
		{"shared": "s", "preimage": "b", "secret": "c"},
		{"shared": "s"},
		{"shared": "s", "preimage": "a"},
	}
	if len(got) != len(want) {
		t.Fatalf("placed %d positions, want %d", len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(str(got[i]), want[i]) {
			t.Fatalf("position %d = %v, want %v", i, str(got[i]), want[i])
		}
	}
	got[0]["preimage"][0] = 'Z'
	if again := args.For(alice.String()); string(again["preimage"]) != "a" {
		t.Fatalf("a placed map reached the value: %q", again["preimage"])
	}

	if placed := (LsigArgs{}).place([]types.Transaction{txn(alice)}); placed != nil {
		t.Fatalf("no arguments placed as %v, want nil", placed)
	}
	if !NewLsigArgs(nil, map[string]map[string][]byte{alice.String(): {}}).Empty() {
		t.Fatal("arguments made of empty maps are not empty")
	}
	only := UntargetedLsigArgs(map[string][]byte{"preimage": []byte("p")}).place([]types.Transaction{txn(alice), txn(bob)})
	if string(only[0]["preimage"]) != "p" || string(only[1]["preimage"]) != "p" {
		t.Fatalf("untargeted arguments placed as %v, want every position", only)
	}
	if named := NewLsigArgs(nil, map[string]map[string][]byte{bob.String(): {"x": {1}}}).place([]types.Transaction{txn(alice), txn(bob)}); named[0] != nil || named[1]["x"] == nil {
		t.Fatalf("bob's argument placed as %v, want bob's position only", named)
	}
}

// lsigArgsEngine is an engine on testnet connected to a test signer that
// lists keys and records each /sign and /plan request, answering 503, and to
// a test node that answers suggested parameters and accounts, each rekeyed
// as authAddrs says.
type lsigArgsEngine struct {
	eng         *Engine
	genesis     []byte
	mu          sync.Mutex
	signs       [][]signerapi.SignRequest
	plans       [][]signerapi.SignRequest
	signerCalls atomic.Int32
}

func newLsigArgsEngine(t *testing.T, keys []signerapi.KeyInfo, authAddrs map[string]string) *lsigArgsEngine {
	t.Helper()
	f := &lsigArgsEngine{}
	var err error
	if f.genesis, err = base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash); err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.signerCalls.Add(1)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
			return
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
		}
		http.Error(w, "test signer", http.StatusServiceUnavailable)
	}))
	t.Cleanup(signer.Close)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 1000,
				GenesisId: "testnet-v1.0", GenesisHash: f.genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			_ = json.NewEncoder(w).Encode(models.Account{
				Address: address, Amount: 5_000_000, MinBalance: 100_000, Status: "Offline", AuthAddr: authAddrs[address],
			})
		default:
			http.Error(w, "test node", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	f.eng, err = NewEngine("testnet", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	f.eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	return f
}

// recorded returns copies of the recorded /sign and /plan requests.
func (f *lsigArgsEngine) recorded() (signs, plans [][]signerapi.SignRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]signerapi.SignRequest(nil), f.signs...), append([][]signerapi.SignRequest(nil), f.plans...)
}

func (f *lsigArgsEngine) payment(t *testing.T, sender types.Address) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(sender.String(), sender.String(), 0, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 2000, GenesisHash: f.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	return txn
}

func signsOf(f *lsigArgsEngine) [][]signerapi.SignRequest { signs, _ := f.recorded(); return signs }
func plansOf(f *lsigArgsEngine) [][]signerapi.SignRequest { _, plans := f.recorded(); return plans }

// sentArgs is the lsig_args of each entry of each recorded request, decoded.
func sentArgs(t *testing.T, requests [][]signerapi.SignRequest) [][]map[string]string {
	t.Helper()
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
					t.Fatalf("request %d entry %d: lsig_args[%q] is not hex: %v", i, j, name, err)
				}
				out[i][j][name] = string(raw)
			}
		}
	}
	return out
}

// The client's check of required arguments and declared lengths reads the
// key that signs for the sender, after the auth address and the key list are
// refreshed: an account rekeyed to a LogicSig key is checked against that
// key's arguments, and a LogicSig account rekeyed to a native key is not
// refused for its own key's required argument. A key the cache describes no
// arguments for passes, and the signer judges.
func TestSubmitChecksLsigArgsAgainstTheEffectiveSigner(t *testing.T) {
	rekeyedToLsig, hashlock := testAddress(11), testAddress(12)
	lsigRekeyedAway, native := testAddress(13), testAddress(14)
	keys := []signerapi.KeyInfo{
		{Address: hashlock.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", Required: true, MaxSize: 64}}},
		{Address: lsigRekeyedAway.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "secret", Type: "bytes", Required: true, ByteLength: 4}}},
		{Address: native.String(), KeyType: "ed25519"},
	}
	authAddrs := map[string]string{rekeyedToLsig.String(): hashlock.String(), lsigRekeyedAway.String(): native.String()}

	t.Run("rekeyed to a LogicSig key, its required argument missing", func(t *testing.T) {
		f := newLsigArgsEngine(t, keys, authAddrs)
		prep := &TransactionPrepResult{Transaction: f.payment(t, rekeyedToLsig)}
		_, err := f.eng.SignAndSubmit(context.Background(), prep, LsigArgs{}, false)
		if err == nil || !strings.Contains(err.Error(), "transaction 1: invalid LogicSig arguments: missing required argument: preimage") {
			t.Fatalf("SignAndSubmit() error = %v, want the authorizer's required preimage missing", err)
		}
		if len(signsOf(f)) != 0 {
			t.Fatalf("/sign was called %d time(s), want none", len(signsOf(f)))
		}
	})
	t.Run("rekeyed to a LogicSig key, its argument given", func(t *testing.T) {
		f := newLsigArgsEngine(t, keys, authAddrs)
		prep := &TransactionPrepResult{Transaction: f.payment(t, rekeyedToLsig)}
		args := NewLsigArgs(nil, map[string]map[string][]byte{rekeyedToLsig.String(): {"preimage": []byte("open")}})
		_, err := f.eng.SignAndSubmit(context.Background(), prep, args, false)
		if err == nil || strings.Contains(err.Error(), "invalid LogicSig arguments") {
			t.Fatalf("SignAndSubmit() error = %v, want the client check passed and the test signer's refusal", err)
		}
		if got := sentArgs(t, signsOf(f)); len(got) != 1 || !reflect.DeepEqual(got[0], []map[string]string{{"preimage": "open"}}) {
			t.Fatalf("/sign lsig_args = %v, want preimage for the one position", got)
		}
		if signsOf(f)[0][0].AuthAddress != hashlock.String() {
			t.Fatalf("/sign auth address = %s, want the authorizer %s", signsOf(f)[0][0].AuthAddress, hashlock)
		}
	})
	t.Run("a LogicSig account rekeyed to a native key", func(t *testing.T) {
		f := newLsigArgsEngine(t, keys, authAddrs)
		prep := &TransactionPrepResult{Transaction: f.payment(t, lsigRekeyedAway)}
		_, err := f.eng.SignAndSubmit(context.Background(), prep, LsigArgs{}, false)
		if err == nil || strings.Contains(err.Error(), "invalid LogicSig arguments") {
			t.Fatalf("SignAndSubmit() error = %v, want no refusal for the account's own key's argument", err)
		}
		if len(signsOf(f)) != 1 {
			t.Fatalf("/sign was called %d time(s), want once", len(signsOf(f)))
		}
	})
	t.Run("a declared length is checked against the effective signer", func(t *testing.T) {
		f := newLsigArgsEngine(t, keys, nil)
		prep := &TransactionPrepResult{Transaction: f.payment(t, lsigRekeyedAway)}
		args := UntargetedLsigArgs(map[string][]byte{"secret": []byte("toolong")})
		_, err := f.eng.SignAndSubmit(context.Background(), prep, args, false)
		if err == nil || !strings.Contains(err.Error(), "argument 'secret': expected 4 bytes, got 7") {
			t.Fatalf("SignAndSubmit() error = %v, want the declared length refused", err)
		}
		if len(signsOf(f)) != 0 {
			t.Fatalf("/sign was called %d time(s), want none", len(signsOf(f)))
		}
	})
}

// A presign-plan position the plugin signs is sent to the plugin with no
// arguments, so an argument that reaches one, addressed to its sender or
// untargeted, is refused before anything is sent: no /plan, no plugin
// signing, no algod read. An argument addressed to a managed position goes
// to it alone.
func TestSignAndSubmitWithPluginSignersRefusesArgumentsForAPluginSignedPosition(t *testing.T) {
	plugin, managed := testAddress(21), testAddress(22)
	keys := []signerapi.KeyInfo{{Address: managed.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true,
		SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", MaxSize: 64}}}}
	refs := map[string]string{plugin.String(): "plugin-ref"}
	preimage := map[string][]byte{"preimage": []byte("open")}

	for name, args := range map[string]LsigArgs{
		"addressed to the plugin's sender": NewLsigArgs(nil, map[string]map[string][]byte{plugin.String(): preimage}),
		"untargeted":                       UntargetedLsigArgs(preimage),
	} {
		t.Run(name, func(t *testing.T) {
			f := newLsigArgsEngine(t, keys, nil)
			var pluginCalls atomic.Int32
			_, err := f.eng.SignAndSubmitWithPluginSigners(context.Background(),
				[]types.Transaction{f.payment(t, managed), f.payment(t, plugin)}, refs, nil,
				func([]PluginSlotSignRequest) ([]PluginSlotSigned, error) {
					pluginCalls.Add(1)
					return nil, errors.New("not reached")
				}, args)
			want := "transaction 2: LogicSig arguments reach " + plugin.String() + ", which the plugin signs"
			if err == nil || !strings.HasPrefix(err.Error(), want) {
				t.Fatalf("SignAndSubmitWithPluginSigners() error = %v, want %q", err, want)
			}
			if got := f.signerCalls.Load(); got != 0 {
				t.Fatalf("signer calls = %d, want 0", got)
			}
			if pluginCalls.Load() != 0 {
				t.Fatal("the plugin was asked to sign")
			}
		})
	}

	f := newLsigArgsEngine(t, keys, nil)
	args := NewLsigArgs(nil, map[string]map[string][]byte{managed.String(): preimage})
	_, err := f.eng.SignAndSubmitWithPluginSigners(context.Background(),
		[]types.Transaction{f.payment(t, managed), f.payment(t, plugin)}, refs, nil,
		func([]PluginSlotSignRequest) ([]PluginSlotSigned, error) { return nil, errors.New("not reached") }, args)
	if err == nil || strings.Contains(err.Error(), "LogicSig arguments reach") {
		t.Fatalf("SignAndSubmitWithPluginSigners() error = %v, want the test signer's /plan refusal", err)
	}
	if got := sentArgs(t, plansOf(f)); len(got) != 1 || !reflect.DeepEqual(got[0], []map[string]string{{"preimage": "open"}, nil}) {
		t.Fatalf("/plan lsig_args = %v, want preimage at the managed position only", got)
	}
}
