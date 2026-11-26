// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

// A command's arg: words are resolved once (resolveLsigArgs) and placed by
// the engine by sender: a transaction gets the untargeted words and those
// whose target is its sender. These tests drive each command against a test
// signer that lists keys and records what /sign and /plan are sent, and check
// what each position got, and that a refusal comes before anything is sent.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

var (
	argsNative = types.Address{41}.String() // ed25519: takes no arguments
	argsHTLC   = types.Address{42}.String() // generic LogicSig: preimage
	argsHTLC2  = types.Address{43}.String() // another of the same type
	argsSecret = types.Address{44}.String() // generic LogicSig: secret
	argsPlugin = types.Address{46}.String() // a presign-plan slot the plugin signs
	argsDest   = types.Address{47}.String() // a receiver the signer holds no key for
	argsFalcon = types.Address{48}.String() // native Falcon: takes no arguments
	// argsRekeyed is an ed25519 key rekeyed to argsFalcon on the test node.
	argsRekeyed = types.Address{49}.String()
	// argsRotating is a rotating account rekeyed to argsStage on the test
	// node, a stage the signer never lists.
	argsRotating = types.Address{50}.String()
	argsStage    = types.Address{51}.String()
)

func argsTestKeys() []signerapi.KeyInfo {
	htlc := func(address string) signerapi.KeyInfo {
		return signerapi.KeyInfo{Address: address, KeyType: "aplane.htlc.v1", AuthorizationKind: "logic_sig", IsGenericLsig: true,
			SigningArgs: []signerapi.RuntimeArgInfo{{Name: "preimage", Type: "bytes", MaxSize: 64}}}
	}
	return []signerapi.KeyInfo{
		{Address: argsNative, KeyType: "ed25519", AuthorizationKind: "ed25519"},
		{Address: argsFalcon, KeyType: "falcon1024", AuthorizationKind: "native_pq"},
		{Address: argsRekeyed, KeyType: "ed25519", AuthorizationKind: "ed25519"},
		{Address: argsRotating, KeyType: rotatingkey.RotatingTripleXmssV1, AuthorizationKind: "logic_sig", SigningFlow: signerapi.SigningFlowRotating1,
			LogicSigResources: &signerapi.LogicSigResourceProfile{Default: &signerapi.LogicSigResourceUsage{
				ProgramBytes: 4_500, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000}}},
		htlc(argsHTLC), htlc(argsHTLC2),
		{Address: argsSecret, KeyType: "example.secret.v1", AuthorizationKind: "logic_sig", IsGenericLsig: true,
			SigningArgs: []signerapi.RuntimeArgInfo{{Name: "secret", Type: "bytes", MaxSize: 32}}},
	}
}

// argsFixture is an app on testnet with a test signer that lists
// argsTestKeys and records each /sign and /plan request, answering 503, and a
// test node with every account funded and offline, suggesting perByteFee
// (zero unless set: the minimum fee). Aliases: hl and hashlock both name
// argsHTLC, hl2 argsHTLC2, sec argsSecret, nat argsNative; the set lsigs is
// hl and hl2.
type argsFixture struct {
	app         *App
	eng         *engine.Engine
	genesis     []byte
	mu          sync.Mutex
	signs       [][]signerapi.SignRequest
	batches     []*signerapi.SignBatch
	plans       [][]signerapi.SignRequest
	signerPosts atomic.Int32
	perByteFee  atomic.Uint64
	// unfunded is an account the node reports with no balance, so a send
	// from it fails its preflight check.
	unfunded string
	// holdings are the assets the node reports an account opted into.
	holdings map[string][]models.AssetHolding
	// assets are the assets the node describes; it fails to look up others.
	assets map[uint64]models.AssetParams
	// unreachable is an account the node fails to look up.
	unreachable string
	// signs makes the signer answer /sign for these senders with each
	// transaction wrapped as signed, and the node accept what is submitted.
	// Any other sender's request is still answered 503.
	signsFor map[string]bool
	// submitted counts the transactions the node accepted.
	submitted atomic.Int32
	// rejectsSubmit makes the node refuse what is submitted.
	rejectsSubmit bool
	// confirms makes the node report every pending transaction confirmed,
	// having created no app.
	confirms bool
}

func newArgsFixture(t *testing.T) *argsFixture {
	t.Helper()
	f := &argsFixture{}
	var err error
	if f.genesis, err = base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash); err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			keys := argsTestKeys()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Keys: keys})
			return
		case r.Method == http.MethodPost:
			f.signerPosts.Add(1)
			if r.URL.Path == "/sign" || r.URL.Path == "/plan" {
				var req signerapi.GroupSignRequest
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Errorf("decode %s request: %v", r.URL.Path, err)
				}
				f.mu.Lock()
				if r.URL.Path == "/sign" {
					f.signs = append(f.signs, req.Requests)
					f.batches = append(f.batches, req.Batch)
				} else {
					f.plans = append(f.plans, req.Requests)
				}
				signsFor := f.signsFor
				f.mu.Unlock()
				if signed, ok := signAsTestSigner(t, req.Requests, signsFor); ok && r.URL.Path == "/sign" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed})
					return
				}
			}
		}
		http.Error(w, "test signer", http.StatusServiceUnavailable)
	}))
	t.Cleanup(signer.Close)
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/transactions/params":
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV43), Fee: f.perByteFee.Load(), MinFee: 1000, LastRound: 1000,
				GenesisId: "testnet-v1.0", GenesisHash: f.genesis,
			})
		case strings.HasPrefix(r.URL.Path, "/v2/accounts/") && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v2/accounts/"), "/"):
			address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
			account := models.Account{Address: address, Amount: 5_000_000, MinBalance: 100_000, Status: "Offline"}
			f.mu.Lock()
			if address == f.unfunded {
				account.Amount = 0
			}
			account.Assets = f.holdings[address]
			unreachable := address == f.unreachable
			f.mu.Unlock()
			if unreachable {
				http.Error(w, "test node cannot find the account", http.StatusServiceUnavailable)
				return
			}
			switch address {
			case argsRekeyed:
				account.AuthAddr = argsFalcon
			case argsRotating:
				account.AuthAddr = argsStage
			}
			_ = json.NewEncoder(w).Encode(account)
		case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions":
			f.mu.Lock()
			accepts, rejects := len(f.signsFor) > 0, f.rejectsSubmit
			f.mu.Unlock()
			if rejects {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "TransactionPool.Remember: overspend"})
				return
			}
			if !accepts {
				http.Error(w, "test node", http.StatusServiceUnavailable)
				return
			}
			f.submitted.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"txId": "TESTTXID"})
		case strings.HasPrefix(r.URL.Path, "/v2/assets/"):
			id, err := strconv.ParseUint(strings.TrimPrefix(r.URL.Path, "/v2/assets/"), 10, 64)
			f.mu.Lock()
			params, ok := f.assets[id]
			f.mu.Unlock()
			if err != nil || !ok {
				http.Error(w, "test node", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(models.Asset{Index: id, Params: params})
		case r.URL.Path == "/v2/status" && f.confirmsPending():
			_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 1000})
		case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/") && f.confirmsPending():
			w.Header().Set("Content-Type", "application/msgpack")
			_, _ = w.Write(msgpack.Encode(models.PendingTransactionInfoResponse{ConfirmedRound: 1001}))
		default:
			http.Error(w, "test node", http.StatusServiceUnavailable)
		}
	}))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	f.eng = engine.NewEngine("testnet", engine.WithAlgodClient(client))
	f.eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	if _, err := f.eng.RefreshKeys(context.Background()); err != nil {
		t.Fatalf("RefreshKeys() error = %v", err)
	}
	f.eng.AliasCache.Aliases = map[string]string{
		"hl": argsHTLC, "hashlock": argsHTLC, "hl2": argsHTLC2, "sec": argsSecret, "nat": argsNative, "dest": argsDest,
	}
	f.eng.SetCache.Sets = map[string][]string{"lsigs": {argsHTLC, argsHTLC2}}
	f.app = New(f.eng, config.DefaultConfig(), t.TempDir())
	return f
}

func (f *argsFixture) confirmsPending() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.confirms
}

// signAsTestSigner wraps each requested transaction as signed, when every
// one of them is sent by an account the fixture signs for.
func signAsTestSigner(t *testing.T, requests []signerapi.SignRequest, signsFor map[string]bool) ([]string, bool) {
	t.Helper()
	if len(requests) == 0 {
		return nil, false
	}
	signed := make([]string, len(requests))
	for i, request := range requests {
		txn, err := txnutil.DecodePrefixedHex(request.TxnBytesHex)
		if err != nil {
			t.Errorf("decode sign request %d: %v", i, err)
			return nil, false
		}
		if !signsFor[txn.Sender.String()] {
			return nil, false
		}
		signed[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: types.Signature{1}}))
	}
	return signed, true
}

// sent returns each request entry's lsig_args, decoded, from the recorded
// /sign (or, with plans, /plan) requests, in order: one list per request.
func (f *argsFixture) sent(t *testing.T, plans bool) [][]map[string]string {
	t.Helper()
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
					t.Fatalf("request %d entry %d: lsig_args[%q] is not hex: %v", i, j, name, err)
				}
				out[i][j][name] = string(raw)
			}
		}
	}
	return out
}

func (f *argsFixture) wantSent(t *testing.T, plans bool, want ...[]map[string]string) {
	t.Helper()
	if got := f.sent(t, plans); !reflect.DeepEqual(got, want) {
		t.Fatalf("sent lsig_args = %v, want %v", got, want)
	}
}

func (f *argsFixture) payment(t *testing.T, sender string) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(sender, argsDest, 0, nil, "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 1000, LastRoundValid: 2000, GenesisHash: f.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	return txn
}

// words parses arg: tokens as a command's parser does.
func words(t *testing.T, tokens ...string) cmdspec.LsigArgs {
	t.Helper()
	var args cmdspec.LsigArgs
	for _, token := range tokens {
		if err := cmdspec.AddLsigArg(&args, token); err != nil {
			t.Fatalf("AddLsigArg(%q) error = %v", token, err)
		}
	}
	return args
}

func sentArgs(pairs ...string) map[string]string {
	out := make(map[string]string, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = pairs[i+1]
	}
	return out
}

func wantRefusedBeforeSending(t *testing.T, f *argsFixture, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
	if got := f.signerPosts.Load(); got != 0 {
		t.Fatalf("signer requests = %d, want none before the refusal", got)
	}
}

// Repeats are judged once every target is an address: a name given twice for
// one account, however it is written, or given both untargeted and for an
// account, is refused. A target that is not a sending account, an unknown
// alias and * (no alias can be *) are refused.
func TestResolveLsigArgsRefusals(t *testing.T) {
	f := newArgsFixture(t)
	senders := []string{argsHTLC, argsHTLC2}
	for _, tc := range []struct {
		name   string
		tokens []string
		want   string
	}{
		{"alias and its address", []string{"arg:hl:preimage=a", "arg:" + argsHTLC + ":preimage=b"},
			"arg:hl:preimage and arg:" + argsHTLC + ":preimage both give preimage to " + argsHTLC + "; give it once"},
		{"two aliases for one account", []string{"arg:hl:preimage=a", "arg:hashlock:preimage=b"},
			"arg:hl:preimage and arg:hashlock:preimage both give preimage to hashlock (" + argsHTLC + "); give it once"},
		{"an alias written in another case", []string{"arg:hl:preimage=a", "arg:HL:preimage=b"}, "both give preimage to"},
		{"untargeted and for an account", []string{"arg:preimage=a", "arg:hl2:preimage=b"},
			"arg:preimage and arg:hl2:preimage both give preimage to hl2 (" + argsHTLC2 + "): arg:preimage, with no account, gives it to every transaction already"},
		{"for an account and then untargeted", []string{"arg:hl2:preimage=b", "arg:preimage=a"}, "arg:preimage and arg:hl2:preimage both give preimage"},
		{"a target that sends nothing", []string{"arg:sec:secret=s"},
			"arg:sec:secret: sec (" + argsSecret + ") is not one of the accounts this command sends from"},
		{"an unknown alias", []string{"arg:hl3:preimage=a"}, "arg:hl3:preimage: 'hl3' is neither a valid Algorand address nor a known alias"},
		{"an asterisk", []string{"arg:*:preimage=a"}, "arg:*:preimage: '*' is neither a valid Algorand address nor a known alias"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.app.resolveLsigArgs(words(t, tc.tokens...), senders)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("resolveLsigArgs(%v) error = %v, want %q", tc.tokens, err, tc.want)
			}
			if strings.Contains(err.Error(), "=a") || strings.Contains(err.Error(), "=b") {
				t.Fatalf("the refusal repeats a value: %v", err)
			}
		})
	}

	args, err := f.app.resolveLsigArgs(words(t, "arg:hl:preimage=a", "arg:"+argsHTLC2+":preimage=b", "arg:shared=s"), senders)
	if err != nil {
		t.Fatalf("resolveLsigArgs() error = %v", err)
	}
	if got := args.For(argsHTLC); string(got["preimage"]) != "a" || string(got["shared"]) != "s" || len(got) != 2 {
		t.Fatalf("hl's arguments = %q", got)
	}
	if got := args.For(argsHTLC2); string(got["preimage"]) != "b" || len(got) != 2 {
		t.Fatalf("hl2's arguments = %q", got)
	}
}

// A target that is not one of the accounts a command sends from is refused
// before anything is sent: a single-account command, a set command (checked
// against the expanded set), an atomic send and a plugin group.
func TestLsigArgsTargetMustSend(t *testing.T) {
	ctx := context.Background()
	notSending := "is not one of the accounts this command sends from"

	f := newArgsFixture(t)
	_, err := f.app.Close(ctx, CloseRequest{Account: "hl", CloseTo: "dest", LsigArgs: words(t, "arg:hl2:preimage=a")})
	wantRefusedBeforeSending(t, f, err, "arg:hl2:preimage: hl2 ("+argsHTLC2+") "+notSending)

	f = newArgsFixture(t)
	_, err = f.app.Validate(ctx, ValidateRequest{Account: "@lsigs", LsigArgs: words(t, "arg:sec:secret=s")})
	wantRefusedBeforeSending(t, f, err, notSending)

	f = newArgsFixture(t)
	_, err = f.app.ExecuteSend(ctx, SendRequest{AmountText: "0", AssetRef: "algo", FromRaw: []string{"@lsigs"}, ToRaw: []string{"dest"},
		Atomic: true, Wait: true, LsigArgs: words(t, "arg:dest:preimage=a")})
	wantRefusedBeforeSending(t, f, err, "arg:dest:preimage: dest ("+argsDest+") "+notSending)

	f = newArgsFixture(t)
	_, err = f.app.CheckPluginGroup(ctx, &jsonrpc.ExecuteResult{Transactions: rawPluginIntents(f.payment(t, argsHTLC))},
		PluginCheckOptions{Interactive: true, LsigArgs: words(t, "arg:sec:secret=s")})
	wantRefusedBeforeSending(t, f, err, notSending)
}

// A sweep checks a target against every source it was asked to sweep, one it
// then skips included (its item says why nothing was sent from it), and the
// other sources get nothing addressed to it.
func TestSweepCountsASkippedSourceAsAskedFor(t *testing.T) {
	f := newArgsFixture(t)
	result, err := f.app.Sweep(context.Background(), SweepRequest{
		AssetRef: "algo", FromRaw: []string{"hl", "nat"}, ToRaw: "hl", Wait: true,
		LsigArgs: words(t, "arg:hl:preimage=a"),
	})
	if err != nil && result == nil {
		t.Fatalf("Sweep() error = %v", err)
	}
	if len(result.Items) != 2 || result.Items[0].SkippedReason != "source and destination are the same account" {
		t.Fatalf("sweep items = %+v, want hl skipped", result.Items)
	}
	f.wantSent(t, false, []map[string]string{nil})
}

// One transaction gets the untargeted words and those for its sender.
func TestSingleTransactionGetsItsSendersArguments(t *testing.T) {
	for _, token := range []string{"arg:preimage=a", "arg:hl:preimage=a", "arg:" + argsHTLC + ":preimage=a"} {
		t.Run(token, func(t *testing.T) {
			f := newArgsFixture(t)
			_, err := f.app.Close(context.Background(), CloseRequest{Account: "hl", CloseTo: "dest", Wait: true, LsigArgs: words(t, token)})
			if err == nil || !strings.Contains(err.Error(), "close failed") {
				t.Fatalf("Close() error = %v, want the test signer's refusal", err)
			}
			f.wantSent(t, false, []map[string]string{sentArgs("preimage", "a")})
		})
	}
}

// A plain send from a set submits each account's transaction on its own;
// each gets the words for its own account and the untargeted ones, and no
// other account's.
func TestSendFromASetGivesEachSubmissionItsOwnArguments(t *testing.T) {
	f := newArgsFixture(t)
	result, err := f.app.ExecuteSend(context.Background(), SendRequest{
		AmountText: "0", AssetRef: "algo", FromRaw: []string{"hl", "hl2", "nat"}, ToRaw: []string{"dest"}, Wait: true,
		LsigArgs: words(t, "arg:hl:preimage=a", "arg:hl2:preimage=b"),
	})
	// The test signer signs for none of these accounts, so every item fails
	// after its request was sent, and the send fails as a whole.
	if err == nil || err.Error() != "all 3 transaction(s) failed" {
		t.Fatalf("ExecuteSend() error = %v, want all 3 failed", err)
	}
	if result == nil || result.NonAtomic == nil || len(result.NonAtomic.Items) != 3 {
		t.Fatalf("send result = %+v, want three items", result)
	}
	f.wantSent(t, false,
		[]map[string]string{sentArgs("preimage", "a")},
		[]map[string]string{sentArgs("preimage", "b")},
		[]map[string]string{nil},
	)
}

// A send from a set asks for each transaction on its own, and each request
// reaches the signer labeled with its place among the ones sent. A sender
// that fails its preflight check is never sent and takes no place, and a send
// of one carries no label.
func TestSendFromASetLabelsEachRequestForTheSigner(t *testing.T) {
	for _, tc := range []struct {
		name     string
		from     []string
		args     cmdspec.LsigArgs
		unfunded string
		want     []*signerapi.SignBatch
	}{
		{"three", []string{"hl", "hl2", "nat"}, words(t, "arg:hl:preimage=a", "arg:hl2:preimage=b"), "",
			[]*signerapi.SignBatch{{Position: 1, Count: 3}, {Position: 2, Count: 3}, {Position: 3, Count: 3}}},
		{"the second unfunded", []string{"hl", "hl2", "nat"}, words(t, "arg:hl:preimage=a", "arg:hl2:preimage=b"), argsHTLC2,
			[]*signerapi.SignBatch{{Position: 1, Count: 2}, {Position: 2, Count: 2}}},
		{"one", []string{"nat"}, nil, "", []*signerapi.SignBatch{nil}},
	} {
		f := newArgsFixture(t)
		f.mu.Lock()
		f.unfunded = tc.unfunded
		f.mu.Unlock()
		result, err := f.app.ExecuteSend(context.Background(), SendRequest{
			AmountText: "0", AssetRef: "algo", FromRaw: tc.from, ToRaw: []string{"dest"}, Wait: true,
			LsigArgs: tc.args,
		})
		// The test signer signs for none of these accounts: every item fails,
		// and so does the send.
		if want := fmt.Sprintf("all %d transaction(s) failed", len(tc.from)); err == nil || err.Error() != want || result == nil {
			t.Fatalf("%s: ExecuteSend() = %v, %v; want the result and %q", tc.name, result != nil, err, want)
		}
		if tc.unfunded != "" {
			if item := result.NonAtomic.Items[1]; !strings.Contains(item.Error, "insufficient balance") {
				t.Fatalf("%s: the unfunded sender's result = %+v, want a preflight refusal", tc.name, item)
			}
		}
		f.mu.Lock()
		sent := append([]*signerapi.SignBatch(nil), f.batches...)
		f.mu.Unlock()
		if !reflect.DeepEqual(sent, tc.want) {
			t.Errorf("%s: batches at /sign = %s, want %s", tc.name, batchesString(sent), batchesString(tc.want))
		}
	}
}

// An atomic send from a set gives each position its own account's words:
// different names for different key types, and one name with a value per
// account.
func TestAtomicSendFromASetPlacesArgumentsBySender(t *testing.T) {
	for _, tc := range []struct {
		name   string
		from   []string
		tokens []string
		want   []map[string]string
	}{
		{"two key types", []string{"hl", "sec", "nat"}, []string{"arg:hl:preimage=a", "arg:sec:secret=s"},
			[]map[string]string{sentArgs("preimage", "a"), sentArgs("secret", "s"), nil}},
		{"one name, a value per account", []string{"@lsigs"}, []string{"arg:hl:preimage=a", "arg:hl2:preimage=b"},
			[]map[string]string{sentArgs("preimage", "a"), sentArgs("preimage", "b")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			_, err := f.app.ExecuteSend(context.Background(), SendRequest{
				AmountText: "0", AssetRef: "algo", FromRaw: tc.from, ToRaw: []string{"dest"}, Atomic: true, Wait: true,
				LsigArgs: words(t, tc.tokens...),
			})
			if err == nil || !strings.Contains(err.Error(), "atomic transaction group failed") {
				t.Fatalf("ExecuteSend() error = %v, want the test signer's refusal", err)
			}
			f.wantSent(t, false, tc.want)
		})
	}
}

// A default-mode plugin draft gets the words placed by sender. An untargeted
// word is sent to every position, a native one included (the signer refuses
// it there); a word for the LogicSig account reaches only its position.
func TestDefaultPluginDraftPlacesArgumentsBySender(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tokens []string
		want   []map[string]string
	}{
		{"untargeted", []string{"arg:preimage=a"}, []map[string]string{sentArgs("preimage", "a"), sentArgs("preimage", "a")}},
		{"for the LogicSig account", []string{"arg:hl:preimage=a"}, []map[string]string{sentArgs("preimage", "a"), nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			result := &jsonrpc.ExecuteResult{Transactions: rawPluginIntents(f.payment(t, argsHTLC), f.payment(t, argsNative))}
			if err := checkAndSubmit(context.Background(), f.app, result, words(t, tc.tokens...)); err == nil {
				t.Fatal("submission succeeded against a signer that refuses everything")
			}
			f.wantSent(t, false, tc.want)
		})
	}
}

// A presign-plan group gives a word for a managed account to that position;
// a word that reaches the plugin-signed position, untargeted or addressed to
// it, is refused by the check, before the group is reviewed or anything is
// sent.
func TestPresignPlanGroupArguments(t *testing.T) {
	presign := func(f *argsFixture) *jsonrpc.ExecuteResult {
		return &jsonrpc.ExecuteResult{
			GroupMode:     jsonrpc.GroupModePresignPlan,
			Transactions:  rawPluginIntents(f.payment(t, argsHTLC), f.payment(t, argsPlugin)),
			PluginSigners: []jsonrpc.PluginSigner{{Address: argsPlugin, SignerRef: "ref", Kind: jsonrpc.PluginSignerKindCallback}},
		}
	}
	f := newArgsFixture(t)
	if err := checkAndSubmit(context.Background(), f.app, presign(f), words(t, "arg:hl:preimage=a")); err == nil {
		t.Fatal("submission succeeded against a signer that refuses everything")
	}
	f.wantSent(t, true, []map[string]string{sentArgs("preimage", "a"), nil})

	for name, token := range map[string]string{"untargeted": "arg:preimage=a", "for the plugin's account": "arg:" + argsPlugin + ":preimage=a"} {
		t.Run(name, func(t *testing.T) {
			f := newArgsFixture(t)
			group, err := f.app.CheckPluginGroup(context.Background(), presign(f), PluginCheckOptions{Interactive: true, LsigArgs: words(t, token)})
			if group != nil {
				t.Fatal("CheckPluginGroup() returned a group for review")
			}
			wantRefusedBeforeSending(t, f, err, "transaction 2: LogicSig arguments reach "+argsPlugin+", which the plugin signs")
		})
	}
}

// An app call with a companion payment sends both from one account, so a
// word for it reaches both.
func TestAppCallCompanionPaymentGetsTheSendersArguments(t *testing.T) {
	f := newArgsFixture(t)
	_, err := f.app.AppCallRaw(context.Background(), AppCallRawRequest{
		AppID: 1234, From: "hl", PayAmount: 1000, Wait: true, LsigArgs: words(t, "arg:hl:preimage=a"),
	})
	if err == nil || !strings.Contains(err.Error(), "grouped raw app call failed") {
		t.Fatalf("AppCallRaw() error = %v, want the test signer's refusal of the group", err)
	}
	f.wantSent(t, false, []map[string]string{sentArgs("preimage", "a"), sentArgs("preimage", "a")})
}

// A script's close() and sweep() take lsigArgs as untargeted arguments, for
// every transaction the call builds, by one route
// (engine.UntargetedLsigArgs), so a name is treated alike by both: one
// holding ':' is passed on as it is, and here refused by the client's
// pre-sign check for a key that does not declare it, before anything is
// signed.
func TestScriptLsigArgsAreUntargeted(t *testing.T) {
	run := func(t *testing.T, f *argsFixture, code string) error {
		t.Helper()
		_, err := f.app.Scripts.EnsureRunner(func(string) {}, nil).RunWithContext(context.Background(), code)
		return err
	}

	f := newArgsFixture(t)
	if err := run(t, f, `close("hl", "dest", {lsigArgs: {preimage: "text:open"}})`); err == nil ||
		!strings.Contains(err.Error(), "close() error submitting transaction") {
		t.Fatalf("close() error = %v, want the test signer's refusal", err)
	}
	f.wantSent(t, false, []map[string]string{sentArgs("preimage", "open")})

	f = newArgsFixture(t)
	if err := run(t, f, `sweep(["hl", "hl2"], "dest", {lsigArgs: {preimage: "text:open"}})`); err == nil ||
		!strings.Contains(err.Error(), "all 2 transaction(s) failed") {
		t.Fatalf("sweep() error = %v, want the test signer's refusal of both", err)
	}
	f.wantSent(t, false, []map[string]string{sentArgs("preimage", "open")}, []map[string]string{sentArgs("preimage", "open")})

	for name, code := range map[string]string{
		"close": `close("hl", "dest", {lsigArgs: {"pre:image": "text:open"}})`,
		"sweep": `sweep(["hl"], "dest", {lsigArgs: {"pre:image": "text:open"}})`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newArgsFixture(t)
			err := run(t, f, code)
			if err == nil || !strings.Contains(err.Error(), "invalid LogicSig arguments: unknown argument 'pre:image' for this account type") {
				t.Fatalf("%s() error = %v, want the pre-sign check's refusal of the name", name, err)
			}
			if got := f.signerPosts.Load(); got != 0 {
				t.Fatalf("signer requests = %d, want none", got)
			}
		})
	}
}

// withAsset7 makes asset 7 one the node describes and the senders and dest
// hold, and gives the engine an ASA cache to keep it in.
func withAsset7(t *testing.T, f *argsFixture) {
	t.Helper()
	f.holdings = map[string][]models.AssetHolding{argsHTLC: {{AssetId: 7}}, argsNative: {{AssetId: 7}}, argsDest: {{AssetId: 7}}}
	f.assets = map[uint64]models.AssetParams{7: {Creator: argsNative, Total: 1_000, UnitName: "T"}}
	f.eng.AsaCache = cache.LoadASACacheFromStore(cache.NewStore(t.TempDir()), "testnet")
}

// Every script function that sends from one account takes lsigArgs, for every
// transaction it builds: the payment an app call's pay adds too, which is from
// the same account.
func TestScriptLsigArgsReachEachFunction(t *testing.T) {
	dir := t.TempDir()
	abi := filepath.Join(dir, "app.json")
	program := filepath.Join(dir, "program.bin")
	if err := os.WriteFile(abi, []byte(`{"name":"t","methods":[{"name":"noop","args":[],"returns":{"type":"void"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, []byte{0x0a, 0x81, 0x01}, 0o600); err != nil { // #pragma version 10; int 1
		t.Fatal(err)
	}
	const args = `lsigArgs: {preimage: "text:open"}`
	online := `votekey: "` + strings.Repeat("A", 43) + `=", selkey: "` + strings.Repeat("A", 43) + `=", sproofkey: "` +
		strings.Repeat("A", 86) + `==", votefirst: 1000, votelast: 2000, keydilution: 100`
	one := []map[string]string{sentArgs("preimage", "open")}
	two := []map[string]string{sentArgs("preimage", "open"), sentArgs("preimage", "open")}
	for _, tc := range []struct {
		name, code string
		want       []map[string]string
	}{
		{"validate", `validate("hl", {` + args + `})`, one},
		{"send", `send("hl", "dest", 1, {` + args + `})`, one},
		{"sendAsset", `sendAsset("hl", "dest", 7, 1, {` + args + `})`, one},
		{"optIn", `optIn("hl", 7, {` + args + `})`, one},
		{"optOut", `optOut("hl", 7, {` + args + `})`, one},
		{"optOut to an account", `optOut("hl", 7, "dest", {` + args + `})`, one},
		{"rekey", `rekey("hl", "nat", {` + args + `})`, one},
		{"unrekey", `unrekey("hl", {` + args + `})`, one},
		{"keyreg offline", `keyreg("hl", "offline", {` + args + `})`, one},
		{"keyreg online", `keyreg("hl", "online", {` + online + `, ` + args + `})`, one},
		{"appDeploy", `appDeploy("hl", "` + program + `", "` + program + `", {approvalCompiled: true, clearCompiled: true, ` + args + `})`, one},
		{"appCallRaw", `appCallRaw(5, "hl", [], {` + args + `})`, one},
		{"appCallRaw with pay", `appCallRaw(5, "hl", [], {pay: 1000, ` + args + `})`, two},
		{"appCall", `appCall(5, "noop", "` + abi + `", "hl", [], {` + args + `})`, one},
		{"appCall with pay", `appCall(5, "noop", "` + abi + `", "hl", [], {pay: 1000, ` + args + `})`, two},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			withAsset7(t, f)
			if _, err := f.app.Scripts.EnsureRunner(func(string) {}, nil).RunWithContext(context.Background(), tc.code); err == nil ||
				!strings.Contains(err.Error(), "test signer") {
				t.Fatalf("error = %v, want the test signer's refusal", err)
			}
			f.wantSent(t, false, tc.want)
		})
	}
	// validate, and keyreg offline, take nothing else, and optOut one options
	// object.
	for code, want := range map[string]string{
		`validate("hl", {wait: false})`:                      "is not known",
		`keyreg("hl", "offline", {votekey: "x"})`:            "is not known",
		`optOut("hl", 7, {fee: 2000}, {` + args + `})`:       "takes one options object",
		`optOut("hl", 7, "dest", {fee: 2000, nowait: true})`: "is not known",
	} {
		f := newArgsFixture(t)
		_, err := f.app.Scripts.EnsureRunner(func(string) {}, nil).RunWithContext(context.Background(), code)
		wantRefusedBeforeSending(t, f, err, want)
	}
}

// An atomic payment's lsigArgs is for its sender. A sender's transactions all
// get the same arguments, so two payments from one sender whose arguments
// differ are refused, one without any among them, before anything is signed;
// for the whole call, lsigArgs would reach every sender, and is refused.
func TestScriptAtomicLsigArgsAreForEachSender(t *testing.T) {
	run := func(t *testing.T, f *argsFixture, code string) error {
		t.Helper()
		_, err := f.app.Scripts.EnsureRunner(func(string) {}, nil).RunWithContext(context.Background(), code)
		return err
	}
	pay := func(from, args string) string {
		if args != "" {
			args = `, lsigArgs: ` + args
		}
		return `{from: "` + from + `", to: "dest", amount: 0` + args + `}`
	}
	for _, tc := range []struct {
		name     string
		payments []string
		want     []map[string]string
	}{
		{"two senders", []string{pay("hl", `{preimage: "text:a"}`), pay("sec", `{secret: "text:b"}`)},
			[]map[string]string{sentArgs("preimage", "a"), sentArgs("secret", "b")}},
		{"beside a native sender", []string{pay("hl", `{preimage: "text:a"}`), pay("nat", "")},
			[]map[string]string{sentArgs("preimage", "a"), nil}},
		{"one sender twice, alike", []string{pay("hl", `{preimage: "text:a"}`), pay("hl", `{preimage: "text:a"}`)},
			[]map[string]string{sentArgs("preimage", "a"), sentArgs("preimage", "a")}},
		{"one sender twice, neither with any", []string{pay("hl", ""), pay("hl", `{}`)}, []map[string]string{nil, nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newArgsFixture(t)
			if err := run(t, f, `atomicSend([`+strings.Join(tc.payments, ", ")+`])`); err == nil || !strings.Contains(err.Error(), "test signer") {
				t.Fatalf("error = %v, want the test signer's refusal", err)
			}
			f.wantSent(t, false, tc.want)
		})
	}
	t.Run("transfers", func(t *testing.T) {
		f := newArgsFixture(t)
		withAsset7(t, f)
		err := run(t, f, `atomicSendAsset([{from: "hl", to: "dest", assetId: 7, amount: 0, lsigArgs: {preimage: "text:a"}}, {from: "nat", to: "dest", assetId: 7, amount: 0}])`)
		if err == nil || !strings.Contains(err.Error(), "test signer") {
			t.Fatalf("error = %v, want the test signer's refusal", err)
		}
		f.wantSent(t, false, []map[string]string{sentArgs("preimage", "a"), nil})
	})
	for name, code := range map[string]string{
		"different":                   `atomicSend([` + pay("hl", `{preimage: "text:a"}`) + `, ` + pay("hl", `{preimage: "text:b"}`) + `])`,
		"omitted":                     `atomicSend([` + pay("hl", `{preimage: "text:a"}`) + `, ` + pay("hl", "") + `])`,
		"empty":                       `atomicSend([` + pay("hl", "") + `, ` + pay("hl", `{preimage: "text:a"}`) + `])`,
		"transfers":                   `atomicSendAsset([{from: "hl", to: "dest", assetId: 7, amount: 0, lsigArgs: {preimage: "text:a"}}, {from: "hl", to: "dest", assetId: 7, amount: 0, lsigArgs: {}}])`,
		"two spellings":               `atomicSend([` + pay("hl", `{preimage: "text:a"}`) + `, ` + pay("hashlock", `{preimage: "text:b"}`) + `])`,
		"alias and address":           `atomicSend([` + pay("hl", `{preimage: "text:a"}`) + `, ` + pay(argsHTLC, "") + `])`,
		"for the whole":               `atomicSend([` + pay("hl", "") + `], {lsigArgs: {preimage: "text:a"}})`,
		"not an object for the whole": `atomicSend([` + pay("hl", "") + `], {lsigArgs: "x"})`,
		"undefined for the whole":     `atomicSend([` + pay("hl", "") + `], {lsigArgs: undefined})`,
		"unknown for the whole":       `atomicSend([` + pay("hl", "") + `], {foo: 1})`,
		"empty for the whole":         `atomicSend([` + pay("hl", "") + `], {lsigArgs: {}})`,
		"for the whole transfer":      `atomicSendAsset([{from: "hl", to: "dest", assetId: 7, amount: 0}], {lsigArgs: {}})`,
	} {
		t.Run("refused "+name, func(t *testing.T) {
			f := newArgsFixture(t)
			want := "give different lsigArgs"
			switch name {
			case "for the whole", "empty for the whole", "not an object for the whole", "undefined for the whole":
				want = "atomicSend() option lsigArgs goes on each payment"
			case "for the whole transfer":
				want = "atomicSendAsset() option lsigArgs goes on each transfer"
			case "unknown for the whole":
				// The group's options are fee and wait; lsigArgs isn't one.
				want = "(known: fee, wait)"
			}
			wantRefusedBeforeSending(t, f, run(t, f, code), want)
		})
	}
}
