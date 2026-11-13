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

	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/rotatingkey"
	"github.com/aplane-algo/aplane/internal/signerclient"
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
		return signerapi.KeyInfo{Address: address, KeyType: "aplane.htlc.v1", IsGenericLsig: true,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "preimage", Type: "bytes", MaxSize: 64}}}
	}
	return []signerapi.KeyInfo{
		{Address: argsNative, KeyType: "ed25519"},
		{Address: argsFalcon, KeyType: "falcon1024"},
		{Address: argsRekeyed, KeyType: "ed25519"},
		{Address: argsRotating, KeyType: rotatingkey.RotatingTripleXmssV1, SigningFlow: signerapi.SigningFlowRotating1,
			LogicSigResources: &signerapi.LogicSigResourceProfile{Default: &signerapi.LogicSigResourceUsage{
				ProgramBytes: 4_500, ArgumentBytes: 1_423, MaxOpcodeCost: 20_000}}},
		htlc(argsHTLC), htlc(argsHTLC2),
		{Address: argsSecret, KeyType: "example.secret.v1", IsGenericLsig: true,
			SigningArgs: []signerapi.SigningArgInfo{{Name: "secret", Type: "bytes", MaxSize: 32}}},
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
	plans       [][]signerapi.SignRequest
	signerPosts atomic.Int32
	perByteFee  atomic.Uint64
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
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
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
				} else {
					f.plans = append(f.plans, req.Requests)
				}
				f.mu.Unlock()
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
			switch address {
			case argsRekeyed:
				account.AuthAddr = argsFalcon
			case argsRotating:
				account.AuthAddr = argsStage
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
	if err != nil {
		t.Fatalf("ExecuteSend() error = %v", err)
	}
	if result.NonAtomic == nil || len(result.NonAtomic.Items) != 3 {
		t.Fatalf("send result = %+v, want three items", result)
	}
	f.wantSent(t, false,
		[]map[string]string{sentArgs("preimage", "a")},
		[]map[string]string{sentArgs("preimage", "b")},
		[]map[string]string{nil},
	)
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
		_, err := f.app.Scripts.EnsureRunner(func(string) {}, nil).Run(code)
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
