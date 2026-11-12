// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	err = checkAndSubmit(context.Background(), app, &jsonrpc.ExecuteResult{}, nil)
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

// interactive is the check of a review that can ask the user, as the REPL's.
var interactive = PluginCheckOptions{Interactive: true}

// checkAndSubmit is what every apshell surface does with a plugin result:
// CheckPluginGroup, then SubmitPluginTransactions with the group it returns.
func checkAndSubmit(ctx context.Context, app *App, result *jsonrpc.ExecuteResult, lsigArgs map[string][]byte) error {
	group, err := app.CheckPluginGroup(ctx, result, interactive)
	if err != nil {
		return err
	}
	_, err = app.SubmitPluginTransactions(ctx, "plugin", group, lsigArgs)
	return err
}

// pluginRekeyFixture is an engine connected to a test signer whose /keys lists
// keys, which a test may change, and whose other endpoints, like the test
// node's, answer 503 and are counted.
type pluginRekeyFixture struct {
	app                     *App
	eng                     *engine.Engine
	mu                      sync.Mutex
	keys                    []signerapi.KeyInfo
	locked                  bool
	keyFetches, signerCalls atomic.Int32
	nodeCalls               atomic.Int32
}

func newPluginRekeyFixture(t *testing.T, keys []signerapi.KeyInfo) *pluginRekeyFixture {
	t.Helper()
	f := &pluginRekeyFixture{keys: keys}
	signerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/keys" {
			f.keyFetches.Add(1)
			f.mu.Lock()
			keys, locked := f.keys, f.locked
			f.mu.Unlock()
			if locked {
				http.Error(w, "signer is locked", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
			return
		}
		f.signerCalls.Add(1)
		http.Error(w, "test signer", http.StatusServiceUnavailable)
	}))
	t.Cleanup(signerServer.Close)
	algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.nodeCalls.Add(1)
		http.Error(w, "test node", http.StatusServiceUnavailable)
	}))
	t.Cleanup(algodServer.Close)
	algodClient, err := algod.MakeClient(algodServer.URL, "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}
	f.eng, err = engine.NewEngine("testnet", engine.WithAlgodClient(algodClient))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	f.eng.Connection.SignerClient = signerclient.NewSignerClient(signerServer.URL)
	f.app = New(f.eng, config.DefaultConfig(), t.TempDir())
	return f
}

// setSigner changes what the test signer's /keys answers.
func (f *pluginRekeyFixture) setSigner(keys []signerapi.KeyInfo, locked bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys, f.locked = keys, locked
}

func (f *pluginRekeyFixture) resetCounts() {
	f.keyFetches.Store(0)
	f.signerCalls.Store(0)
	f.nodeCalls.Store(0)
}

// pluginRekeyResults puts txn into a result of each plugin mode: the default
// draft, where apsigner signs it, and a presign-plan and a pregrouped-signed
// group, where the plugin signs it. It returns txn's position in each group,
// counted from 1.
func pluginRekeyResults(t *testing.T, txn types.Transaction) map[string]struct {
	result   *jsonrpc.ExecuteResult
	position string
} {
	t.Helper()
	filler := rekeySubmitTestTxn(types.Address{7}, types.Address{})
	return map[string]struct {
		result   *jsonrpc.ExecuteResult
		position string
	}{
		"default": {result: &jsonrpc.ExecuteResult{Transactions: rawPluginIntents(txn)}, position: "1"},
		"presign-plan": {result: &jsonrpc.ExecuteResult{
			GroupMode:     jsonrpc.GroupModePresignPlan,
			Transactions:  rawPluginIntents(filler, txn),
			PluginSigners: []jsonrpc.PluginSigner{{Address: txn.Sender.String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref"}},
		}, position: "2"},
		"pregrouped-signed": {result: &jsonrpc.ExecuteResult{
			GroupMode:    jsonrpc.GroupModePregroupedSigned,
			Transactions: signedPluginIntents(t, filler, txn),
		}, position: "2"},
	}
}

var (
	rekeyTestNative   = types.Address{20}
	rekeyTestRotating = types.Address{21}
	rekeyTestHTLC     = types.Address{22}
	rekeyTestForeign  = types.Address{25}
	rekeyTestOther    = types.Address{1}
)

func rekeyTestKeys() []signerapi.KeyInfo {
	return []signerapi.KeyInfo{
		{Address: rekeyTestNative.String(), KeyType: "ed25519", ValidRekeyTarget: true},
		{Address: rekeyTestRotating.String(), KeyType: "aplane.rotating-triple-wotsc.v1", SigningFlow: signerapi.SigningFlowRotating1},
		{Address: rekeyTestHTLC.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true},
	}
}

func rekeyRefusal(position string, target types.Address, keyType string) string {
	return "transaction " + position + ": cannot rekey to " + target.String() +
		": this signer holds its aplane key (" + keyType + "), which is not a valid rekey target"
}

// A plugin-built group is refused, in every mode, when a transaction at any
// position rekeys an account to a held aplane key that is not a valid rekey
// target, the account's own address included. The check fetches the signer's
// key list and sends nothing else: nothing goes to the signer's other
// endpoints or to the node. A held aplane key that is a valid rekey target,
// and a foreign address, are not refused: submission fetches the list again
// and the group goes on to the signer or the node. The REPL, MCP and
// JavaScript all take the group from CheckPluginGroup and submit it with
// SubmitPluginTransactions.
func TestSubmitPluginTransactionsRefusesARekeyToAHeldInvalidTarget(t *testing.T) {
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	for _, tc := range []struct {
		name    string
		txn     types.Transaction
		keyType string // set when the rekey is refused
	}{
		{name: "held rotating account", txn: rekeySubmitTestTxn(rekeyTestOther, rekeyTestRotating), keyType: "aplane.rotating-triple-wotsc.v1"},
		{name: "held generic LogicSig that is not a valid rekey target", txn: rekeySubmitTestTxn(rekeyTestOther, rekeyTestHTLC), keyType: "aplane.htlc.v1"},
		{name: "own address that is not a valid rekey target", txn: rekeySubmitTestTxn(rekeyTestRotating, rekeyTestRotating), keyType: "aplane.rotating-triple-wotsc.v1"},
		{name: "held aplane key that is a valid rekey target", txn: rekeySubmitTestTxn(rekeyTestOther, rekeyTestNative)},
		{name: "foreign address", txn: rekeySubmitTestTxn(rekeyTestOther, rekeyTestForeign)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for mode, c := range pluginRekeyResults(t, tc.txn) {
				f.resetCounts()
				err := checkAndSubmit(context.Background(), f.app, c.result, nil)
				sent := f.signerCalls.Load() + f.nodeCalls.Load()
				if tc.keyType != "" {
					if want := rekeyRefusal(c.position, tc.txn.RekeyTo, tc.keyType); err == nil || err.Error() != want {
						t.Errorf("%s: error = %v, want %q", mode, err, want)
					}
					if sent != 0 || f.keyFetches.Load() != 1 {
						t.Errorf("%s: a refused group fetched the key list %d time(s) and sent %d other request(s)", mode, f.keyFetches.Load(), sent)
					}
					continue
				}
				if err != nil && strings.Contains(err.Error(), "not a valid rekey target") {
					t.Errorf("%s: refused a rekey the signer allows: %v", mode, err)
				}
				if got := f.keyFetches.Load(); got != 2 {
					t.Errorf("%s: fetched the key list %d time(s), want once at the check and once at submission", mode, got)
				}
				if sent == 0 {
					t.Errorf("%s: the group reached neither the signer nor the node (error %v)", mode, err)
				}
			}
		})
	}
}

// Submission judges a rekeying group again against a key list fetched again,
// before it sends the group anywhere (before the signer in the default flow,
// before broadcast for pregrouped-signed, before /plan for presign-plan): a
// key the signer creates while the group waits at the review is refused at
// submission in every mode, as is a signer locked meanwhile, and nothing
// reaches the node.
func TestSubmitPluginTransactionsRechecksTheKeyListBeforeSending(t *testing.T) {
	rekey := rekeySubmitTestTxn(rekeyTestOther, rekeyTestHTLC)
	f := newPluginRekeyFixture(t, rekeyTestKeys()[:1])
	for mode, c := range pluginRekeyResults(t, rekey) {
		f.setSigner(rekeyTestKeys()[:1], false)
		group, err := f.app.CheckPluginGroup(context.Background(), c.result, interactive)
		if err != nil {
			t.Fatalf("%s: CheckPluginGroup() with the target foreign: %v", mode, err)
		}
		f.setSigner(rekeyTestKeys(), false)
		f.resetCounts()
		_, err = f.app.SubmitPluginTransactions(context.Background(), "plugin", group, nil)
		if want := rekeyRefusal(c.position, rekeyTestHTLC, "aplane.htlc.v1"); err == nil || err.Error() != want {
			t.Errorf("%s: SubmitPluginTransactions() error = %v, want %q", mode, err, want)
		}
		if f.keyFetches.Load() != 1 || f.signerCalls.Load() != 0 || f.nodeCalls.Load() != 0 {
			t.Errorf("%s: submission fetched the key list %d time(s), sent %d request(s) to the signer and %d to the node",
				mode, f.keyFetches.Load(), f.signerCalls.Load(), f.nodeCalls.Load())
		}

		f.setSigner(rekeyTestKeys()[:1], true)
		f.resetCounts()
		_, err = f.app.SubmitPluginTransactions(context.Background(), "plugin", group, nil)
		if want := "plugin group rekeys an account (transaction " + c.position + "): the signer is locked; unlock it so apshell can check the rekey target against its aplane keys"; err == nil || err.Error() != want {
			t.Errorf("%s: locked at submission: error = %v, want %q", mode, err, want)
		}
		if f.nodeCalls.Load() != 0 {
			t.Errorf("%s: locked at submission: sent %d request(s) to the node", mode, f.nodeCalls.Load())
		}
	}
}

// A rekey in a plugin group needs the signer's current key list. Without a
// connection, or with a locked signer, the group is refused in every mode,
// whatever the cache holds, and nothing goes to the node.
func TestCheckPluginGroupNeedsTheSignersKeyListForARekey(t *testing.T) {
	rekey := rekeySubmitTestTxn(rekeyTestOther, rekeyTestHTLC)

	f := newPluginRekeyFixture(t, rekeyTestKeys())
	f.eng.Connection.SignerClient = nil
	for mode, c := range pluginRekeyResults(t, rekey) {
		f.resetCounts()
		want := "plugin group rekeys an account (transaction " + c.position + "): connect to the signer so apshell can check the rekey target against its aplane keys"
		if err := checkAndSubmit(context.Background(), f.app, c.result, nil); err == nil || err.Error() != want {
			t.Errorf("not connected, %s: error = %v, want %q", mode, err, want)
		}
		if f.nodeCalls.Load() != 0 || f.keyFetches.Load() != 0 {
			t.Errorf("not connected, %s: sent %d request(s) to the node and fetched the key list %d time(s)", mode, f.nodeCalls.Load(), f.keyFetches.Load())
		}
	}

	locked := newPluginRekeyFixture(t, rekeyTestKeys())
	locked.setSigner(rekeyTestKeys(), true)
	for mode, c := range pluginRekeyResults(t, rekey) {
		locked.resetCounts()
		want := "plugin group rekeys an account (transaction " + c.position + "): the signer is locked; unlock it so apshell can check the rekey target against its aplane keys"
		if err := checkAndSubmit(context.Background(), locked.app, c.result, nil); err == nil || err.Error() != want {
			t.Errorf("locked, %s: error = %v, want %q", mode, err, want)
		}
		if locked.nodeCalls.Load() != 0 || locked.signerCalls.Load() != 0 {
			t.Errorf("locked, %s: sent %d request(s) to the node and %d to the signer", mode, locked.nodeCalls.Load(), locked.signerCalls.Load())
		}
	}
}

// The verdict and the review's facts come from the records the fetch returned,
// never from the signer cache, which the check neither reads nor rewrites: a
// cache that says the opposite of the signer changes nothing, and is left as
// it was.
func TestCheckPluginGroupJudgesFromTheFetchedKeys(t *testing.T) {
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	// The cache says the HTLC is a valid rekey target and that a foreign
	// address holds an HTLC; the signer says neither.
	contradicting := []signerapi.KeyInfo{
		{Address: rekeyTestHTLC.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true, ValidRekeyTarget: true},
		{Address: rekeyTestForeign.String(), KeyType: "aplane.htlc.v1", IsGenericLsig: true},
	}
	if err := f.eng.PopulateSignerCache(contradicting); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	cached := maps.Clone(f.eng.SignerCache.Keys)

	for mode, c := range pluginRekeyResults(t, rekeySubmitTestTxn(rekeyTestOther, rekeyTestHTLC)) {
		if _, err := f.app.CheckPluginGroup(context.Background(), c.result, interactive); err == nil || err.Error() != rekeyRefusal(c.position, rekeyTestHTLC, "aplane.htlc.v1") {
			t.Errorf("%s: a rekey to the signer's HTLC: error = %v", mode, err)
		}
	}
	for mode, c := range pluginRekeyResults(t, rekeySubmitTestTxn(rekeyTestOther, rekeyTestForeign)) {
		group, err := f.app.CheckPluginGroup(context.Background(), c.result, interactive)
		if err != nil {
			t.Fatalf("%s: a rekey to an address the signer does not list: %v", mode, err)
		}
		// The review shows the facts the check judged from: the signer's list.
		facts := group.RekeyTargets()
		if facts.KnownAddresses[rekeyTestForeign.String()] || !facts.KnownAddresses[rekeyTestHTLC.String()] {
			t.Errorf("%s: the review's held set is not the fetched list: %v", mode, facts.KnownAddresses)
		}
		if _, ok := facts.InvalidRekeyTargets[rekeyTestHTLC.String()]; !ok {
			t.Errorf("%s: the review's not-valid set is not the fetched list: %v", mode, facts.InvalidRekeyTargets)
		}
	}
	if !maps.Equal(f.eng.SignerCache.Keys, cached) {
		t.Fatalf("the check rewrote the signer cache: %v, was %v", f.eng.SignerCache.Keys, cached)
	}
}

// A plugin group with no rekey needs no key list: it fetches nothing at the
// check or at submission, and a pregrouped-signed group with no rekey is
// checked with no signer connection.
func TestCheckPluginGroupLeavesAGroupWithNoRekeyAlone(t *testing.T) {
	plain := rekeySubmitTestTxn(rekeyTestOther, types.Address{})
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	for mode, c := range pluginRekeyResults(t, plain) {
		f.resetCounts()
		group, err := f.app.CheckPluginGroup(context.Background(), c.result, interactive)
		if err != nil {
			t.Fatalf("%s: CheckPluginGroup() error = %v", mode, err)
		}
		if group.RekeyTargets().KnownAddresses != nil {
			t.Errorf("%s: a group with no rekey has rekey facts", mode)
		}
		_, _ = f.app.SubmitPluginTransactions(context.Background(), "plugin", group, nil)
		if f.keyFetches.Load() != 0 {
			t.Errorf("%s: a group with no rekey fetched the key list %d time(s)", mode, f.keyFetches.Load())
		}
	}

	offline := (&App{})
	result := pluginRekeyResults(t, plain)["pregrouped-signed"].result
	if _, err := offline.CheckPluginGroup(context.Background(), result, interactive); err != nil {
		t.Fatalf("offline pregrouped-signed group with no rekey: CheckPluginGroup() error = %v", err)
	}
}

// The checked group holds copies of what review and submission read: a
// change to the result after the check changes neither, and a group the
// check did not produce is refused.
func TestPluginGroupIsFrozenAtTheCheck(t *testing.T) {
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	c := pluginRekeyResults(t, rekeySubmitTestTxn(rekeyTestOther, types.Address{}))["presign-plan"]
	c.result.RequiresApproval = true
	group, err := f.app.CheckPluginGroup(context.Background(), c.result, interactive)
	if err != nil {
		t.Fatalf("CheckPluginGroup() error = %v", err)
	}
	c.result.GroupMode = "bogus"
	c.result.RequiresApproval = false
	c.result.PluginSigners[0].SignerRef = "changed"
	c.result.PluginSigners = nil
	c.result.Transactions = nil
	txns, err := group.Transactions()
	if err != nil {
		t.Fatalf("Transactions() error = %v", err)
	}
	if group.Mode() != jsonrpc.GroupModePresignPlan || !group.RequiresApproval() ||
		len(group.PluginSigners()) != 1 || group.PluginSigners()[0].SignerRef != "ref" || len(txns) != 2 {
		t.Fatalf("the checked group followed the result: mode %q, approval %v, signers %+v, %d transaction(s)",
			group.Mode(), group.RequiresApproval(), group.PluginSigners(), len(txns))
	}
	f.resetCounts()
	_, err = f.app.SubmitPluginTransactions(context.Background(), "plugin", group, nil)
	if err == nil || strings.Contains(err.Error(), "pluginSigners") || f.nodeCalls.Load() == 0 {
		t.Fatalf("submission did not submit the checked group: error %v, %d node request(s)", err, f.nodeCalls.Load())
	}

	if _, err := f.app.SubmitPluginTransactions(context.Background(), "plugin", &PluginGroup{}, nil); !errors.Is(err, ErrUncheckedPluginGroup) {
		t.Fatalf("SubmitPluginTransactions(unchecked group) error = %v, want ErrUncheckedPluginGroup", err)
	}
}

// A transaction the group returns is a copy all the way down: changing a
// slice field of one changes no later copy, and submission decodes its own
// from what the check kept, so the group submitted is the group reviewed.
func TestPluginGroupTransactionsAreDeepCopies(t *testing.T) {
	txn := rekeySubmitTestTxn(rekeyTestOther, types.Address{})
	txn.Note = []byte("reviewed")
	group, err := (&App{}).CheckPluginGroup(context.Background(), &jsonrpc.ExecuteResult{Transactions: rawPluginIntents(txn)}, interactive)
	if err != nil {
		t.Fatalf("CheckPluginGroup() error = %v", err)
	}
	first, err := group.Transactions()
	if err != nil {
		t.Fatalf("Transactions() error = %v", err)
	}
	first[0].Note[0] = 'X'
	first[0].RekeyTo = rekeyTestHTLC
	again, err := group.Transactions()
	if err != nil {
		t.Fatalf("Transactions() error = %v", err)
	}
	if string(again[0].Note) != "reviewed" || !again[0].RekeyTo.IsZero() {
		t.Fatalf("a change to a returned transaction reached the group: note %q, rekey %s", again[0].Note, again[0].RekeyTo)
	}
}

// A pregrouped-signed group can never be submitted without a review that can
// ask the user, so under AutoConfirm it is refused for that reason first, even
// when it rekeys and no key list could be had.
func TestCheckPluginGroupRefusesANonInteractivePregroupedGroupFirst(t *testing.T) {
	c := pluginRekeyResults(t, rekeySubmitTestTxn(rekeyTestOther, rekeyTestHTLC))["pregrouped-signed"]
	_, err := (&App{}).CheckPluginGroup(context.Background(), c.result, PluginCheckOptions{})
	if !errors.Is(err, errPregroupedNonInteractive) {
		t.Fatalf("CheckPluginGroup(non-interactive) error = %v, want the non-interactive refusal", err)
	}
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	if _, err := f.app.CheckPluginGroup(context.Background(), c.result, PluginCheckOptions{}); !errors.Is(err, errPregroupedNonInteractive) || f.keyFetches.Load() != 0 {
		t.Fatalf("CheckPluginGroup(non-interactive, connected) error = %v after %d key fetch(es)", err, f.keyFetches.Load())
	}
	// The other modes have another gate and are not affected.
	for _, mode := range []string{"default", "presign-plan"} {
		if _, err := f.app.CheckPluginGroup(context.Background(), pluginRekeyResults(t, rekeySubmitTestTxn(rekeyTestOther, types.Address{}))[mode].result, PluginCheckOptions{}); err != nil {
			t.Errorf("%s: CheckPluginGroup(non-interactive) error = %v", mode, err)
		}
	}
}
