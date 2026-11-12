// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

	"github.com/aplane-algo/aplane/internal/cache"
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

// checkAndSubmit is what every apshell surface does with a plugin result:
// CheckPluginGroup, then SubmitPluginTransactions with the group it returns.
func checkAndSubmit(ctx context.Context, app *App, result *jsonrpc.ExecuteResult, lsigArgs map[string][]byte) error {
	group, err := app.CheckPluginGroup(ctx, result)
	if err != nil {
		return err
	}
	_, err = app.SubmitPluginTransactions(ctx, "plugin", group, lsigArgs)
	return err
}

// pluginRekeyFixture is an engine connected to a test signer whose /keys lists
// keys, and whose other endpoints, like the test node's, answer 503 and are
// counted.
type pluginRekeyFixture struct {
	app                     *App
	eng                     *engine.Engine
	keys                    []signerapi.KeyInfo
	keyFetches, signerCalls atomic.Int32
	nodeCalls               atomic.Int32
	locked                  bool
}

func newPluginRekeyFixture(t *testing.T, keys []signerapi.KeyInfo) *pluginRekeyFixture {
	t.Helper()
	f := &pluginRekeyFixture{keys: keys}
	signerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/keys" {
			f.keyFetches.Add(1)
			if f.locked {
				http.Error(w, "signer is locked", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(f.keys), Keys: f.keys})
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

// A plugin-built group is refused, in every mode, when a transaction at any
// position rekeys an account to a held aplane key that is not a valid rekey
// target, the account's own address included. The check fetches the signer's
// key list, so it holds with an empty cache, and fetches nothing else: nothing
// goes to the signer's other endpoints or to the node. A held aplane key that
// is a valid rekey target, and a foreign address, are not refused: the group
// goes on to the signer or the node. The REPL, MCP and JavaScript all take the
// group from CheckPluginGroup and submit it with SubmitPluginTransactions.
func TestSubmitPluginTransactionsRefusesARekeyToAHeldInvalidTarget(t *testing.T) {
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	refusal := func(position string, target types.Address, keyType string) string {
		return "transaction " + position + ": cannot rekey to " + target.String() +
			": this signer holds its aplane key (" + keyType + "), which is not a valid rekey target"
	}
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
				// Each check starts from an empty cache: the list comes from the signer.
				f.eng.SignerCache = cache.NewSignerCache()
				f.resetCounts()
				err := checkAndSubmit(context.Background(), f.app, c.result, nil)
				if got := f.keyFetches.Load(); got < 1 {
					t.Errorf("%s: the check fetched the signer's key list %d time(s), want at least once", mode, got)
				}
				sent := f.signerCalls.Load() + f.nodeCalls.Load()
				if tc.keyType != "" {
					if want := refusal(c.position, tc.txn.RekeyTo, tc.keyType); err == nil || err.Error() != want {
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
				if sent == 0 {
					t.Errorf("%s: the group reached neither the signer nor the node (error %v)", mode, err)
				}
			}
		})
	}
}

// A rekey in a plugin group needs the signer's current key list. Without a
// connection, or with a locked signer, the group is refused in every mode,
// whatever the cache holds, and nothing goes to the node. A key the signer
// lists that the cache does not yet hold is still caught.
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
			t.Errorf("not connected, %s: sent %d request(s) to the node", mode, f.nodeCalls.Load())
		}
	}

	locked := newPluginRekeyFixture(t, rekeyTestKeys())
	locked.locked = true
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

	// The cache lists only the ed25519 key; the signer has since added the HTLC.
	added := newPluginRekeyFixture(t, rekeyTestKeys())
	if err := added.eng.PopulateSignerCache(rekeyTestKeys()[:1]); err != nil {
		t.Fatalf("PopulateSignerCache() error = %v", err)
	}
	for mode, c := range pluginRekeyResults(t, rekey) {
		want := "transaction " + c.position + ": cannot rekey to " + rekeyTestHTLC.String() +
			": this signer holds its aplane key (aplane.htlc.v1), which is not a valid rekey target"
		if err := checkAndSubmit(context.Background(), added.app, c.result, nil); err == nil || err.Error() != want {
			t.Errorf("key added since, %s: error = %v, want %q", mode, err, want)
		}
	}
}

// A plugin group with no rekey needs no key list: it is not refreshed, and a
// pregrouped-signed group with no rekey is checked with no signer connection.
func TestCheckPluginGroupLeavesAGroupWithNoRekeyAlone(t *testing.T) {
	plain := rekeySubmitTestTxn(rekeyTestOther, types.Address{})
	f := newPluginRekeyFixture(t, rekeyTestKeys())
	for mode, c := range pluginRekeyResults(t, plain) {
		f.resetCounts()
		group, err := f.app.CheckPluginGroup(context.Background(), c.result)
		if err != nil {
			t.Fatalf("%s: CheckPluginGroup() error = %v", mode, err)
		}
		if f.keyFetches.Load() != 0 || f.signerCalls.Load() != 0 {
			t.Errorf("%s: a group with no rekey fetched the key list %d time(s)", mode, f.keyFetches.Load())
		}
		if group.RekeyTargets().KnownAddresses != nil {
			t.Errorf("%s: a group with no rekey read the signer cache", mode)
		}
	}

	offline := (&App{})
	result := pluginRekeyResults(t, plain)["pregrouped-signed"].result
	if _, err := offline.CheckPluginGroup(context.Background(), result); err != nil {
		t.Fatalf("offline pregrouped-signed group with no rekey: CheckPluginGroup() error = %v", err)
	}
}
