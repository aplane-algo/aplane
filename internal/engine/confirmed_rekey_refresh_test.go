// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

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
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// confirmedRekeyNet is a signer holding account's ed25519 key, and a node on
// which account signs for itself until a group is submitted and is rekeyed
// to target after it. The node confirms every submission. With
// failAfterSubmit, its account queries fail once a group is submitted.
type confirmedRekeyNet struct {
	account, plugin crypto.Account
	target          types.Address
	genesis         []byte
	failAfterSubmit bool

	mu        sync.Mutex
	submitted bool
}

func newConfirmedRekeyNet(t *testing.T, failAfterSubmit bool) (*confirmedRekeyNet, *Engine) {
	t.Helper()
	n := &confirmedRekeyNet{
		account: crypto.GenerateAccount(), plugin: crypto.GenerateAccount(),
		target: crypto.GenerateAccount().Address, failAfterSubmit: failAfterSubmit,
	}
	var err error
	if n.genesis, err = base64.StdEncoding.DecodeString(config.AlgorandTestnetGenesisHash); err != nil {
		t.Fatal(err)
	}
	signer := httptest.NewServer(n.serveSigner(t))
	t.Cleanup(signer.Close)
	node := httptest.NewServer(http.HandlerFunc(n.serveNode))
	t.Cleanup(node.Close)
	client, err := algod.MakeClient(node.URL, "")
	if err != nil {
		t.Fatalf("algod.MakeClient() error = %v", err)
	}
	eng, err := NewEngine("testnet", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	eng.Connection.SignerClient = signerclient.NewSignerClient(signer.URL)
	return n, eng
}

func (n *confirmedRekeyNet) serveSigner(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/keys":
			keys := []signerapi.KeyInfo{{Address: n.account.Address.String(), KeyType: "ed25519", ValidRekeyTarget: true}}
			_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: len(keys), Keys: keys})
		case r.Method == http.MethodGet && r.URL.Path == "/status":
			_ = json.NewEncoder(w).Encode(signerapi.StatusResponse{State: "unlocked", ReadyForSigning: true, KeyCount: 1})
		case r.Method == http.MethodPost && r.URL.Path == "/plan":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			planned := make([]types.Transaction, len(req.Requests))
			for i, item := range req.Requests {
				txn, err := txnutil.DecodePrefixedHex(item.TxnBytesHex)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				planned[i] = txn
			}
			groupID, err := crypto.ComputeGroupID(planned)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			encoded := make([]string, len(planned))
			for i := range planned {
				planned[i].Group = groupID
				encoded[i] = txnutil.EncodeWithPrefixHex(planned[i])
			}
			_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{
				Transactions: encoded,
				Mutations: &signerapi.MutationReport{
					GroupIDChanged: true, OriginalCount: len(planned), FinalCount: len(planned),
					ForeignCount: 1, Reason: "foreign",
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/sign":
			var req signerapi.GroupSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			signed := make([]string, len(req.Requests))
			for i, item := range req.Requests {
				if item.SignedTxnHex != "" {
					signed[i] = item.SignedTxnHex
					continue
				}
				txn, err := txnutil.DecodePrefixedHex(item.TxnBytesHex)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				_, raw, err := signing.SignTransactionWithKey(n.account.PrivateKey, txn)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				signed[i] = hex.EncodeToString(raw)
			}
			_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed})
		default:
			t.Errorf("unexpected signer request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}
}

func (n *confirmedRekeyNet) serveNode(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v2/transactions/params":
		_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
			ConsensusVersion: string(protocol.ConsensusV43), MinFee: 1000, LastRound: 100,
			GenesisId: "testnet-v1.0", GenesisHash: n.genesis,
		})
	case strings.HasPrefix(r.URL.Path, "/v2/accounts/"):
		if n.submitted && n.failAfterSubmit {
			http.Error(w, `{"message":"node unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		address := strings.TrimPrefix(r.URL.Path, "/v2/accounts/")
		account := models.Account{Address: address, Amount: 10_000_000, MinBalance: 100_000, Status: "Offline"}
		if n.submitted && address == n.account.Address.String() {
			account.AuthAddr = n.target.String()
		}
		_ = json.NewEncoder(w).Encode(account)
	case r.Method == http.MethodPost && r.URL.Path == "/v2/transactions":
		n.submitted = true
		_ = json.NewEncoder(w).Encode(map[string]string{"txId": "SUBMITTED"})
	case r.URL.Path == "/v2/status":
		_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 100})
	case strings.HasPrefix(r.URL.Path, "/v2/status/wait-for-block-after/"):
		_ = json.NewEncoder(w).Encode(models.NodeStatus{LastRound: 101})
	case strings.HasPrefix(r.URL.Path, "/v2/transactions/pending/"):
		w.Header().Set("Content-Type", "application/msgpack")
		_, _ = w.Write(msgpack.Encode(models.PendingTransactionInfoResponse{ConfirmedRound: 101}))
	default:
		http.NotFound(w, r)
	}
}

func (n *confirmedRekeyNet) payment(t *testing.T, sender types.Address, note string) types.Transaction {
	t.Helper()
	txn, err := transaction.MakePaymentTxn(sender.String(), sender.String(), 0, []byte(note), "", types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 100, LastRoundValid: 1100, GenesisHash: n.genesis, GenesisID: "testnet-v1.0", FlatFee: true,
	})
	if err != nil {
		t.Fatalf("make payment: %v", err)
	}
	return txn
}

// rekey is account's transaction that hands it to target.
func (n *confirmedRekeyNet) rekey(t *testing.T) types.Transaction {
	t.Helper()
	txn := n.payment(t, n.account.Address, "rekey")
	txn.RekeyTo = n.target
	return txn
}

// pregrouped is account's rekey and a payment, grouped and signed by
// account, as a plugin hands a pregrouped-signed group over.
func (n *confirmedRekeyNet) pregrouped(t *testing.T) *PregroupedSignedGroup {
	t.Helper()
	txns := []types.Transaction{n.rekey(t), n.payment(t, n.account.Address, "pay")}
	groupID, err := crypto.ComputeGroupID(txns)
	if err != nil {
		t.Fatalf("compute group id: %v", err)
	}
	encoded := make([]string, len(txns))
	for i := range txns {
		txns[i].Group = groupID
		_, raw, err := signing.SignTransactionWithKey(n.account.PrivateKey, txns[i])
		if err != nil {
			t.Fatalf("sign txn %d: %v", i, err)
		}
		encoded[i] = base64.StdEncoding.EncodeToString(raw)
	}
	group, err := DecodePregroupedSigned(encoded)
	if err != nil {
		t.Fatalf("DecodePregroupedSigned() error = %v", err)
	}
	return group
}

// signPluginSlots signs each plugin slot with the plugin account's key.
func (n *confirmedRekeyNet) signPluginSlots(requests []PluginSlotSignRequest) ([]PluginSlotSigned, error) {
	out := make([]PluginSlotSigned, len(requests))
	for i, request := range requests {
		raw, err := base64.StdEncoding.DecodeString(request.Encoded)
		if err != nil {
			return nil, err
		}
		var txn types.Transaction
		if err := msgpack.Decode(raw, &txn); err != nil {
			return nil, err
		}
		_, signed, err := signing.SignTransactionWithKey(n.plugin.PrivateKey, txn)
		if err != nil {
			return nil, err
		}
		out[i] = PluginSlotSigned{Index: request.Index, Encoded: base64.StdEncoding.EncodeToString(signed)}
	}
	return out, nil
}

// confirmedRekeyPaths submits a rekey of the network's account through each
// engine submission path. Each returns the result's auth refresh warning.
func confirmedRekeyPaths() map[string]func(*testing.T, *confirmedRekeyNet, *Engine) (string, error) {
	ctx := context.Background()
	return map[string]func(*testing.T, *confirmedRekeyNet, *Engine) (string, error){
		"single transaction": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			result, err := eng.SignAndSubmit(ctx, &TransactionPrepResult{Transaction: n.rekey(t)}, LsigArgs{}, true)
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
		"group": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			result, err := eng.SignAndSubmitGroup(ctx, []types.Transaction{n.rekey(t)}, LsigArgs{})
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
		"transaction file": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			result, err := eng.SignAndSubmitTransactions(ctx, []types.Transaction{n.rekey(t)}, true)
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
		"atomic group": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			result, err := eng.SignAndSubmitAtomic(ctx, &AtomicPrepResult{Transactions: []types.Transaction{n.rekey(t)}}, LsigArgs{}, true)
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
		"prepared group": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			group := &PreparedGroup{Entries: []PreparedGroupEntry{{Transaction: n.rekey(t)}}}
			result, err := eng.ExecutePreparedGroup(ctx, group, LsigArgs{}, true)
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
		"pregrouped-signed plugin group": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			result, err := eng.SubmitPregroupedSigned(ctx, n.pregrouped(t))
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
		"presign-plan plugin group": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) (string, error) {
			txns := []types.Transaction{n.payment(t, n.plugin.Address, "plugin"), n.rekey(t)}
			refs := map[string]string{n.plugin.Address.String(): "plugin-ref"}
			result, err := eng.SignAndSubmitWithPluginSigners(ctx, txns, refs, nil, n.signPluginSlots, LsigArgs{})
			if result == nil {
				return "", err
			}
			return result.AuthRefreshWarning, err
		},
	}
}

// A confirmed rekey moves the sender's on-chain authorizer, and every
// submission path, not only the single-transaction one, then overwrites the
// sender's auth-cache entry, which was filled with the old authorizer before
// signing. A later send names the new one.
func TestEveryConfirmedSubmissionRefreshesARekeyedSender(t *testing.T) {
	for name, submit := range confirmedRekeyPaths() {
		t.Run(name, func(t *testing.T) {
			n, eng := newConfirmedRekeyNet(t, false)
			eng.AuthCache.AuthAddresses = map[string]string{n.account.Address.String(): ""}
			if _, err := submit(t, n, eng); err != nil {
				t.Fatalf("submission error = %v", err)
			}
			if got, ok := eng.AuthCache.GetAuthAddress(n.account.Address.String()); !ok || got != n.target.String() {
				t.Fatalf("auth cache entry after the rekey = (%q, %v), want (%q, true)", got, ok, n.target)
			}
		})
	}
}

// The rekey has committed when the refresh after it fails, so the failure is
// a warning on the result of every path, not an error.
func TestAFailedRefreshAfterAConfirmedRekeyIsAWarning(t *testing.T) {
	for name, submit := range confirmedRekeyPaths() {
		t.Run(name, func(t *testing.T) {
			n, eng := newConfirmedRekeyNet(t, true)
			eng.AuthCache.AuthAddresses = map[string]string{n.account.Address.String(): ""}
			warning, err := submit(t, n, eng)
			if err != nil {
				t.Fatalf("submission error = %v, want a warning only", err)
			}
			if !strings.Contains(warning, "failed to refresh auth address for "+n.account.Address.String()) {
				t.Fatalf("auth refresh warning = %q, want the failed refresh named", warning)
			}
		})
	}
}

// A plugin group may rekey the plugin's own account, which the client does not
// track: the refresh after a confirmed group leaves it out of the auth cache,
// and refreshes only the client's own rekeying sender.
func TestTheRefreshAfterAPluginGroupLeavesThePluginsAccountsAlone(t *testing.T) {
	ctx := context.Background()
	for name, submit := range map[string]func(*testing.T, *confirmedRekeyNet, *Engine) error{
		"pregrouped-signed": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) error {
			pluginRekey := n.payment(t, n.plugin.Address, "plugin rekey")
			pluginRekey.RekeyTo = n.target
			txns := []types.Transaction{pluginRekey, n.rekey(t)}
			keys := []crypto.Account{n.plugin, n.account}
			groupID, err := crypto.ComputeGroupID(txns)
			if err != nil {
				t.Fatalf("compute group id: %v", err)
			}
			encoded := make([]string, len(txns))
			for i := range txns {
				txns[i].Group = groupID
				_, raw, err := signing.SignTransactionWithKey(keys[i].PrivateKey, txns[i])
				if err != nil {
					t.Fatalf("sign txn %d: %v", i, err)
				}
				encoded[i] = base64.StdEncoding.EncodeToString(raw)
			}
			group, err := DecodePregroupedSigned(encoded)
			if err != nil {
				t.Fatalf("DecodePregroupedSigned() error = %v", err)
			}
			_, err = eng.SubmitPregroupedSigned(ctx, group)
			return err
		},
		"presign-plan": func(t *testing.T, n *confirmedRekeyNet, eng *Engine) error {
			pluginRekey := n.payment(t, n.plugin.Address, "plugin rekey")
			pluginRekey.RekeyTo = n.target
			txns := []types.Transaction{pluginRekey, n.rekey(t)}
			refs := map[string]string{n.plugin.Address.String(): "plugin-ref"}
			_, err := eng.SignAndSubmitWithPluginSigners(ctx, txns, refs, nil, n.signPluginSlots, LsigArgs{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			n, eng := newConfirmedRekeyNet(t, false)
			eng.AuthCache.AuthAddresses = map[string]string{n.account.Address.String(): ""}
			if err := submit(t, n, eng); err != nil {
				t.Fatalf("submission error = %v", err)
			}
			if got, ok := eng.AuthCache.GetAuthAddress(n.plugin.Address.String()); ok {
				t.Fatalf("plugin account's auth cache entry = %q, want none", got)
			}
			if got, ok := eng.AuthCache.GetAuthAddress(n.account.Address.String()); !ok || got != n.target.String() {
				t.Fatalf("auth cache entry after the rekey = (%q, %v), want (%q, true)", got, ok, n.target)
			}
		})
	}
}
