// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package manager

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/plugin/discovery"
	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
	"github.com/aplane-algo/aplane/internal/plugin/manifest"
)

// TestPresignSignTransactionsRoundTrip validates the pre-sign planning round trip
// at the manager boundary: execute returns a draft + PluginSigners, then the host
// calls signTransactions on the SAME running instance and the plugin signs the
// canonical bytes with the key it owns — without exporting that key.
func TestPresignSignTransactionsRoundTrip(t *testing.T) {
	acct := crypto.GenerateAccount()

	sp := types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 1, LastRoundValid: 1001,
		GenesisHash: make([]byte, 32), GenesisID: "presign-test", FlatFee: true,
	}
	// Stands in for the canonical bytes /plan would produce in the real flow.
	canonical, err := transaction.MakePaymentTxn(acct.Address.String(), acct.Address.String(), 0, []byte("canonical"), "", sp)
	if err != nil {
		t.Fatalf("make canonical txn: %v", err)
	}
	canonicalB64 := base64.StdEncoding.EncodeToString(msgpack.Encode(canonical))

	inst := newPresignPluginInstance(t, acct, canonicalB64)

	m := NewManager()
	m.instances["presign"] = inst // inject so StartPlugin returns this instance

	// execute -> draft + pluginSigners
	exec, err := m.ExecuteCommand("presign", "deposit", nil, jsonrpc.Context{})
	if err != nil {
		t.Fatalf("ExecuteCommand: %v", err)
	}
	if exec.GroupMode != jsonrpc.GroupModePresignPlan {
		t.Fatalf("groupMode = %q, want %q", exec.GroupMode, jsonrpc.GroupModePresignPlan)
	}
	if len(exec.PluginSigners) != 1 || exec.PluginSigners[0].Address != acct.Address.String() {
		t.Fatalf("pluginSigners = %#v", exec.PluginSigners)
	}
	if exec.PluginSigners[0].Kind != jsonrpc.PluginSignerKindCallback {
		t.Fatalf("signer kind = %q", exec.PluginSigners[0].Kind)
	}

	// signTransactions callback over the canonical bytes
	res, err := m.SignTransactions("presign", jsonrpc.SignTransactionsParams{
		Requests: []jsonrpc.SignTransactionRequest{{
			Index: 0, Address: acct.Address.String(), SignerRef: exec.PluginSigners[0].SignerRef, Encoded: canonicalB64,
		}},
	})
	if err != nil {
		t.Fatalf("SignTransactions: %v", err)
	}
	if len(res.Signed) != 1 || res.Signed[0].Index != 0 {
		t.Fatalf("signed = %#v", res.Signed)
	}

	rawSigned, err := base64.StdEncoding.DecodeString(res.Signed[0].Encoded)
	if err != nil {
		t.Fatalf("decode signed: %v", err)
	}
	var stxn types.SignedTxn
	if err := msgpack.Decode(rawSigned, &stxn); err != nil {
		t.Fatalf("decode signed txn: %v", err)
	}
	if stxn.Txn.Sender != acct.Address {
		t.Fatalf("signed txn sender = %s, want %s", stxn.Txn.Sender, acct.Address)
	}
	if stxn.Sig == (types.Signature{}) {
		t.Fatal("signed txn has no signature — plugin did not sign")
	}
}

func newPresignPluginInstance(t *testing.T, acct crypto.Account, canonicalB64 string) *Instance {
	t.Helper()
	serverToClientReader, serverToClientWriter := io.Pipe()
	clientToServerReader, clientToServerWriter := io.Pipe()
	inst := &Instance{
		Plugin:  &discovery.Plugin{Manifest: &manifest.Manifest{Name: "presign", Timeout: 5}},
		Client:  jsonrpc.NewClient(serverToClientReader, clientToServerWriter),
		Started: time.Now(),
	}
	inst.Client.Start()

	go func() {
		dec := json.NewDecoder(clientToServerReader)
		enc := json.NewEncoder(serverToClientWriter)
		for {
			var req jsonrpc.Request
			if err := dec.Decode(&req); err != nil {
				_ = clientToServerReader.Close()
				_ = serverToClientWriter.Close()
				return
			}
			resp := jsonrpc.Response{Jsonrpc: jsonrpc.Version, ID: req.ID}
			switch req.Method {
			case jsonrpc.MethodExecute:
				setResult(&resp, jsonrpc.ExecuteResult{
					Success:      true,
					GroupMode:    jsonrpc.GroupModePresignPlan,
					Transactions: []jsonrpc.TransactionIntent{{Type: jsonrpc.TransactionIntentRaw, Encoded: canonicalB64}},
					PluginSigners: []jsonrpc.PluginSigner{{
						Address: acct.Address.String(), Kind: jsonrpc.PluginSignerKindCallback, SignerRef: "ref-1",
					}},
				})
			case jsonrpc.MethodSignTransactions:
				var p jsonrpc.SignTransactionsParams
				_ = req.ParseParams(&p)
				var out jsonrpc.SignTransactionsResult
				for _, r := range p.Requests {
					raw, _ := base64.StdEncoding.DecodeString(r.Encoded)
					var txn types.Transaction
					_ = msgpack.Decode(raw, &txn)
					_, stx, _ := crypto.SignTransaction(acct.PrivateKey, txn)
					out.Signed = append(out.Signed, jsonrpc.SignedTxnEntry{
						Index: r.Index, Encoded: base64.StdEncoding.EncodeToString(stx),
					})
				}
				setResult(&resp, out)
			}
			if err := enc.Encode(resp); err != nil {
				return
			}
		}
	}()

	return inst
}

func setResult(resp *jsonrpc.Response, v interface{}) {
	raw, _ := json.Marshal(v)
	rm := json.RawMessage(raw)
	resp.Result = &rm
}
