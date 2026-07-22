// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

func presignTestTxn(t *testing.T, sender, note string) types.Transaction {
	t.Helper()
	sp := types.SuggestedParams{
		Fee: 1000, FirstRoundValid: 10, LastRoundValid: 1010,
		GenesisHash: make([]byte, 32), GenesisID: "presign-test", FlatFee: true,
	}
	txn, err := transaction.MakePaymentTxn(sender, sender, 0, []byte(note), "", sp)
	if err != nil {
		t.Fatalf("make txn: %v", err)
	}
	return txn
}

func TestAssertSlotArtifactFieldsPreserved(t *testing.T) {
	acct := crypto.GenerateAccount()
	draft := presignTestTxn(t, acct.Address.String(), "deposit")

	t.Run("only group and fee changed -> ok", func(t *testing.T) {
		canonical := draft
		canonical.Group = types.Digest{1, 2, 3}
		canonical.Fee = 5000
		if err := assertSlotArtifactFieldsPreserved(draft, canonical); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*types.Transaction)
	}{
		{"sender", func(tx *types.Transaction) { tx.Sender = crypto.GenerateAccount().Address }},
		{"firstValid", func(tx *types.Transaction) { tx.FirstValid++ }},
		{"lastValid", func(tx *types.Transaction) { tx.LastValid++ }},
		{"amount", func(tx *types.Transaction) { tx.Amount++ }},
		{"lease", func(tx *types.Transaction) { tx.Lease = [32]byte{9} }},
		{"genesisHash", func(tx *types.Transaction) { tx.GenesisHash = types.Digest{7} }},
	} {
		t.Run(tc.name+" changed -> error", func(t *testing.T) {
			canonical := draft
			canonical.Group = types.Digest{1}
			canonical.Fee = 5000
			tc.mutate(&canonical)
			if err := assertSlotArtifactFieldsPreserved(draft, canonical); err == nil {
				t.Fatalf("expected error when %s changed", tc.name)
			}
		})
	}
}

func TestAssertPluginSignersMatched(t *testing.T) {
	a := crypto.GenerateAccount()
	b := crypto.GenerateAccount()
	txns := []types.Transaction{
		presignTestTxn(t, a.Address.String(), "a"),
		presignTestTxn(t, b.Address.String(), "b"),
	}

	t.Run("all declared signers match -> ok", func(t *testing.T) {
		refs := map[string]string{a.Address.String(): "ref-a"}
		if err := assertPluginSignersMatched(txns, refs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("unused declared signer -> error", func(t *testing.T) {
		bogus := crypto.GenerateAccount()
		refs := map[string]string{
			a.Address.String():     "ref-a",
			bogus.Address.String(): "ref-bogus", // matches no txn
		}
		if err := assertPluginSignersMatched(txns, refs); err == nil {
			t.Fatal("expected error when a declared signer matches no transaction")
		}
	})
}

func TestValidatePluginSignedSlot(t *testing.T) {
	acct := crypto.GenerateAccount()
	canonical := presignTestTxn(t, acct.Address.String(), "canonical")
	canonical.Group = types.Digest{4, 2}

	sign := func(txn types.Transaction) string {
		_, raw, err := crypto.SignTransaction(acct.PrivateKey, txn)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}

	t.Run("signs exact canonical -> ok", func(t *testing.T) {
		hexStr, err := validatePluginSignedSlot(canonical, sign(canonical))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hexStr == "" {
			t.Fatal("expected non-empty signed hex")
		}
	})

	t.Run("signs a different txn -> rejected", func(t *testing.T) {
		other := canonical
		other.Amount++ // substitution
		if _, err := validatePluginSignedSlot(canonical, sign(other)); err == nil {
			t.Fatal("expected substitution to be rejected")
		}
	})

	t.Run("bad base64 -> error", func(t *testing.T) {
		if _, err := validatePluginSignedSlot(canonical, "!!!"); err == nil {
			t.Fatal("expected error for bad base64")
		}
	})

	t.Run("bad msgpack -> error", func(t *testing.T) {
		if _, err := validatePluginSignedSlot(canonical, base64.StdEncoding.EncodeToString([]byte("nope"))); err == nil {
			t.Fatal("expected error for bad msgpack")
		}
	})
}

func TestSignAndSubmitWithPluginSignersSimulatesSignedGroupClientSide(t *testing.T) {
	pluginAccount := crypto.GenerateAccount()
	managedAccount := crypto.GenerateAccount()
	txns := []types.Transaction{
		presignTestTxn(t, pluginAccount.Address.String(), "plugin"),
		presignTestTxn(t, managedAccount.Address.String(), "managed"),
	}

	var planCalls, signCalls, signerSimulateCalls atomic.Int32
	var signedMu sync.Mutex
	var finalSignedHex []string
	signerMux := http.NewServeMux()
	signerMux.HandleFunc("/plan", func(w http.ResponseWriter, r *http.Request) {
		planCalls.Add(1)
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
		if _, err := signing.AssignGroupID(planned); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		encoded := make([]string, len(planned))
		for i, txn := range planned {
			encoded[i] = txnutil.EncodeWithPrefixHex(txn)
		}
		_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{Transactions: encoded})
	})
	signerMux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		signCalls.Add(1)
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
			_, raw, err := crypto.SignTransaction(managedAccount.PrivateKey, txn)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			signed[i] = hex.EncodeToString(raw)
		}
		signedMu.Lock()
		finalSignedHex = append([]string(nil), signed...)
		signedMu.Unlock()
		_ = json.NewEncoder(w).Encode(signerapi.GroupSignResponse{Signed: signed})
	})
	signerMux.HandleFunc("/simulate", func(w http.ResponseWriter, r *http.Request) {
		signerSimulateCalls.Add(1)
		http.NotFound(w, r)
	})
	signerServer := httptest.NewServer(signerMux)
	defer signerServer.Close()

	var simulateReq models.SimulateRequest
	algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/simulate" {
			t.Fatalf("algod path = %s, want /v2/transactions/simulate", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read simulate request: %v", err)
		}
		if err := msgpack.Decode(body, &simulateReq); err != nil {
			t.Fatalf("decode simulate request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.SimulateResponse{
			LastRound: 11,
			TxnGroups: []models.SimulateTransactionGroupResult{{
				TxnResults: make([]models.SimulateTransactionResult, len(simulateReq.TxnGroups[0].Txns)),
			}},
		})
	}))
	defer algodServer.Close()
	algodClient, err := algod.MakeClient(algodServer.URL, "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}

	authCache := cache.NewAuthAddressCache()
	engine, err := NewEngine("test", WithAlgodClient(algodClient), WithAuthCache(authCache))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	engine.Connection.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")
	engine.Simulate = true

	var pluginCalls atomic.Int32
	result, err := engine.SignAndSubmitWithPluginSigners(
		context.Background(),
		txns,
		map[string]string{pluginAccount.Address.String(): "plugin-ref"},
		map[string]int{pluginAccount.Address.String(): 0},
		func(requests []PluginSlotSignRequest) ([]PluginSlotSigned, error) {
			pluginCalls.Add(1)
			out := make([]PluginSlotSigned, len(requests))
			for i, request := range requests {
				rawTxn, err := base64.StdEncoding.DecodeString(request.Encoded)
				if err != nil {
					return nil, err
				}
				var txn types.Transaction
				if err := msgpack.Decode(rawTxn, &txn); err != nil {
					return nil, err
				}
				_, signed, err := crypto.SignTransaction(pluginAccount.PrivateKey, txn)
				if err != nil {
					return nil, err
				}
				out[i] = PluginSlotSigned{Index: request.Index, Encoded: base64.StdEncoding.EncodeToString(signed)}
			}
			return out, nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("SignAndSubmitWithPluginSigners() error = %v", err)
	}
	if planCalls.Load() != 1 || pluginCalls.Load() != 1 || signCalls.Load() != 1 {
		t.Fatalf("plan/plugin/sign calls = %d/%d/%d, want 1/1/1", planCalls.Load(), pluginCalls.Load(), signCalls.Load())
	}
	if signerSimulateCalls.Load() != 0 {
		t.Fatalf("signer /simulate calls = %d, want 0", signerSimulateCalls.Load())
	}
	if len(result.TxIDs) != 2 || len(simulateReq.TxnGroups) != 1 || len(simulateReq.TxnGroups[0].Txns) != 2 {
		t.Fatalf("result/simulate shape = %d/%#v, want two transactions", len(result.TxIDs), simulateReq.TxnGroups)
	}
	if simulateReq.AllowEmptySignatures || simulateReq.FixSigners {
		t.Fatal("plugin signed simulation enabled empty-signature overrides")
	}
	signedMu.Lock()
	wantSigned := append([]string(nil), finalSignedHex...)
	signedMu.Unlock()
	for i, signedHex := range wantSigned {
		want, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatalf("decode signed position %d: %v", i, err)
		}
		if got := msgpack.Encode(simulateReq.TxnGroups[0].Txns[i]); !bytes.Equal(got, want) {
			t.Fatalf("simulated position %d differs from final /sign bytes", i)
		}
	}
}

func TestSignAndSubmitWithPluginSignersRejectsNilAlgodBeforeSigning(t *testing.T) {
	pluginAccount := crypto.GenerateAccount()
	managedAccount := crypto.GenerateAccount()
	txns := []types.Transaction{
		presignTestTxn(t, pluginAccount.Address.String(), "plugin"),
		presignTestTxn(t, managedAccount.Address.String(), "managed"),
	}
	engine, err := NewEngine("test")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	engine.Simulate = true
	var pluginCalls atomic.Int32
	_, err = engine.SignAndSubmitWithPluginSigners(
		context.Background(),
		txns,
		map[string]string{pluginAccount.Address.String(): "plugin-ref"},
		nil,
		func(requests []PluginSlotSignRequest) ([]PluginSlotSigned, error) {
			pluginCalls.Add(1)
			return nil, nil
		},
		nil,
	)
	if !errors.Is(err, ErrNoAlgodClient) {
		t.Fatalf("SignAndSubmitWithPluginSigners(nil algod) error = %v, want ErrNoAlgodClient", err)
	}
	if pluginCalls.Load() != 0 {
		t.Fatalf("plugin signing calls = %d, want 0", pluginCalls.Load())
	}
}
