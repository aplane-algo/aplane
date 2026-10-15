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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/protocol"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/pkg/signerapi"
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

// presignPlan builds a planned group from drafts the way the planner does: the
// first slot's fee raised by delta, appended canonical dummies, and the group id
// over the final group. It returns the planned group and its mutation report.
func presignPlan(t *testing.T, drafts []types.Transaction, delta uint64, dummies int) ([]types.Transaction, *signerapi.MutationReport) {
	t.Helper()
	planned := append([]types.Transaction(nil), drafts...)
	planned[0].Fee += types.MicroAlgos(delta)
	if dummies > 0 {
		first := drafts[0]
		extra, err := signing.CreateDummyTransactions(dummies, types.SuggestedParams{
			Fee: first.Fee, FirstRoundValid: first.FirstValid, LastRoundValid: first.LastValid,
			GenesisID: first.GenesisID, GenesisHash: first.GenesisHash[:], FlatFee: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		planned = append(planned, extra...)
	}
	gid, err := crypto.ComputeGroupID(planned)
	if err != nil {
		t.Fatal(err)
	}
	for i := range planned {
		planned[i].Group = gid
	}
	report := &signerapi.MutationReport{
		DummiesAdded: dummies, GroupIDChanged: true, TotalFeesDelta: int(delta),
		OriginalCount: len(drafts), FinalCount: len(planned), ForeignCount: 1,
	}
	if delta > 0 {
		report.FeesModified = []int{0}
	}
	return planned, report
}

// regroupPlan re-stamps the group id over planned after a test edit, so the
// check under test is the edit itself rather than a stale group id.
func regroupPlan(t *testing.T, planned []types.Transaction) {
	t.Helper()
	ungrouped := append([]types.Transaction(nil), planned...)
	for i := range ungrouped {
		ungrouped[i].Group = types.Digest{}
	}
	gid, err := crypto.ComputeGroupID(ungrouped)
	if err != nil {
		t.Fatal(err)
	}
	for i := range planned {
		planned[i].Group = gid
	}
}

func TestValidatePluginPlan(t *testing.T) {
	plugin := crypto.GenerateAccount()
	managed := crypto.GenerateAccount()
	drafts := []types.Transaction{
		presignTestTxn(t, managed.Address.String(), "funder"),
		presignTestTxn(t, plugin.Address.String(), "deposit"),
	}
	refs := map[string]string{plugin.Address.String(): "ref"}

	t.Run("group id, reported fee increase, canonical dummies -> ok", func(t *testing.T) {
		planned, report := presignPlan(t, drafts, 2000, 2)
		if err := validatePluginPlan(drafts, planned, report, refs); err != nil {
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
		{"unreported fee", func(tx *types.Transaction) { tx.Fee += 1000 }},
	} {
		t.Run("plugin slot "+tc.name+" changed -> error", func(t *testing.T) {
			planned, report := presignPlan(t, drafts, 0, 0)
			tc.mutate(&planned[1])
			regroupPlan(t, planned)
			err := validatePluginPlan(drafts, planned, report, refs)
			if err == nil || !strings.Contains(err.Error(), "plugin slot 1") {
				t.Fatalf("expected plugin slot rejection when %s changed, got %v", tc.name, err)
			}
		})
	}

	reject := func(name, want string, edit func([]types.Transaction, *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport)) {
		t.Run(name, func(t *testing.T) {
			planned, report := presignPlan(t, drafts, 2000, 1)
			planned, report = edit(planned, report)
			err := validatePluginPlan(drafts, planned, report, refs)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want an error containing %q", err, want)
			}
		})
	}
	reject("fee decrease", "decreased the fee", func(p []types.Transaction, r *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport) {
		p[0].Fee = drafts[0].Fee - 1
		r.TotalFeesDelta = 0
		regroupPlan(t, p)
		return p, r
	})
	reject("wrong total fee delta", "total_fees_delta", func(p []types.Transaction, r *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport) {
		r.TotalFeesDelta = 1
		return p, r
	})
	reject("dummies without a report", "without a mutation report", func(p []types.Transaction, r *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport) {
		return p, nil
	})
	reject("dummy count mismatch", "dummies_added", func(p []types.Transaction, r *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport) {
		r.DummiesAdded = 2
		return p, r
	})
	reject("non-canonical group id", "canonical group ID", func(p []types.Transaction, r *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport) {
		for i := range p {
			p[i].Group = types.Digest{1}
		}
		return p, r
	})
	reject("non-canonical dummy", "canonical resource dummy", func(p []types.Transaction, r *signerapi.MutationReport) ([]types.Transaction, *signerapi.MutationReport) {
		p[2].Fee = 1000
		regroupPlan(t, p)
		return p, r
	})
}

func TestVerifySignedAgainstPlan(t *testing.T) {
	acct := crypto.GenerateAccount()
	canonical := []types.Transaction{
		presignTestTxn(t, acct.Address.String(), "managed"),
		presignTestTxn(t, acct.Address.String(), "plugin"),
	}
	sign := func(txn types.Transaction) []byte {
		_, raw, err := crypto.SignTransaction(acct.PrivateKey, txn)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	pluginSigned := sign(canonical[1])
	passthrough := map[int]string{1: hex.EncodeToString(pluginSigned)}

	if err := verifySignedAgainstPlan(canonical, passthrough, [][]byte{sign(canonical[0]), pluginSigned}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	other := canonical[0]
	other.Amount++
	if err := verifySignedAgainstPlan(canonical, passthrough, [][]byte{sign(other), pluginSigned}); err == nil || !strings.Contains(err.Error(), "different transaction at slot 0") {
		t.Fatalf("substituted managed slot: got %v", err)
	}
	if err := verifySignedAgainstPlan(canonical, passthrough, [][]byte{sign(canonical[0]), sign(canonical[0])}); err == nil || !strings.Contains(err.Error(), "altered passthrough slot 1") {
		t.Fatalf("altered passthrough slot: got %v", err)
	}
	if err := verifySignedAgainstPlan(canonical, passthrough, [][]byte{sign(canonical[0])}); err == nil {
		t.Fatal("short response accepted")
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
		hexStr, err := validatePluginSignedSlot(canonical, sign(canonical), PluginSlotAuthorization{})
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
		if _, err := validatePluginSignedSlot(canonical, sign(other), PluginSlotAuthorization{}); err == nil {
			t.Fatal("expected substitution to be rejected")
		}
	})

	t.Run("bad base64 -> error", func(t *testing.T) {
		if _, err := validatePluginSignedSlot(canonical, "!!!", PluginSlotAuthorization{}); err == nil {
			t.Fatal("expected error for bad base64")
		}
	})

	t.Run("bad msgpack -> error", func(t *testing.T) {
		if _, err := validatePluginSignedSlot(canonical, base64.StdEncoding.EncodeToString([]byte("nope")), PluginSlotAuthorization{}); err == nil {
			t.Fatal("expected error for bad msgpack")
		}
	})

	logicSigned := func(logic []byte, args [][]byte) string {
		return base64.StdEncoding.EncodeToString(msgpack.Encode(types.SignedTxn{
			Txn:  canonical,
			Lsig: types.LogicSig{Logic: logic, Args: args},
		}))
	}
	t.Run("LogicSig authorization matches declaration", func(t *testing.T) {
		resources := &signerapi.LogicSigResourceUsage{ProgramBytes: 3, ArgumentBytes: 2, MaxOpcodeCost: 20_000}
		if _, err := validatePluginSignedSlot(canonical, logicSigned([]byte{1, 2, 3}, [][]byte{{4, 5}}), PluginSlotAuthorization{LsigResources: resources}); err != nil {
			t.Fatalf("validatePluginSignedSlot() error = %v", err)
		}
	})
	t.Run("undeclared LogicSig authorization rejects", func(t *testing.T) {
		_, err := validatePluginSignedSlot(canonical, logicSigned([]byte{1}, nil), PluginSlotAuthorization{})
		if err == nil || !strings.Contains(err.Error(), "without declaring lsig_resources") {
			t.Fatalf("validatePluginSignedSlot() error = %v, want declaration rejection", err)
		}
	})
	t.Run("LogicSig size mismatch rejects", func(t *testing.T) {
		resources := &signerapi.LogicSigResourceUsage{ProgramBytes: 2, MaxOpcodeCost: 20_000}
		_, err := validatePluginSignedSlot(canonical, logicSigned([]byte{1}, nil), PluginSlotAuthorization{LsigResources: resources})
		if err == nil || !strings.Contains(err.Error(), "program_bytes") {
			t.Fatalf("validatePluginSignedSlot() error = %v, want program mismatch", err)
		}
	})
	t.Run("native-PQ authorization matches declaration", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString(msgpack.Encode(types.SignedTxn{
			Txn: canonical,
			PQsig: types.PQSig{
				Scheme:    types.PQScheme{'f', '1'},
				Signature: []byte{1},
			},
		}))
		if _, err := validatePluginSignedSlot(canonical, encoded, PluginSlotAuthorization{PQScheme: signerapi.PQSchemeFalcon1024}); err != nil {
			t.Fatalf("validatePluginSignedSlot() error = %v", err)
		}
	})
	t.Run("unsigned ordinary authorization rejects", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: canonical}))
		_, err := validatePluginSignedSlot(canonical, encoded, PluginSlotAuthorization{})
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Fatalf("validatePluginSignedSlot() error = %v, want missing-authorization rejection", err)
		}
	})
}

func TestSignAndSubmitWithPluginSignersSimulatesSignedGroupClientSide(t *testing.T) {
	pluginAddress, err := signing.DummyAddress()
	if err != nil {
		t.Fatalf("signing.DummyAddress() error = %v", err)
	}
	managedAccount := crypto.GenerateAccount()
	pluginProgram := append([]byte(nil), signing.EmbeddedDummyTealTok...)
	pluginResources := &signerapi.LogicSigResourceUsage{
		ProgramBytes:  uint64(len(pluginProgram)),
		ArgumentBytes: 0,
		MaxOpcodeCost: 20_000,
	}
	txns := []types.Transaction{
		presignTestTxn(t, pluginAddress.String(), "plugin"),
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
		if got := req.Requests[0].LsigResources; got == nil || *got != *pluginResources {
			http.Error(w, fmt.Sprintf("plugin LogicSig resources = %#v, want %#v", got, pluginResources), http.StatusBadRequest)
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
		for i := range planned {
			planned[i].Group = groupID
		}
		encoded := make([]string, len(planned))
		for i, txn := range planned {
			encoded[i] = txnutil.EncodeWithPrefixHex(txn)
		}
		_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{
			Transactions: encoded,
			Mutations: &signerapi.MutationReport{
				GroupIDChanged: true, OriginalCount: len(planned), FinalCount: len(planned),
				ForeignCount: 1, Reason: "foreign",
			},
		})
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
				if i == 0 && (item.LsigResources == nil || *item.LsigResources != *pluginResources) {
					http.Error(w, fmt.Sprintf("final plugin LogicSig resources = %#v, want %#v", item.LsigResources, pluginResources), http.StatusBadRequest)
					return
				}
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
		if r.URL.Path == "/v2/transactions/params" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(models.TransactionParametersResponse{
				ConsensusVersion: string(protocol.ConsensusV42),
			})
			return
		}
		if r.URL.Path != "/v2/transactions/simulate" {
			t.Fatalf("algod path = %s, want params or simulate", r.URL.Path)
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
	engine.Connection.SignerClient = signerclient.NewSignerClient(signerServer.URL)
	engine.Simulate = true

	var pluginCalls atomic.Int32
	result, err := engine.SignAndSubmitWithPluginSigners(
		context.Background(),
		txns,
		map[string]string{pluginAddress.String(): "plugin-ref"},
		map[string]PluginSlotAuthorization{
			pluginAddress.String(): {LsigResources: pluginResources},
		},
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
				signed := msgpack.Encode(types.SignedTxn{
					Txn:  txn,
					Lsig: types.LogicSig{Logic: pluginProgram},
				})
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

func TestSignAndSubmitWithPluginSignersRejectsUnsupportedConsensusBeforePlanning(t *testing.T) {
	pluginAccount := crypto.GenerateAccount()
	managedAccount := crypto.GenerateAccount()
	txns := []types.Transaction{
		presignTestTxn(t, pluginAccount.Address.String(), "plugin"),
		presignTestTxn(t, managedAccount.Address.String(), "managed"),
	}
	client, server := consensusTestAlgod(t, string(protocol.ConsensusV41), nil)
	defer server.Close()
	engine, err := NewEngine("test", WithAlgodClient(client))
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
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
	if err == nil || !strings.Contains(err.Error(), "network consensus") {
		t.Fatalf("SignAndSubmitWithPluginSigners() error = %v, want unsupported-consensus rejection", err)
	}
	if pluginCalls.Load() != 0 {
		t.Fatalf("plugin signing calls = %d, want 0", pluginCalls.Load())
	}
}
