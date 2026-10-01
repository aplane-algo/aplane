// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type guardedSimulationCapture struct {
	userRoleCalls     atomic.Int32
	cosignerRoleCalls atomic.Int32
	assembleCalls     atomic.Int32
	signerSimulateHit atomic.Int32

	// rejectSign makes /sign refuse the request, as a signer policy or
	// operator denial would. Set before the server starts; read-only after.
	rejectSign bool

	mu             sync.Mutex
	assembly       signerapi.AssemblyRequest
	assembledGroup []string
	events         []string
}

func (c *guardedSimulationCapture) record(event string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
}

func (c *guardedSimulationCapture) setAssembly(req signerapi.AssemblyRequest, signed []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.assembly = req
	c.assembledGroup = append([]string(nil), signed...)
}

func (c *guardedSimulationCapture) snapshot() (signerapi.AssemblyRequest, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assembly, append([]string(nil), c.assembledGroup...)
}

func (c *guardedSimulationCapture) eventSnapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.events...)
}

// newGuardedExecutableTestServer serves the normal guarded signing surface.
// It intentionally exposes no signer simulation behavior.
func newGuardedExecutableTestServer(t *testing.T, publicKeyHex string, capture *guardedSimulationCapture) *httptest.Server {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode cosigner public key: %v", err)
	}
	componentSelector, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Witness Key ID: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		capture.record("keys")
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:      componentSelector,
				PublicKeyHex: publicKeyHex,
				KeyType:      witness.Falcon1024V1,
				IsWitnessKey: true,
			}},
		})
	})
	mux.HandleFunc("/plan", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		transactions := make([]string, len(req.Requests))
		for i, request := range req.Requests {
			transactions[i] = request.TxnBytesHex
		}
		_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{Transactions: transactions})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch req.TargetKind() {
		case signerapi.ComponentTargetKindUser:
			capture.userRoleCalls.Add(1)
			capture.record("user")
		case signerapi.ComponentTargetKindBoundedBase:
			capture.record("base")
			resp := signerapi.ComponentResponse{RequestID: req.RequestID}
			for _, target := range req.Targets {
				resp.Components = append(resp.Components, signerapi.Component{
					TargetIndex: target.TargetIndex, Kind: target.Kind, AuthAddress: target.AuthAddress,
					BaseSignatures: []string{"aa"}, AssemblyReceipt: "bb", SignatureScheme: "aplane.falcon1024.v1",
				})
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		case signerapi.ComponentTargetKindCosigner:
			capture.cosignerRoleCalls.Add(1)
			capture.record("cosigner")
		default:
			http.Error(w, "unexpected component role", http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentResponse{
			RequestID:  req.RequestID,
			Components: make([]signerapi.Component, 0, len(req.Targets)),
		}
		for _, target := range req.Targets {
			resp.Components = append(resp.Components, signerapi.Component{
				TargetIndex:     target.TargetIndex,
				Kind:            target.Kind,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       hex.EncodeToString([]byte{byte(target.TargetIndex + 1)}),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		capture.record("sign")
		if capture.rejectSign {
			http.Error(w, "rejected by signer policy", http.StatusForbidden)
			return
		}
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := signerapi.GroupSignResponse{Signed: make([]string, len(req.Requests))}
		for i, request := range req.Requests {
			if mode, err := request.Mode(); err != nil || mode != signerapi.RequestModeSign {
				continue
			}
			txn, err := txnutil.DecodePrefixedHex(request.TxnBytesHex)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resp.Signed[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/sign/assemble", func(w http.ResponseWriter, r *http.Request) {
		capture.assembleCalls.Add(1)
		capture.record("assemble")
		var req signerapi.AssemblyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := req.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		group, err := canonical.DecodeGroupHex(req.GroupBytesHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signed := make([]string, len(group.Entries))
		for i, entry := range group.Entries {
			signed[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: entry.Txn}))
		}
		capture.setAssembly(req, signed)
		_ = json.NewEncoder(w).Encode(signerapi.AssemblyResponse{
			RequestID:   req.RequestID,
			SignedGroup: signed,
		})
	})
	mux.HandleFunc("/simulate", func(w http.ResponseWriter, r *http.Request) {
		capture.signerSimulateHit.Add(1)
		http.NotFound(w, r)
	})
	mux.HandleFunc("/simulate/guarded", func(w http.ResponseWriter, r *http.Request) {
		capture.signerSimulateHit.Add(1)
		http.NotFound(w, r)
	})
	return httptest.NewServer(mux)
}

func newGuardedAlgodSimulationClient(t *testing.T, failure string, captured *models.SimulateRequest) (*algod.Client, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions/simulate" {
			t.Fatalf("algod path = %s, want /v2/transactions/simulate", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read simulate request: %v", err)
		}
		if err := msgpack.Decode(body, captured); err != nil {
			t.Fatalf("decode simulate request: %v", err)
		}
		result := models.SimulateTransactionGroupResult{
			FailureMessage: failure,
			TxnResults:     make([]models.SimulateTransactionResult, len(captured.TxnGroups[0].Txns)),
		}
		if failure != "" {
			result.FailedAt = []uint64{0}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(models.SimulateResponse{
			LastRound: 9,
			TxnGroups: []models.SimulateTransactionGroupResult{result},
		})
	}))
	client, err := algod.MakeClient(server.URL, "")
	if err != nil {
		server.Close()
		t.Fatalf("MakeClient() error = %v", err)
	}
	return client, server.Close
}

func TestSignAndSubmitGroupSimulateUsesExecutableGuardedFlow(t *testing.T) {
	publicKey, _ := testFalconCosignerKeypair(t, 0x71)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	capture := &guardedSimulationCapture{}
	signerServer := newGuardedExecutableTestServer(t, cosignerHex, capture)
	defer signerServer.Close()
	var simulateReq models.SimulateRequest
	algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "", &simulateReq)
	defer closeAlgod()

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")
	s.endpointRegistry = cosignerEndpointRegistry("local-cosigner", config.ClientEndpointConfig{
		URL: signerServer.URL, TokenFile: writeCosignerTokenFile(t, "cosigner-token"),
	})
	s.algod = algodClient

	var out bytes.Buffer
	txIDs, submitted, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{
		Ctx:      context.Background(),
		Simulate: true,
		Out:      &out,
	})
	if err != nil {
		t.Fatalf("SignAndSubmitGroup(simulate) error = %v", err)
	}
	if capture.userRoleCalls.Load() != 1 || capture.cosignerRoleCalls.Load() != 1 {
		t.Fatalf("component calls user/cosigner = %d/%d, want 1/1", capture.userRoleCalls.Load(), capture.cosignerRoleCalls.Load())
	}
	if got := strings.Join(capture.eventSnapshot(), ","); got != "user,keys,cosigner,assemble" {
		t.Fatalf("guarded event order = %s, want user,keys,cosigner,assemble", got)
	}
	if capture.assembleCalls.Load() != 1 {
		t.Fatalf("/sign/assemble calls = %d, want 1", capture.assembleCalls.Load())
	}
	if capture.signerSimulateHit.Load() != 0 {
		t.Fatalf("signer simulation calls = %d, want 0", capture.signerSimulateHit.Load())
	}
	if len(txIDs) != len(submitted) || len(submitted) == 0 {
		t.Fatalf("simulate returned %d txIDs / %d txns, want matching non-empty results", len(txIDs), len(submitted))
	}
	if len(simulateReq.TxnGroups) != 1 || len(simulateReq.TxnGroups[0].Txns) != len(submitted) {
		t.Fatalf("algod simulate group = %#v, want %d transactions", simulateReq.TxnGroups, len(submitted))
	}
	if simulateReq.AllowEmptySignatures || simulateReq.FixSigners {
		t.Fatal("guarded signed simulation enabled empty-signature overrides")
	}

	assembly, assembledHex := capture.snapshot()
	if len(assembly.Targets) != 1 || assembly.Targets[0].UserSignature == "" || assembly.Targets[0].CosignerSignature == "" {
		t.Fatalf("assembly targets = %#v, want executable user+cosigner signatures", assembly.Targets)
	}
	if len(assembledHex) != len(simulateReq.TxnGroups[0].Txns) {
		t.Fatalf("assembled/simulated lengths = %d/%d", len(assembledHex), len(simulateReq.TxnGroups[0].Txns))
	}
	for i, signedHex := range assembledHex {
		want, err := hex.DecodeString(signedHex)
		if err != nil {
			t.Fatalf("decode assembled position %d: %v", i, err)
		}
		if got := msgpack.Encode(simulateReq.TxnGroups[0].Txns[i]); !bytes.Equal(got, want) {
			t.Fatalf("simulated position %d differs from assembled signed bytes", i)
		}
	}
	if !strings.Contains(out.String(), "Simulation successful") {
		t.Fatalf("output = %q, want simulation success", out.String())
	}
}

func TestBoundedCosignerSimulateUsesUserFirstChoreography(t *testing.T) {
	publicKey, _ := testFalconCosignerKeypair(t, 0x72)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "bounded-cosigner")
	componentSelector, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	events := make([]string, 0, 3)
	appendEvent := func(event string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		appendEvent("keys")
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{Count: 1, Keys: []signerapi.KeyInfo{{Address: componentSelector, PublicKeyHex: cosignerHex, KeyType: witness.Falcon1024V1, IsWitnessKey: true}}})
	})
	mux.HandleFunc("/plan", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		transactions := make([]string, len(req.Requests))
		for i, request := range req.Requests {
			transactions[i] = request.TxnBytesHex
		}
		_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{Transactions: transactions})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.ComponentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.TargetKind() == signerapi.ComponentTargetKindBoundedBase {
			appendEvent("base")
			_ = json.NewEncoder(w).Encode(signerapi.ComponentResponse{RequestID: req.RequestID, Components: []signerapi.Component{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: txn.Sender.String(), BaseSignatures: []string{"aa"}, AssemblyReceipt: "bb", SignatureScheme: "aplane.falcon1024.v1"}}})
			return
		}
		appendEvent("cosigner")
		_ = json.NewEncoder(w).Encode(signerapi.ComponentResponse{RequestID: req.RequestID, Components: []signerapi.Component{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindCosigner, Signature: "cc", SignatureScheme: witness.Falcon1024V1}}})
	})
	mux.HandleFunc("/sign/assemble", func(w http.ResponseWriter, r *http.Request) {
		appendEvent("assemble")
		var req signerapi.AssemblyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		signed := hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
		_ = json.NewEncoder(w).Encode(signerapi.AssemblyResponse{RequestID: req.RequestID, SignedGroup: []string{signed}})
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	var simulateReq models.SimulateRequest
	algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "", &simulateReq)
	defer closeAlgod()
	s, _ := newTestSigner(t, func(c *cache.SignerCache) {
		account := txn.Sender.String()
		c.AddAddress(account, "test.bounded-cosigner.v1")
		c.SetSigningFlowForAddress(account, signerapi.SigningFlowBoundedCosigner1)
		c.SetCosignerComponentKeyTypeForAddress(account, witness.Falcon1024V1)
		c.SetCosignerPublicKeyForAddress(account, cosignerHex)
		c.SetBoundedMaxFeeForAddress(account, 10_000)
		c.SetLogicSigResourceProfile(account, lsigresource.Profile{
			ProgramBytes:  4_000,
			Spend:         &lsigresource.PathProfile{MaxOpcodeCost: 20_000},
			SpendingRekey: &lsigresource.PathProfile{MaxOpcodeCost: 20_000},
			AdminRekey:    &lsigresource.PathProfile{MaxOpcodeCost: 20_000},
		})
	})
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")
	s.endpointRegistry = cosignerEndpointRegistry("local-cosigner", config.ClientEndpointConfig{
		URL: server.URL, TokenFile: writeCosignerTokenFile(t, "cosigner-token"),
	})
	s.algod = algodClient
	if _, _, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{Ctx: t.Context(), Simulate: true, Out: io.Discard}); err != nil {
		t.Fatalf("SignAndSubmitGroup() error = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(events, ",") != "base,keys,cosigner,assemble" {
		t.Fatalf("bounded-cosigner event order = %v, want base, keys, cosigner, assemble", events)
	}
}

// TestMixedGroupsFinishUserSideBeforeCosigner pins the user-first
// choreography in ARCH_COSIGNER.md for mixed groups: the user signer signs the
// non-guarded positions before the cosigner sees the group, so a /sign
// rejection never reaches the cosigner.
func TestMixedGroupsFinishUserSideBeforeCosigner(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bounded    bool
		rejectSign bool
		wantEvents string
	}{
		{name: "cosigner1", wantEvents: "user,sign,keys,cosigner,assemble"},
		{name: "cosigner1 sign rejected", rejectSign: true, wantEvents: "user,sign"},
		{name: "bounded-cosigner1", bounded: true, wantEvents: "base,sign,keys,cosigner,assemble"},
		{name: "bounded-cosigner1 sign rejected", bounded: true, rejectSign: true, wantEvents: "base,sign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicKey, _ := testFalconCosignerKeypair(t, 0x73)
			cosignerHex := hex.EncodeToString(publicKey)
			txns := []types.Transaction{
				testPaymentTxn(t, testAddress(1), testAddress(2), "guarded"),
				testPaymentTxn(t, testAddress(3), testAddress(2), "ordinary"),
			}
			groupID, err := crypto.ComputeGroupID(txns)
			if err != nil {
				t.Fatal(err)
			}
			for i := range txns {
				txns[i].Group = groupID
			}

			capture := &guardedSimulationCapture{rejectSign: tc.rejectSign}
			server := newGuardedExecutableTestServer(t, cosignerHex, capture)
			defer server.Close()
			var simulateReq models.SimulateRequest
			algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "", &simulateReq)
			defer closeAlgod()

			guarded := txns[0].Sender.String()
			s, _ := newGuardedTestSigner(t, guarded, 1500, cosignerHex)
			if tc.bounded {
				s, _ = newTestSigner(t, func(c *cache.SignerCache) {
					c.AddAddress(guarded, "test.bounded-cosigner.v1")
					c.SetSigningFlowForAddress(guarded, signerapi.SigningFlowBoundedCosigner1)
					c.SetCosignerComponentKeyTypeForAddress(guarded, witness.Falcon1024V1)
					c.SetCosignerPublicKeyForAddress(guarded, cosignerHex)
					c.SetBoundedMaxFeeForAddress(guarded, 10_000)
					c.SetLogicSigResourceProfile(guarded, lsigresource.Profile{
						ProgramBytes: 4_000,
						Spend:        &lsigresource.PathProfile{MaxOpcodeCost: 20_000},
					})
				})
			}
			s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")
			s.endpointRegistry = cosignerEndpointRegistry("local-cosigner", config.ClientEndpointConfig{
				URL: server.URL, TokenFile: writeCosignerTokenFile(t, "cosigner-token"),
			})
			s.algod = algodClient

			_, _, err = s.SignAndSubmitGroup(txns, clientsign.SubmitOptions{Ctx: t.Context(), Simulate: true, Out: io.Discard})
			if tc.rejectSign != (err != nil) {
				t.Fatalf("SignAndSubmitGroup() error = %v, want error %v", err, tc.rejectSign)
			}
			if got := strings.Join(capture.eventSnapshot(), ","); got != tc.wantEvents {
				t.Fatalf("event order = %s, want %s", got, tc.wantEvents)
			}
		})
	}
}

func TestBoundedCosignerRejectsPlannedFeeBeforeReleasingComponents(t *testing.T) {
	publicKey, _ := testFalconCosignerKeypair(t, 0x73)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "bounded-cosigner")
	var componentCalls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/plan", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		transactions := make([]string, len(req.Requests))
		for i, request := range req.Requests {
			transactions[i] = request.TxnBytesHex
		}
		_ = json.NewEncoder(w).Encode(signerapi.GroupPlanResponse{Transactions: transactions})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, _ *http.Request) {
		componentCalls.Add(1)
		http.Error(w, "component signing must not run", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	s, _ := newTestSigner(t, func(c *cache.SignerCache) {
		account := txn.Sender.String()
		c.AddAddress(account, "test.bounded-cosigner.v1")
		c.SetSigningFlowForAddress(account, signerapi.SigningFlowBoundedCosigner1)
		c.SetCosignerComponentKeyTypeForAddress(account, witness.Falcon1024V1)
		c.SetCosignerPublicKeyForAddress(account, cosignerHex)
		c.SetBoundedMaxFeeForAddress(account, uint64(txn.Fee)-1)
		c.SetLogicSigResourceProfile(account, lsigresource.Profile{
			ProgramBytes: 1,
			Spend:        &lsigresource.PathProfile{MaxOpcodeCost: 1},
		})
	})
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")
	var simulateReq models.SimulateRequest
	algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "", &simulateReq)
	defer closeAlgod()
	s.algod = algodClient

	_, _, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{Ctx: t.Context(), Simulate: true, Out: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "exceeds advertised max_fee") {
		t.Fatalf("SignAndSubmitGroup() error = %v, want max_fee rejection", err)
	}
	if got := componentCalls.Load(); got != 0 {
		t.Fatalf("component calls = %d, want 0 before fee rejection", got)
	}
}

func TestSignAndSubmitGroupSimulateReportsFailure(t *testing.T) {
	publicKey, _ := testFalconCosignerKeypair(t, 0x72)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(3), testAddress(4), "guarded")

	capture := &guardedSimulationCapture{}
	signerServer := newGuardedExecutableTestServer(t, cosignerHex, capture)
	defer signerServer.Close()
	var simulateReq models.SimulateRequest
	algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "logic eval error", &simulateReq)
	defer closeAlgod()

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")
	s.endpointRegistry = cosignerEndpointRegistry("local-cosigner", config.ClientEndpointConfig{
		URL: signerServer.URL, TokenFile: writeCosignerTokenFile(t, "cosigner-token"),
	})
	s.algod = algodClient

	var out bytes.Buffer
	_, _, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{
		Ctx:      context.Background(),
		Simulate: true,
		Out:      &out,
	})
	if !errors.Is(err, signing.ErrSimulationFailed) {
		t.Fatalf("SignAndSubmitGroup(simulate) error = %v, want ErrSimulationFailed", err)
	}
	if capture.userRoleCalls.Load() != 1 || capture.assembleCalls.Load() != 1 {
		t.Fatalf("user/assemble calls = %d/%d, want 1/1", capture.userRoleCalls.Load(), capture.assembleCalls.Load())
	}
	if !strings.Contains(out.String(), "logic eval error") {
		t.Fatalf("output = %q, want failure report", out.String())
	}
}

func TestSignAndSubmitGroupRejectsNilAlgodBeforeComponentSigning(t *testing.T) {
	publicKey, _ := testFalconCosignerKeypair(t, 0x73)
	cosignerHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(5), testAddress(6), "guarded")

	capture := &guardedSimulationCapture{}
	signerServer := newGuardedExecutableTestServer(t, cosignerHex, capture)
	defer signerServer.Close()
	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, cosignerHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")

	_, _, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{
		Ctx:      context.Background(),
		Simulate: true,
		Out:      io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "algod client not configured") {
		t.Fatalf("SignAndSubmitGroup(nil algod) error = %v, want algod configuration error", err)
	}
	if capture.userRoleCalls.Load() != 0 || capture.cosignerRoleCalls.Load() != 0 || capture.assembleCalls.Load() != 0 {
		t.Fatalf("signer calls user/cosigner/assemble = %d/%d/%d, want 0/0/0", capture.userRoleCalls.Load(), capture.cosignerRoleCalls.Load(), capture.assembleCalls.Load())
	}
}
