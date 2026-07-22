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
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/witness"
)

type guardedSimulationCapture struct {
	userRoleCalls     atomic.Int32
	sentryRoleCalls   atomic.Int32
	assembleCalls     atomic.Int32
	signerSimulateHit atomic.Int32

	mu             sync.Mutex
	assembly       signerapi.GuardedAssemblyRequest
	assembledGroup []string
}

func (c *guardedSimulationCapture) setAssembly(req signerapi.GuardedAssemblyRequest, signed []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.assembly = req
	c.assembledGroup = append([]string(nil), signed...)
}

func (c *guardedSimulationCapture) snapshot() (signerapi.GuardedAssemblyRequest, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.assembly, append([]string(nil), c.assembledGroup...)
}

// newGuardedExecutableTestServer serves the normal guarded signing surface.
// It intentionally exposes no signer simulation behavior.
func newGuardedExecutableTestServer(t *testing.T, publicKeyHex string, capture *guardedSimulationCapture) *httptest.Server {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode sentry public key: %v", err)
	}
	componentSelector, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Witness Key ID: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
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
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.ComponentSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		switch req.Role {
		case signerapi.ComponentSignRoleUser:
			capture.userRoleCalls.Add(1)
		case signerapi.ComponentSignRoleSentry:
			capture.sentryRoleCalls.Add(1)
		default:
			http.Error(w, "unexpected component role", http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentSignResponse{
			RequestID:    req.RequestID,
			ComponentKey: req.ComponentKey,
			Signatures:   make([]signerapi.ComponentSignature, 0, len(req.TargetIndices)),
		}
		for _, index := range req.TargetIndices {
			resp.Signatures = append(resp.Signatures, signerapi.ComponentSignature{
				TargetIndex:     index,
				SignatureScheme: witness.Falcon1024V1,
				Signature:       hex.EncodeToString([]byte{byte(index + 1)}),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/sign/assemble", func(w http.ResponseWriter, r *http.Request) {
		capture.assembleCalls.Add(1)
		var req signerapi.GuardedAssemblyRequest
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
		_ = json.NewEncoder(w).Encode(signerapi.GuardedAssemblyResponse{
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
	publicKey, _ := testFalconSentryKeypair(t, 0x71)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	capture := &guardedSimulationCapture{}
	signerServer := newGuardedExecutableTestServer(t, sentryHex, capture)
	defer signerServer.Close()
	var simulateReq models.SimulateRequest
	algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "", &simulateReq)
	defer closeAlgod()

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")
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
	if capture.userRoleCalls.Load() != 1 || capture.sentryRoleCalls.Load() != 1 {
		t.Fatalf("component calls user/sentry = %d/%d, want 1/1", capture.userRoleCalls.Load(), capture.sentryRoleCalls.Load())
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
	if len(assembly.Targets) != 1 || assembly.Targets[0].UserSignature == "" || assembly.Targets[0].SentrySignature == "" {
		t.Fatalf("assembly targets = %#v, want executable user+sentry signatures", assembly.Targets)
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

func TestSignAndSubmitGroupSimulateReportsFailure(t *testing.T) {
	publicKey, _ := testFalconSentryKeypair(t, 0x72)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(3), testAddress(4), "guarded")

	capture := &guardedSimulationCapture{}
	signerServer := newGuardedExecutableTestServer(t, sentryHex, capture)
	defer signerServer.Close()
	var simulateReq models.SimulateRequest
	algodClient, closeAlgod := newGuardedAlgodSimulationClient(t, "logic eval error", &simulateReq)
	defer closeAlgod()

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")
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
	publicKey, _ := testFalconSentryKeypair(t, 0x73)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(5), testAddress(6), "guarded")

	capture := &guardedSimulationCapture{}
	signerServer := newGuardedExecutableTestServer(t, sentryHex, capture)
	defer signerServer.Close()
	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(signerServer.URL, "")

	_, _, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{
		Ctx:      context.Background(),
		Simulate: true,
		Out:      io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "algod client not configured") {
		t.Fatalf("SignAndSubmitGroup(nil algod) error = %v, want algod configuration error", err)
	}
	if capture.userRoleCalls.Load() != 0 || capture.sentryRoleCalls.Load() != 0 || capture.assembleCalls.Load() != 0 {
		t.Fatalf("signer calls user/sentry/assemble = %d/%d/%d, want 0/0/0", capture.userRoleCalls.Load(), capture.sentryRoleCalls.Load(), capture.assembleCalls.Load())
	}
}
