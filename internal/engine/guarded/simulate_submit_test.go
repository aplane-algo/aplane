// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/message"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/lsig/falcon1024/signerops"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// newGuardedSimulateTestServer serves the signer-and-sentry surface a
// contained guarded simulation needs: /keys and sentry-role /sign/component
// (self-signer fallback), plus /simulate/guarded. Any user-role component
// request is counted and rejected — the contained flow must never ask the
// wire for user component signatures.
func newGuardedSimulateTestServer(t *testing.T, publicKeyHex string, privateKey []byte, captured *signerapi.GuardedSimulateRequest, userRoleCalls, simulateCalls *atomic.Int32, respond func(req signerapi.GuardedSimulateRequest) signerapi.GuardedSimulateResponse) *httptest.Server {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode sentry public key: %v", err)
	}
	componentSelector, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, publicKey)
	if err != nil {
		t.Fatalf("Sentry Key ID: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(signerapi.KeysResponse{
			Count: 1,
			Keys: []signerapi.KeyInfo{{
				Address:        componentSelector,
				PublicKeyHex:   publicKeyHex,
				KeyType:        keytypes.SentryComponentFalcon1024V1,
				IsComponentKey: true,
			}},
		})
	})
	mux.HandleFunc("/sign/component", func(w http.ResponseWriter, r *http.Request) {
		var req signerapi.ComponentSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Role == signerapi.ComponentSignRoleUser {
			userRoleCalls.Add(1)
			http.Error(w, "user component signing must stay inside the signer during simulation", http.StatusBadRequest)
			return
		}
		group, err := canonical.DecodeGroupHex(req.GroupBytesHex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := signerapi.ComponentSignResponse{
			RequestID:    req.RequestID,
			ComponentKey: req.ComponentKey,
			Signatures:   make([]signerapi.ComponentSignature, 0, len(req.TargetIndices)),
		}
		for _, index := range req.TargetIndices {
			msg := message.ComponentMessage(message.RoleSentry, group.Entries[index].TxID)
			signature, err := signerops.New(nil).Sign(privateKey, msg[:])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp.Signatures = append(resp.Signatures, signerapi.ComponentSignature{
				TargetIndex:     index,
				SignatureScheme: keytypes.SentryComponentFalcon1024V1,
				Signature:       hex.EncodeToString(signature),
			})
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/simulate/guarded", func(w http.ResponseWriter, r *http.Request) {
		simulateCalls.Add(1)
		var req signerapi.GuardedSimulateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*captured = req
		_ = json.NewEncoder(w).Encode(respond(req))
	})
	return httptest.NewServer(mux)
}

func TestSignAndSubmitGroupSimulateUsesContainedGuardedEndpoint(t *testing.T) {
	publicKey, privateKey := testFalconSentryKeypair(t, 0x71)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(1), testAddress(2), "guarded")

	var captured signerapi.GuardedSimulateRequest
	var userRoleCalls, simulateCalls atomic.Int32
	server := newGuardedSimulateTestServer(t, sentryHex, privateKey, &captured, &userRoleCalls, &simulateCalls, func(req signerapi.GuardedSimulateRequest) signerapi.GuardedSimulateResponse {
		txIDs := make([]string, len(req.Requests))
		for i := range txIDs {
			txIDs[i] = "SIMID" + string(rune('A'+i))
		}
		return signerapi.GuardedSimulateResponse{
			RequestID: req.RequestID,
			TxIDs:     txIDs,
			Output:    "SIMULATION-REPORT",
		}
	})
	defer server.Close()

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	var out bytes.Buffer
	txIDs, submitted, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{
		Ctx:      context.Background(),
		Simulate: true,
		Out:      &out,
	})
	if err != nil {
		t.Fatalf("SignAndSubmitGroup(simulate) error = %v", err)
	}
	if simulateCalls.Load() != 1 {
		t.Fatalf("/simulate/guarded calls = %d, want 1", simulateCalls.Load())
	}
	if userRoleCalls.Load() != 0 {
		t.Fatalf("user-role /sign/component calls = %d, want 0 during contained simulation", userRoleCalls.Load())
	}
	if len(txIDs) == 0 || len(submitted) == 0 {
		t.Fatalf("simulate returned %d txIDs / %d txns, want non-empty", len(txIDs), len(submitted))
	}
	if !strings.Contains(out.String(), "SIMULATION-REPORT") {
		t.Fatalf("output = %q, want simulation report", out.String())
	}

	if len(captured.Targets) != 1 {
		t.Fatalf("captured targets = %#v, want 1", captured.Targets)
	}
	target := captured.Targets[0]
	if target.TargetIndex != 0 || target.GuardedAccount != txn.Sender.String() || target.SentrySignature == "" {
		t.Fatalf("captured target = %#v, want guarded position 0 with sentry signature", target)
	}
	if len(captured.Requests) < 1 {
		t.Fatal("captured requests empty")
	}
	dummyCount := len(captured.Requests) - 1
	if len(captured.Passthrough) != dummyCount {
		t.Fatalf("captured passthrough = %d, want one per dummy (%d)", len(captured.Passthrough), dummyCount)
	}
	for _, passthrough := range captured.Passthrough {
		if passthrough.TargetIndex < 1 || passthrough.SignedTxnHex == "" {
			t.Fatalf("captured passthrough entry = %#v, want signed dummy position", passthrough)
		}
	}
}

func TestSignAndSubmitGroupSimulateReportsFailure(t *testing.T) {
	publicKey, privateKey := testFalconSentryKeypair(t, 0x72)
	sentryHex := hex.EncodeToString(publicKey)
	txn := testPaymentTxn(t, testAddress(3), testAddress(4), "guarded")

	var captured signerapi.GuardedSimulateRequest
	var userRoleCalls, simulateCalls atomic.Int32
	server := newGuardedSimulateTestServer(t, sentryHex, privateKey, &captured, &userRoleCalls, &simulateCalls, func(req signerapi.GuardedSimulateRequest) signerapi.GuardedSimulateResponse {
		return signerapi.GuardedSimulateResponse{
			RequestID: req.RequestID,
			TxIDs:     []string{"SIMFAIL"},
			Output:    "logic eval error",
			Failed:    true,
		}
	})
	defer server.Close()

	s, _ := newGuardedTestSigner(t, txn.Sender.String(), 1500, sentryHex)
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	var out bytes.Buffer
	_, _, err := s.SignAndSubmitGroup([]types.Transaction{txn}, clientsign.SubmitOptions{
		Ctx:      context.Background(),
		Simulate: true,
		Out:      &out,
	})
	if !errors.Is(err, signing.ErrSimulationFailed) {
		t.Fatalf("SignAndSubmitGroup(simulate) error = %v, want ErrSimulationFailed", err)
	}
	if !strings.Contains(out.String(), "logic eval error") {
		t.Fatalf("output = %q, want failure report", out.String())
	}
}
