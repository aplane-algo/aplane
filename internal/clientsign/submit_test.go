// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientsign

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func jsonResponse(req *http.Request, status int, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func signedTxnHex(txn types.Transaction) string {
	var sig types.Signature
	sig[0] = 1
	return hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn, Sig: sig}))
}

func TestSignAndSubmitViaGroupRejectsForeignPlaceholders(t *testing.T) {
	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sign" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		resp := signerapi.GroupSignResponse{
			Signed: []string{""},
			Mutations: &signerapi.MutationReport{
				ForeignCount: 1,
			},
		}
		return jsonResponse(r, http.StatusOK, resp)
	})}

	authCache := cache.NewAuthAddressCache()

	txns := []types.Transaction{{Header: types.Header{Sender: types.Address{1}}}}
	_, _, err := SignAndSubmitViaGroup(txns, &authCache, signerClient, nil, SubmitOptions{Out: io.Discard})
	if err == nil {
		t.Fatal("expected foreign placeholder error, got nil")
	}
	if !strings.Contains(err.Error(), "foreign placeholder") {
		t.Fatalf("error = %q, want foreign placeholder message", err)
	}
}

func TestSignAndSubmitViaGroupIncludesAppCallMetadata(t *testing.T) {
	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sign" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if len(req.Requests) != 1 {
			t.Fatalf("len(requests) = %d, want 1", len(req.Requests))
		}
		if req.Requests[0].AppCallInfo == nil || req.Requests[0].AppCallInfo.Mode != "abi" || req.Requests[0].AppCallInfo.Method != "increment(uint64)" {
			t.Fatalf("AppCallInfo = %#v, want abi method metadata", req.Requests[0].AppCallInfo)
		}
		resp := signerapi.GroupSignResponse{
			Signed: []string{signedTxnHex(types.Transaction{
				Header: types.Header{Sender: types.Address{1}},
			})},
		}
		return jsonResponse(r, http.StatusOK, resp)
	})}

	authCache := cache.NewAuthAddressCache()

	txns := []types.Transaction{{Header: types.Header{Sender: types.Address{1}}}}
	_, _, _ = SignAndSubmitViaGroup(txns, &authCache, signerClient, nil, SubmitOptions{
		Out:         io.Discard,
		AppCallInfo: []*signerapi.AppCallInfo{{Mode: "abi", Method: "increment(uint64)"}},
	})
}

func TestSignAndSubmitViaGroupSimulateUsesSignerSimulateEndpoint(t *testing.T) {
	var signerPaths []string
	simulatedTxn := types.Transaction{
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    5000,
		},
	}
	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		signerPaths = append(signerPaths, r.URL.Path)
		if r.URL.Path == "/plan" {
			t.Fatal("simulate path called /plan; want /simulate")
		}
		if r.URL.Path == "/sign" {
			t.Fatal("simulate path called /sign; want /simulate")
		}
		if r.URL.Path != "/simulate" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		resp := signerapi.GroupSimulateResponse{
			TxIDs:        []string{"SIMTXID"},
			Transactions: []string{txnutil.EncodeWithPrefixHex(simulatedTxn)},
			Output:       "simulation output\n",
		}
		return jsonResponse(r, http.StatusOK, resp)
	})}

	authCache := cache.NewAuthAddressCache()
	txns := []types.Transaction{{Header: types.Header{Sender: types.Address{1}}}}
	var out bytes.Buffer
	txIDs, submitted, err := SignAndSubmitViaGroup(txns, &authCache, signerClient, nil, SubmitOptions{
		Out:      &out,
		Simulate: true,
	})
	if err != nil {
		t.Fatalf("SignAndSubmitViaGroup() error = %v", err)
	}
	if len(signerPaths) != 1 || signerPaths[0] != "/simulate" {
		t.Fatalf("signer paths = %v, want [/simulate]", signerPaths)
	}
	if len(txIDs) != 1 || txIDs[0] != "SIMTXID" {
		t.Fatalf("txIDs = %v, want [SIMTXID]", txIDs)
	}
	if len(submitted) != 1 || submitted[0].Fee != simulatedTxn.Fee {
		t.Fatalf("submitted = %#v, want simulated txn fee %d", submitted, simulatedTxn.Fee)
	}
	if !strings.Contains(out.String(), "simulation output") {
		t.Fatalf("output = %q, want simulation output", out.String())
	}
}

func TestSignAndSubmitViaGroupSimulateFailureReturnsSentinel(t *testing.T) {
	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/simulate" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		resp := signerapi.GroupSimulateResponse{
			TxIDs:        []string{"SIMTXID"},
			Transactions: []string{txnutil.EncodeWithPrefixHex(types.Transaction{Header: types.Header{Sender: types.Address{1}}})},
			Output:       "Simulation FAILED\n",
			Failed:       true,
		}
		return jsonResponse(r, http.StatusOK, resp)
	})}

	authCache := cache.NewAuthAddressCache()
	txns := []types.Transaction{{Header: types.Header{Sender: types.Address{1}}}}
	_, _, err := SignAndSubmitViaGroup(txns, &authCache, signerClient, nil, SubmitOptions{
		Out:      io.Discard,
		Simulate: true,
	})
	if err == nil {
		t.Fatal("expected simulation failure, got nil")
	}
	if !errors.Is(err, signing.ErrSimulationFailed) {
		t.Fatalf("error = %q, want simulation failure sentinel", err)
	}
}

func TestSignAndSubmitViaGroupRejectsNilAlgodAfterSigning(t *testing.T) {
	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sign" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		resp := signerapi.GroupSignResponse{
			Signed: []string{signedTxnHex(types.Transaction{
				Header: types.Header{Sender: types.Address{1}},
			})},
		}
		return jsonResponse(r, http.StatusOK, resp)
	})}

	authCache := cache.NewAuthAddressCache()
	txns := []types.Transaction{{Header: types.Header{Sender: types.Address{1}}}}

	_, _, err := SignAndSubmitViaGroup(txns, &authCache, signerClient, nil, SubmitOptions{Out: io.Discard})
	if err == nil {
		t.Fatal("expected algod client error, got nil")
	}
	if !strings.Contains(err.Error(), "algod client not configured") {
		t.Fatalf("error = %q, want algod client error", err)
	}
}

func TestSignAndSubmitViaGroupWritesSubmittedTransactions(t *testing.T) {
	original := types.Transaction{
		Type: types.PaymentTx,
		Header: types.Header{
			Sender: types.Address{1},
			Fee:    1000,
		},
		PaymentTxnFields: types.PaymentTxnFields{
			Receiver: types.Address{2},
			Amount:   1,
		},
	}
	submitted := original
	submitted.Fee = 5000

	signerClient := signerclient.NewSignerClientWithToken("http://signer.test", "test-token")
	signerClient.Client = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/sign" {
			return jsonResponse(r, http.StatusNotFound, map[string]string{"error": "not found"})
		}
		return jsonResponse(r, http.StatusOK, signerapi.GroupSignResponse{
			Signed: []string{signedTxnHex(submitted)},
		})
	})}

	algodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/transactions" {
			t.Fatalf("algod path = %s, want /v2/transactions", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"txId":"test-txid"}`))
	}))
	defer algodServer.Close()
	algodClient, err := algod.MakeClient(algodServer.URL, "")
	if err != nil {
		t.Fatalf("MakeClient() error = %v", err)
	}

	var written []types.Transaction
	authCache := cache.NewAuthAddressCache()
	txIDs, submittedTxns, err := SignAndSubmitViaGroup(
		[]types.Transaction{original},
		&authCache,
		signerClient,
		algodClient,
		SubmitOptions{
			Out: io.Discard,
			TxnWriter: func(txn types.Transaction, txID string) {
				written = append(written, txn)
			},
		},
	)
	if err != nil {
		t.Fatalf("SignAndSubmitViaGroup() error = %v", err)
	}
	if len(txIDs) != 1 {
		t.Fatalf("len(txIDs) = %d, want 1", len(txIDs))
	}
	if len(submittedTxns) != 1 || submittedTxns[0].Fee != submitted.Fee {
		t.Fatalf("submittedTxns = %#v, want fee %d", submittedTxns, submitted.Fee)
	}
	if len(written) != 1 || written[0].Fee != submitted.Fee {
		t.Fatalf("written txns = %#v, want fee %d", written, submitted.Fee)
	}
	if original.Fee == submitted.Fee {
		t.Fatal("test setup invalid: original and submitted fees match")
	}
}
