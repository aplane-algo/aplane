// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package guarded

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestRequestNonGuardedSignaturesShapesModesAndExtracts(t *testing.T) {
	guarded := testAddress(1).String()
	nonGuarded := testAddress(2).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024Sentry1024V1)
		setTestLogicSigResources(c, guarded, 1500)
		c.SetLogicSigResourceProfile(guarded, lsigresource.Profile{
			ProgramBytes: 77,
			Default:      &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 1_700},
		})
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
		c.AddAddress(nonGuarded, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "guarded"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
		testPaymentTxn(t, testAddress(9), testAddress(5), "dummy"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signed, err := s.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2,
		map[int]guardedTarget{0: guardedTargetForTest(guarded, sentryHex)},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("requestNonGuardedSignatures() error = %v", err)
	}

	if len(signed) != 1 {
		t.Fatalf("len(signed) = %d, want 1 (only the non-guarded original)", len(signed))
	}
	if signed[1] == "" {
		t.Fatal("non-guarded position 1 signed hex is empty")
	}
	if _, ok := signed[0]; ok {
		t.Fatal("guarded position 0 must not be signed in the intermediate /sign call")
	}

	if got := captured.calls.Load(); got != 1 {
		t.Fatalf("/sign calls = %d, want 1", got)
	}
	req := captured.get()
	if err := req.Validate(); err != nil {
		t.Fatalf("captured /sign request failed validation (passthrough+foreign mix?): %v", err)
	}
	if mode, _ := req.Requests[0].Mode(); mode != signerapi.RequestModeForeign {
		t.Fatalf("guarded request[0] mode = %q, want foreign", mode)
	}
	if got := req.Requests[0].LsigResources; got == nil || got.ProgramBytes != 77 || got.ArgumentBytes != 1_423 || got.MaxOpcodeCost != 1_700 {
		t.Fatalf("guarded request[0] lsig_resources = %#v", got)
	}
	if mode, _ := req.Requests[1].Mode(); mode != signerapi.RequestModeSign {
		t.Fatalf("non-guarded request[1] mode = %q, want sign", mode)
	}
	if req.Requests[1].AuthAddress != nonGuarded || req.Requests[1].TxnSender != nonGuarded {
		t.Fatalf("non-guarded request[1] auth/sender = %q/%q, want %q", req.Requests[1].AuthAddress, req.Requests[1].TxnSender, nonGuarded)
	}
	if mode, _ := req.Requests[2].Mode(); mode != signerapi.RequestModeForeign {
		t.Fatalf("dummy request[2] mode = %q, want foreign", mode)
	}
	if got := req.Requests[2].LsigResources; got == nil || got.ProgramBytes != uint64(len(signing.EmbeddedDummyTealTok)) || got.ArgumentBytes != 0 || got.MaxOpcodeCost != 1 {
		t.Fatalf("dummy request[2] lsig_resources = %#v", got)
	}
}

func TestRequestNonGuardedSignaturesUsesGuardedAuthorizerResources(t *testing.T) {
	sender := testAddress(4).String()
	guardedAuthorizer := testAddress(1).String()
	nonGuarded := testAddress(2).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(guardedAuthorizer, keytypes.GuardedFalcon1024Sentry1024V1)
		setTestLogicSigResources(c, guardedAuthorizer, 1500)
		c.SetSentryPublicKeyForAddress(guardedAuthorizer, sentryHex)
		c.AddAddress(nonGuarded, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(4), testAddress(5), "guarded-authorizer"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signed, err := s.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2,
		map[int]guardedTarget{0: {
			Index:                  0,
			Sender:                 sender,
			Account:                guardedAuthorizer,
			SentryComponentKeyType: witness.Falcon1024V1,
			SentryPublicKey:        sentryHex,
		}},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("requestNonGuardedSignatures() error = %v", err)
	}
	if len(signed) != 1 || signed[1] == "" {
		t.Fatalf("signed = %#v, want only non-guarded position 1", signed)
	}

	req := captured.get()
	if mode, _ := req.Requests[0].Mode(); mode != signerapi.RequestModeForeign {
		t.Fatalf("guarded-authorizer request[0] mode = %q, want foreign", mode)
	}
	if req.Requests[0].AuthAddress != "" {
		t.Fatalf("guarded-authorizer request[0] auth address = %q, want empty foreign request", req.Requests[0].AuthAddress)
	}
	if resource := req.Requests[0].LsigResources; resource == nil || resource.ProgramBytes != 1500 || resource.MaxOpcodeCost != 1 {
		t.Fatalf("guarded-authorizer request[0] resources = %#v, want structured profile", resource)
	}
}

// TestRequestNonGuardedSignaturesAllGuardedMakesNoSignerCall verifies the
// all-guarded path is unchanged: with no non-guarded originals, no /sign call is
// made and no passthrough entries are produced.
func TestRequestNonGuardedSignaturesAllGuardedMakesNoSignerCall(t *testing.T) {
	guarded := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024Sentry1024V1)
		setTestLogicSigResources(c, guarded, 1500)
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "guarded"),
		testPaymentTxn(t, testAddress(9), testAddress(5), "dummy"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signed, err := s.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 1,
		map[int]guardedTarget{0: guardedTargetForTest(guarded, sentryHex)},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("requestNonGuardedSignatures() error = %v", err)
	}
	if len(signed) != 0 {
		t.Fatalf("len(signed) = %d, want 0 (all-guarded group)", len(signed))
	}
	if got := captured.calls.Load(); got != 0 {
		t.Fatalf("/sign calls = %d, want 0 (no non-guarded positions)", got)
	}
}

// TestRequestNonGuardedSignaturesRejectsMissingSignature verifies that a signer
// response with no signature for a sign-mode position is rejected rather than
// producing an invalid assembly.
func TestRequestNonGuardedSignaturesRejectsMissingSignature(t *testing.T) {
	guarded := testAddress(1).String()
	nonGuarded := testAddress(2).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024Sentry1024V1)
		setTestLogicSigResources(c, guarded, 1500)
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
		c.AddAddress(nonGuarded, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "guarded"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{emptyAll: true}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	_, err := s.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2,
		map[int]guardedTarget{0: guardedTargetForTest(guarded, sentryHex)},
		clientsign.SubmitOptions{},
	)
	if err == nil || !strings.Contains(err.Error(), "no signature for non-guarded position 2") {
		t.Fatalf("requestNonGuardedSignatures() error = %v, want missing signature for position 2", err)
	}
}

func newMixedTestSigner(t *testing.T, build func(c *cache.SignerCache)) *Signer {
	t.Helper()
	s, _ := newTestSigner(t, build)
	return s
}

// capturedSignRequest records the GroupSignRequest a mock user signer received.
// req is mutex-guarded so -race sees the handler write happen-before the test
// read; emptyAll is set before the server starts and read-only thereafter.
type capturedSignRequest struct {
	mu       sync.Mutex
	req      signerapi.GroupSignRequest
	calls    atomic.Int32
	emptyAll bool
}

func (c *capturedSignRequest) set(req signerapi.GroupSignRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.req = req
}

func (c *capturedSignRequest) get() signerapi.GroupSignRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.req
}

// newUserSignerSignTestServer mocks the user signer's POST /sign. It mirrors the
// real server's request-shape validation, signs sign-mode positions (returning a
// stand-in signed transaction), and returns "" for foreign positions — exactly
// as ExecuteGroupSigning does.
func newUserSignerSignTestServer(t *testing.T, captured *capturedSignRequest) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		captured.calls.Add(1)
		var req signerapi.GroupSignRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := req.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		captured.set(req)

		resp := signerapi.GroupSignResponse{Signed: make([]string, len(req.Requests))}
		for i, sr := range req.Requests {
			mode, err := sr.Mode()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if captured.emptyAll || mode != signerapi.RequestModeSign {
				resp.Signed[i] = ""
				continue
			}
			txn, err := txnutil.DecodePrefixedHex(sr.TxnBytesHex)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resp.Signed[i] = hex.EncodeToString(msgpack.Encode(types.SignedTxn{Txn: txn}))
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}
