// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

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
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
)

const nonGuardedFalconKeyType = "aplane.falcon1024.v1"

// TestPlanGuardedGroupSizesBudgetAcrossAllLogicSigs verifies the mixed-group
// budget generalization (Correction 2): LogicSig-budget dummies are sized over
// every LogicSig position, not just guarded ones. With a guarded account (800
// bytes) plus a non-guarded falcon1024 LogicSig (1500 bytes), the two original
// transactions provide 2000 bytes of budget but demand 2300, so one dummy is
// required — and that dummy only appears if the non-guarded falcon's budget is
// counted.
func TestPlanGuardedGroupSizesBudgetAcrossAllLogicSigs(t *testing.T) {
	guarded := testAddress(1).String()
	nonGuardedFalcon := testAddress(3).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	eng := newMixedGuardedTestEngine(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024SentryEd25519V1)
		c.SetLsigSize(guarded, 800)
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
		c.AddAddress(nonGuardedFalcon, nonGuardedFalconKeyType)
		c.SetLsigSize(nonGuardedFalcon, 1500)
	})

	txns := []types.Transaction{
		testPreparedTxn(t, testAddress(1), testAddress(2), "guarded", nil).Transaction,
		testPreparedTxn(t, testAddress(3), testAddress(2), "falcon", nil).Transaction,
	}
	targets := []guardedOriginalTarget{{
		Index:                  0,
		Account:                guarded,
		SentryComponentKeyType: keytypes.SentryComponentEd25519V1,
		SentryPublicKey:        sentryHex,
	}}

	planned, dummies, err := eng.planGuardedGroup(txns, targets, nil)
	if err != nil {
		t.Fatalf("planGuardedGroup() error = %v", err)
	}
	if len(dummies) != 1 {
		t.Fatalf("len(dummies) = %d, want 1 (non-guarded falcon budget must be counted)", len(dummies))
	}
	if len(planned) != 3 {
		t.Fatalf("len(planned) = %d, want 3", len(planned))
	}
	if planned[0].Group == (types.Digest{}) {
		t.Fatal("planned group ID is empty")
	}
	for i := range planned {
		if planned[i].Group != planned[0].Group {
			t.Fatalf("planned[%d].Group = %x, want %x", i, planned[i].Group, planned[0].Group)
		}
	}
}

// TestRequestNonGuardedSignaturesShapesModesAndExtracts verifies the Strategy A
// intermediate /sign call: non-guarded originals are sign mode, guarded
// originals are foreign with an lsig_size hint, dummies are foreign, the request
// passes validation (no forbidden passthrough+foreign mix), and only the
// non-guarded signed bytes are extracted by index.
func TestRequestNonGuardedSignaturesShapesModesAndExtracts(t *testing.T) {
	guarded := testAddress(1).String()
	nonGuarded := testAddress(2).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	eng := newMixedGuardedTestEngine(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024SentryEd25519V1)
		c.SetLsigSize(guarded, 1500)
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
		c.AddAddress(nonGuarded, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPreparedTxn(t, testAddress(1), testAddress(5), "guarded", nil).Transaction,
		testPreparedTxn(t, testAddress(2), testAddress(5), "ordinary", nil).Transaction,
		testPreparedTxn(t, testAddress(9), testAddress(5), "dummy", nil).Transaction,
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signed, err := eng.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2, map[int]bool{0: true}, signing.SubmitOptions{},
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
	if req.Requests[0].LsigSize != 1500 {
		t.Fatalf("guarded request[0] lsig_size = %d, want 1500", req.Requests[0].LsigSize)
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
	if req.Requests[2].LsigSize != 0 {
		t.Fatalf("dummy request[2] lsig_size = %d, want 0", req.Requests[2].LsigSize)
	}
}

// TestRequestNonGuardedSignaturesAllGuardedMakesNoSignerCall verifies the
// all-guarded path is unchanged: with no non-guarded originals, no /sign call is
// made and no passthrough entries are produced.
func TestRequestNonGuardedSignaturesAllGuardedMakesNoSignerCall(t *testing.T) {
	guarded := testAddress(1).String()
	sentryHex := testSentryPublicKeyHex(0xd6)

	eng := newMixedGuardedTestEngine(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024SentryEd25519V1)
		c.SetLsigSize(guarded, 1500)
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
	})

	plannedTxns := []types.Transaction{
		testPreparedTxn(t, testAddress(1), testAddress(5), "guarded", nil).Transaction,
		testPreparedTxn(t, testAddress(9), testAddress(5), "dummy", nil).Transaction,
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	signed, err := eng.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 1, map[int]bool{0: true}, signing.SubmitOptions{},
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

	eng := newMixedGuardedTestEngine(t, func(c *cache.SignerCache) {
		c.AddAddress(guarded, keytypes.GuardedFalcon1024SentryEd25519V1)
		c.SetLsigSize(guarded, 1500)
		c.SetSentryPublicKeyForAddress(guarded, sentryHex)
		c.AddAddress(nonGuarded, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPreparedTxn(t, testAddress(1), testAddress(5), "guarded", nil).Transaction,
		testPreparedTxn(t, testAddress(2), testAddress(5), "ordinary", nil).Transaction,
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{emptyAll: true}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	eng.Connection.SignerClient = signerclient.NewSignerClientWithToken(server.URL, "")

	_, err := eng.requestNonGuardedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2, map[int]bool{0: true}, signing.SubmitOptions{},
	)
	if err == nil || !strings.Contains(err.Error(), "no signature for non-guarded position 2") {
		t.Fatalf("requestNonGuardedSignatures() error = %v, want missing signature for position 2", err)
	}
}

func newMixedGuardedTestEngine(t *testing.T, build func(c *cache.SignerCache)) *Engine {
	t.Helper()
	signerCache := cache.NewSignerCache()
	build(&signerCache)
	eng, err := NewEngine("testnet",
		WithCacheStore(cache.NewStore(t.TempDir())),
		WithSignerCache(signerCache),
	)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return eng
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
