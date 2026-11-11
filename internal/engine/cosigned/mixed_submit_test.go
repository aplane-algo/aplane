// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cosigned

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/cache"
	"github.com/aplane-algo/aplane/internal/clientsign"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/signerclient"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/txnutil"
	"github.com/aplane-algo/aplane/internal/witness"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

func TestRequestNonCosignedSignaturesShapesModesAndExtracts(t *testing.T) {
	cosigned := testAddress(1).String()
	nonCosigned := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosigned, "aplane.falcon1024.v1")
		setTestCosignedResources(c, cosigned, 1500)
		c.SetLogicSigResourceProfile(cosigned, lsigresource.Profile{
			ProgramBytes: 77,
			Spend:        &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 1_700},
		})
		c.SetCosignerPublicKeyForAddress(cosigned, cosignerHex)
		c.AddAddress(nonCosigned, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "cosigned"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
		testPaymentTxn(t, testAddress(9), testAddress(5), "dummy"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClient(server.URL)

	signed, err := s.requestNonCosignedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2,
		map[int]cosignedTarget{0: cosignedTargetForTest(cosigned, cosignerHex)},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("requestNonCosignedSignatures() error = %v", err)
	}

	if len(signed) != 1 {
		t.Fatalf("len(signed) = %d, want 1 (only the non-cosigned original)", len(signed))
	}
	if signed[1] == "" {
		t.Fatal("non-cosigned position 1 signed hex is empty")
	}
	if _, ok := signed[0]; ok {
		t.Fatal("cosigned position 0 must not be signed in the intermediate /sign call")
	}

	if got := captured.calls.Load(); got != 1 {
		t.Fatalf("/sign calls = %d, want 1", got)
	}
	req := captured.get()
	if err := req.Validate(); err != nil {
		t.Fatalf("captured /sign request failed validation (passthrough+foreign mix?): %v", err)
	}
	if mode, _ := req.Requests[0].Mode(); mode != signerapi.RequestModeForeign {
		t.Fatalf("cosigned request[0] mode = %q, want foreign", mode)
	}
	if got := req.Requests[0].LsigResources; got == nil || got.ProgramBytes != 77 || got.ArgumentBytes != 1_423 || got.MaxOpcodeCost != 1_700 {
		t.Fatalf("cosigned request[0] lsig_resources = %#v", got)
	}
	if mode, _ := req.Requests[1].Mode(); mode != signerapi.RequestModeSign {
		t.Fatalf("non-cosigned request[1] mode = %q, want sign", mode)
	}
	if req.Requests[1].AuthAddress != nonCosigned || req.Requests[1].TxnSender != nonCosigned {
		t.Fatalf("non-cosigned request[1] auth/sender = %q/%q, want %q", req.Requests[1].AuthAddress, req.Requests[1].TxnSender, nonCosigned)
	}
	if mode, _ := req.Requests[2].Mode(); mode != signerapi.RequestModeForeign {
		t.Fatalf("dummy request[2] mode = %q, want foreign", mode)
	}
	if got := req.Requests[2].LsigResources; got == nil || got.ProgramBytes != uint64(len(signing.EmbeddedDummyTealTok)) || got.ArgumentBytes != 0 || got.MaxOpcodeCost != signing.DummyOpcodeCost {
		t.Fatalf("dummy request[2] lsig_resources = %#v", got)
	}
}

// A non-cosigned position goes to /plan and /sign/component as the signer's
// own, with no size hint: the signer sizes it from its records and can put the
// group's authorization charge on it (audit #10, #19).
func TestBuildBoundedComponentRequestsSendsHeldPositionsAsTheSignersOwn(t *testing.T) {
	cosigned := testAddress(1).String()
	nativeFalcon := testAddress(2).String()
	stranger := testAddress(3)
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosigned, "aplane.falcon1024.v1")
		setTestCosignedResources(c, cosigned, 1_500)
		c.SetCosignerPublicKeyForAddress(cosigned, cosignerHex)
		c.AddAddress(nativeFalcon, "falcon1024")
	})

	txns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "cosigned"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "native-falcon"),
	}
	targets := map[int]cosignedTarget{0: cosignedTargetForTest(cosigned, cosignerHex)}
	requests, err := s.buildBoundedComponentRequests(txns, targets, clientsign.SubmitOptions{})
	if err != nil {
		t.Fatalf("buildBoundedComponentRequests() error = %v", err)
	}
	held := requests[1]
	if mode, _ := held.Mode(); mode != signerapi.RequestModeSign || held.AuthAddress != nativeFalcon {
		t.Fatalf("held native Falcon request = %#v, want sign mode for %s", held, nativeFalcon)
	}
	if held.PQScheme != "" || held.LsigResources != nil {
		t.Fatalf("held request carries a size hint: %#v", held)
	}

	// /sign/component names the same account for that position, with no hint,
	// so the signer sizes it as /plan did.
	group := frozenGroup{BytesHex: []string{"a", "b", "dummy"}, OriginalCount: 2}
	component := boundedBaseComponentRequest(group, requests, targets, []*signerapi.AppCallInfo{nil, {Mode: "raw"}})
	if len(component.Targets) != 1 || component.Targets[0].TargetIndex != 0 || component.Targets[0].AuthAddress != cosigned {
		t.Fatalf("component targets = %#v", component.Targets)
	}
	want := []signerapi.ComponentContextPosition{{TargetIndex: 1, AuthAddress: nativeFalcon, AppCallInfo: &signerapi.AppCallInfo{Mode: "raw"}}}
	if !reflect.DeepEqual(component.ContextualPositions, want) {
		t.Fatalf("contextual positions = %#v, want %#v", component.ContextualPositions, want)
	}
	if len(component.DummyPositions) != 1 || component.DummyPositions[0].TargetIndex != 2 {
		t.Fatalf("dummy positions = %#v", component.DummyPositions)
	}

	// A position the signer doesn't hold could never be signed through /sign,
	// so the group is refused before anything is planned or approved.
	_, err = s.buildBoundedComponentRequests(
		append(txns, testPaymentTxn(t, stranger, testAddress(5), "not-held")),
		targets,
		clientsign.SubmitOptions{},
	)
	if err == nil || !strings.Contains(err.Error(), "transaction 3: the signer holds no key for "+stranger.String()) {
		t.Fatalf("unheld position: err = %v, want it refused up front", err)
	}
}

func TestRequestNonCosignedSignaturesUsesCosignedAuthorizerResources(t *testing.T) {
	sender := testAddress(4).String()
	cosignedAuthorizer := testAddress(1).String()
	nonCosigned := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosignedAuthorizer, "aplane.falcon1024.v1")
		setTestCosignedResources(c, cosignedAuthorizer, 1500)
		c.SetCosignerPublicKeyForAddress(cosignedAuthorizer, cosignerHex)
		c.AddAddress(nonCosigned, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(4), testAddress(5), "cosigned-authorizer"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClient(server.URL)

	signed, err := s.requestNonCosignedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2,
		map[int]cosignedTarget{0: {
			Index:                    0,
			Sender:                   sender,
			Account:                  cosignedAuthorizer,
			CosignerComponentKeyType: witness.Falcon1024V1,
			CosignerPublicKey:        cosignerHex,
			Route:                    flowRouteBoundedCosigner,
			BoundedPath:              signerapi.ComponentPathSpend,
		}},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("requestNonCosignedSignatures() error = %v", err)
	}
	if len(signed) != 1 || signed[1] == "" {
		t.Fatalf("signed = %#v, want only non-cosigned position 1", signed)
	}

	req := captured.get()
	if mode, _ := req.Requests[0].Mode(); mode != signerapi.RequestModeForeign {
		t.Fatalf("cosigned-authorizer request[0] mode = %q, want foreign", mode)
	}
	if req.Requests[0].AuthAddress != "" {
		t.Fatalf("cosigned-authorizer request[0] auth address = %q, want empty foreign request", req.Requests[0].AuthAddress)
	}
	if resource := req.Requests[0].LsigResources; resource == nil || resource.ProgramBytes != 1500 || resource.MaxOpcodeCost != 1 {
		t.Fatalf("cosigned-authorizer request[0] resources = %#v, want structured profile", resource)
	}
}

func TestBuildGroupSignRequestsUsesSelectedBoundedSpendResources(t *testing.T) {
	cosigned := testAddress(1).String()
	nonCosigned := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosigned, "test.bounded-cosigner.v1")
		c.SetLogicSigResourceProfile(cosigned, lsigresource.Profile{
			ProgramBytes:  2_500,
			Spend:         &lsigresource.PathProfile{ArgumentBytes: 1_423, MaxOpcodeCost: 1_700},
			SpendingRekey: &lsigresource.PathProfile{ArgumentBytes: 2_846, MaxOpcodeCost: 45_000},
		})
		c.AddAddress(nonCosigned, "ed25519")
	})

	txns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "cosigned"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
	}
	requests, signIndices, err := s.buildGroupSignRequests(
		txns,
		encodeGroupHex(txns),
		len(txns),
		map[int]cosignedTarget{0: {
			Index: 0, Sender: cosigned, Account: cosigned,
			Route: flowRouteBoundedCosigner, CosignerPublicKey: cosignerHex, BoundedPath: signerapi.ComponentPathSpend,
		}},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("buildGroupSignRequests() error = %v", err)
	}
	if len(signIndices) != 1 || signIndices[0] != 1 {
		t.Fatalf("sign indices = %v, want [1]", signIndices)
	}
	got := requests[0].LsigResources
	if got == nil || got.ProgramBytes != 2_500 || got.ArgumentBytes != 1_423 || got.MaxOpcodeCost != 1_700 {
		t.Fatalf("bounded spend resources = %#v, want exact spend path", got)
	}
	// A cosigned rekey is budgeted on the path its base component named.
	requests, _, err = s.buildGroupSignRequests(txns, encodeGroupHex(txns), len(txns),
		map[int]cosignedTarget{0: {
			Index: 0, Sender: cosigned, Account: cosigned,
			Route: flowRouteBoundedCosigner, CosignerPublicKey: cosignerHex, BoundedPath: signerapi.ComponentPathSpendingRekey,
		}}, clientsign.SubmitOptions{})
	if err != nil {
		t.Fatalf("buildGroupSignRequests(rekey) error = %v", err)
	}
	if got := requests[0].LsigResources; got == nil || got.ArgumentBytes != 2_846 || got.MaxOpcodeCost != 45_000 {
		t.Fatalf("cosigned rekey resources = %#v, want the spending-rekey path", got)
	}
	// Before its component arrives, a cosigned target has no path to budget.
	if _, _, err := s.buildGroupSignRequests(txns, encodeGroupHex(txns), len(txns),
		map[int]cosignedTarget{0: {Index: 0, Sender: cosigned, Account: cosigned, Route: flowRouteBoundedCosigner, CosignerPublicKey: cosignerHex}},
		clientsign.SubmitOptions{}); err == nil || !strings.Contains(err.Error(), "no base component path") {
		t.Fatalf("buildGroupSignRequests(no path) error = %v", err)
	}
}

// The mixed /sign carries each cosigned target's app call description, so the
// approval of the non-cosigned positions shows the target's ABI method. A
// dummy has none, and a target the caller described nothing for gets none.
func TestBuildGroupSignRequestsCarriesCosignedTargetAppCallInfo(t *testing.T) {
	cosigned := testAddress(1).String()
	nonCosigned := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)
	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosigned, "aplane.falcon1024.v1")
		setTestCosignedResources(c, cosigned, 1500)
		c.SetCosignerPublicKeyForAddress(cosigned, cosignerHex)
		c.AddAddress(nonCosigned, "ed25519")
	})
	txns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "cosigned"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
		testPaymentTxn(t, testAddress(9), testAddress(5), "dummy"),
	}
	targets := map[int]cosignedTarget{0: cosignedTargetForTest(cosigned, cosignerHex)}
	targetInfo := &signerapi.AppCallInfo{Mode: "abi", Method: "pay(uint64)void"}
	ordinaryInfo := &signerapi.AppCallInfo{Mode: "raw"}
	requests, _, err := s.buildGroupSignRequests(txns, encodeGroupHex(txns), 2, targets,
		clientsign.SubmitOptions{AppCallInfo: []*signerapi.AppCallInfo{targetInfo, ordinaryInfo}})
	if err != nil {
		t.Fatalf("buildGroupSignRequests() error = %v", err)
	}
	if mode, _ := requests[0].Mode(); mode != signerapi.RequestModeForeign || requests[0].AppCallInfo != targetInfo {
		t.Fatalf("cosigned target request = %#v, want foreign with its app call description", requests[0])
	}
	if requests[1].AppCallInfo != ordinaryInfo {
		t.Fatalf("non-cosigned request app call info = %#v, want the caller's", requests[1].AppCallInfo)
	}
	if requests[2].AppCallInfo != nil {
		t.Fatalf("dummy request app call info = %#v, want none", requests[2].AppCallInfo)
	}
	requests, _, err = s.buildGroupSignRequests(txns, encodeGroupHex(txns), 2, targets, clientsign.SubmitOptions{})
	if err != nil {
		t.Fatalf("buildGroupSignRequests(no app call info) error = %v", err)
	}
	if requests[0].AppCallInfo != nil {
		t.Fatalf("cosigned target app call info = %#v, want none when the caller gave none", requests[0].AppCallInfo)
	}
}

// The cosigned client says how much the signer raised the fees at /plan, as
// it says how many dummies it added, and says nothing about fees when the
// plan raised none.
func TestPlanFrozenGroupReportsTheSignersFeeRaise(t *testing.T) {
	original := testPaymentTxn(t, testAddress(1), testAddress(2), "cosigned")
	planned := original
	planned.Fee += 3_000
	dummies, err := signing.CreateDummyTransactions(1, suggestedParamsFromTxn(original))
	if err != nil {
		t.Fatal(err)
	}
	group := []types.Transaction{planned, dummies[0]}
	gid, err := crypto.ComputeGroupID(group)
	if err != nil {
		t.Fatal(err)
	}
	for i := range group {
		group[i].Group = gid
	}
	raised := signerapi.GroupPlanResponse{
		Transactions: encodeGroupHex(group),
		Mutations: &signerapi.MutationReport{
			DummiesAdded: 1, GroupIDChanged: true, FeesModified: []int{0},
			TotalFeesDelta: 3_000, OriginalCount: 1, FinalCount: 2,
		},
	}
	unchanged := signerapi.GroupPlanResponse{Transactions: encodeGroupHex([]types.Transaction{original})}

	for _, tc := range []struct {
		name     string
		response signerapi.GroupPlanResponse
		want     []string
		notWant  string
	}{
		{name: "raised", response: raised, want: []string{
			"[COSIGNED] Signer added 1 dummy transaction(s)",
			"[COSIGNED] Signer raised fees by 3000 microAlgos for authorization, on transaction(s) [1]",
		}},
		{name: "unchanged", response: unchanged, notWant: "raised fees"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/plan", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(tc.response)
			})
			server := httptest.NewServer(mux)
			defer server.Close()
			s := newMixedTestSigner(t, nil)
			s.conn.SignerClient = signerclient.NewSignerClient(server.URL)

			var out strings.Builder
			requests := []signerapi.SignRequest{{AuthAddress: original.Sender.String(), TxnBytesHex: txnutil.EncodeWithPrefixHex(original)}}
			if _, err := s.planFrozenGroup(context.Background(), []types.Transaction{original}, requests, &out); err != nil {
				t.Fatalf("planFrozenGroup() error = %v", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output = %q, want %q", out.String(), want)
				}
			}
			if tc.notWant != "" && strings.Contains(out.String(), tc.notWant) {
				t.Errorf("output = %q, did not want %q", out.String(), tc.notWant)
			}
		})
	}
}

// TestRequestNonCosignedSignaturesAllCosignedMakesNoSignerCall verifies the
// all-cosigned path is unchanged: with no non-cosigned originals, no /sign call is
// made and no passthrough entries are produced.
func TestRequestNonCosignedSignaturesAllCosignedMakesNoSignerCall(t *testing.T) {
	cosigned := testAddress(1).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosigned, "aplane.falcon1024.v1")
		setTestCosignedResources(c, cosigned, 1500)
		c.SetCosignerPublicKeyForAddress(cosigned, cosignerHex)
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "cosigned"),
		testPaymentTxn(t, testAddress(9), testAddress(5), "dummy"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClient(server.URL)

	signed, err := s.requestNonCosignedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 1,
		map[int]cosignedTarget{0: cosignedTargetForTest(cosigned, cosignerHex)},
		clientsign.SubmitOptions{},
	)
	if err != nil {
		t.Fatalf("requestNonCosignedSignatures() error = %v", err)
	}
	if len(signed) != 0 {
		t.Fatalf("len(signed) = %d, want 0 (all-cosigned group)", len(signed))
	}
	if got := captured.calls.Load(); got != 0 {
		t.Fatalf("/sign calls = %d, want 0 (no non-cosigned positions)", got)
	}
}

// TestRequestNonCosignedSignaturesRejectsMissingSignature verifies that a signer
// response with no signature for a sign-mode position is rejected rather than
// producing an invalid assembly.
func TestRequestNonCosignedSignaturesRejectsMissingSignature(t *testing.T) {
	cosigned := testAddress(1).String()
	nonCosigned := testAddress(2).String()
	cosignerHex := testCosignerPublicKeyHex(0xd6)

	s := newMixedTestSigner(t, func(c *cache.SignerCache) {
		c.AddAddress(cosigned, "aplane.falcon1024.v1")
		setTestCosignedResources(c, cosigned, 1500)
		c.SetCosignerPublicKeyForAddress(cosigned, cosignerHex)
		c.AddAddress(nonCosigned, "ed25519")
	})

	plannedTxns := []types.Transaction{
		testPaymentTxn(t, testAddress(1), testAddress(5), "cosigned"),
		testPaymentTxn(t, testAddress(2), testAddress(5), "ordinary"),
	}
	groupBytesHex := encodeGroupHex(plannedTxns)

	captured := &capturedSignRequest{emptyAll: true}
	server := newUserSignerSignTestServer(t, captured)
	defer server.Close()
	s.conn.SignerClient = signerclient.NewSignerClient(server.URL)

	_, err := s.requestNonCosignedSignatures(
		context.Background(), plannedTxns, groupBytesHex, 2,
		map[int]cosignedTarget{0: cosignedTargetForTest(cosigned, cosignerHex)},
		clientsign.SubmitOptions{},
	)
	if err == nil || !strings.Contains(err.Error(), "no signature for non-cosigned position 2") {
		t.Fatalf("requestNonCosignedSignatures() error = %v, want missing signature for position 2", err)
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

// setTestCosignedResources gives a cosigned account the resource profile the
// daemon serves for it: per path, with no default.
func setTestCosignedResources(signerCache *cache.SignerCache, address string, programBytes int) {
	signerCache.SetLogicSigResourceProfile(address, lsigresource.Profile{
		ProgramBytes:  uint64(programBytes),
		Spend:         &lsigresource.PathProfile{MaxOpcodeCost: 1},
		SpendingRekey: &lsigresource.PathProfile{MaxOpcodeCost: 1},
		ListedRekey:   &lsigresource.PathProfile{MaxOpcodeCost: 1},
	})
}
