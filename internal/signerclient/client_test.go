// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

func TestRequestGroupSignRejectsInvalidRequestBeforeHTTP(t *testing.T) {
	client := NewSignerClientWithToken("http://127.0.0.1:1", "test-token")
	_, err := client.RequestGroupSign([]signerapi.SignRequest{{AuthAddress: "ADDR"}})
	if err == nil || !strings.Contains(err.Error(), "invalid group sign request") {
		t.Fatalf("RequestGroupSign() error = %v", err)
	}
}

func TestRequestGroupPlanRejectsInvalidRequestBeforeHTTP(t *testing.T) {
	client := NewSignerClientWithToken("http://127.0.0.1:1", "test-token")
	_, err := client.RequestGroupPlan([]signerapi.SignRequest{{AuthAddress: "ADDR"}})
	if err == nil || !strings.Contains(err.Error(), "invalid group plan request") {
		t.Fatalf("RequestGroupPlan() error = %v", err)
	}
}

func TestRequestComponentsRejectsInvalidRequestBeforeHTTP(t *testing.T) {
	client := NewSignerClientWithToken("http://127.0.0.1:1", "test-token")
	_, err := client.RequestComponents(signerapi.ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets:       []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindUser}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid component request") {
		t.Fatalf("RequestComponents() error = %v", err)
	}
}

func TestRequestAssembleRejectsInvalidRequestBeforeHTTP(t *testing.T) {
	client := NewSignerClientWithToken("http://127.0.0.1:1", "test-token")
	_, err := client.RequestAssemble(signerapi.AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid assembly request") {
		t.Fatalf("RequestAssemble() error = %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewSignerClientHasNoGlobalTimeout(t *testing.T) {
	client := NewSignerClientWithToken("http://signer.test", "test-token")
	if client.Client.Timeout != 0 {
		t.Fatalf("Client.Timeout = %s, want no global timeout", client.Client.Timeout)
	}
}

func TestSignerClientHealthUsesConfiguredClient(t *testing.T) {
	used := false
	client := NewSignerClientWithToken("http://signer.test", "test-token")
	client.Client = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		used = true
		if req.URL.Path != "/health" {
			t.Fatalf("request path = %s, want /health", req.URL.Path)
		}
		if got := req.Header.Get("Authorization"); got != "aplane test-token" {
			t.Fatalf("authorization header = %q", got)
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	})}

	if err := client.Health(); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !used {
		t.Fatal("Health() did not use configured client transport")
	}
}

func TestSignerClientHealthPropagatesConfiguredClientError(t *testing.T) {
	client := NewSignerClientWithToken("http://signer.test", "test-token")
	client.Client = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("transport boom")
	})}

	err := client.Health()
	if err == nil || !strings.Contains(err.Error(), "transport boom") {
		t.Fatalf("Health() error = %v", err)
	}
}

func TestSignerClientContextAccessIsRaceSafe(t *testing.T) {
	client := NewSignerClientWithToken("http://signer.test", "test-token")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if j%2 == 0 {
					client.SetContext(ctx)
				} else {
					client.ClearContext()
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				reqCtx, cleanup := client.requestContext(client.Context(), 0)
				if reqCtx == nil {
					t.Error("requestContext returned nil context")
				}
				cleanup()
				_ = client.Context()
			}
		}()
	}
	wg.Wait()
}

func TestGetStatus_Success(t *testing.T) {
	resp := signerapi.StatusResponse{
		State:           "unlocked",
		ReadyForSigning: true,
		KeyCount:        2,
		KeysetRevision:  5,
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/status" {
			t.Fatalf("request = %s %s, want GET /status", req.Method, req.URL.Path)
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	got, err := c.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}
	if got.KeysetRevision != 5 || got.KeyCount != 2 {
		t.Fatalf("GetStatus() = %+v, want revision 5 count 2", got)
	}
}

func TestGetStatusRefreshesApprovalWaitCacheForSign(t *testing.T) {
	identityWaits := []int64{420, 60}
	identityCalls := 0
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/status":
			requireDeadlineNear(t, req.Context(), statusTimeout)
			if identityCalls >= len(identityWaits) {
				t.Fatalf("unexpected extra /status request")
			}
			resp := signerapi.StatusResponse{ApprovalWaitSeconds: identityWaits[identityCalls]}
			identityCalls++
			return mockResponse(200, jsonBody(t, resp)), nil
		case "/sign":
			requireDeadlineNear(t, req.Context(), 90*time.Second)
			return mockResponse(200, jsonBody(t, signerapi.GroupSignResponse{Signed: []string{"aabb"}})), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})

	if _, err := c.GetStatus(); err != nil {
		t.Fatalf("first GetStatus() error = %v", err)
	}
	if _, err := c.GetStatus(); err != nil {
		t.Fatalf("second GetStatus() error = %v", err)
	}
	if _, err := c.RequestGroupSign([]signerapi.SignRequest{{TxnBytesHex: "aabb", AuthAddress: "ADDR1"}}); err != nil {
		t.Fatalf("RequestGroupSign() error = %v", err)
	}
	if identityCalls != 2 {
		t.Fatalf("/status calls = %d, want 2", identityCalls)
	}
}

func TestRequestGroupSignDiscoversApprovalWaitBeforeSigning(t *testing.T) {
	paths := []string{}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		switch req.URL.Path {
		case "/status":
			return mockResponse(200, jsonBody(t, signerapi.StatusResponse{ApprovalWaitSeconds: 60})), nil
		case "/sign":
			requireDeadlineNear(t, req.Context(), 90*time.Second)
			return mockResponse(200, jsonBody(t, signerapi.GroupSignResponse{Signed: []string{"aabb"}})), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})

	if _, err := c.RequestGroupSign([]signerapi.SignRequest{{TxnBytesHex: "aabb", AuthAddress: "ADDR1"}}); err != nil {
		t.Fatalf("RequestGroupSign() error = %v", err)
	}
	if strings.Join(paths, ",") != "/status,/sign" {
		t.Fatalf("request paths = %v, want [/status /sign]", paths)
	}
}

func TestRequestGroupSignFallsBackWhenApprovalWaitMissing(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		calls++
		switch req.URL.Path {
		case "/status":
			return mockResponse(200, jsonBody(t, signerapi.StatusResponse{})), nil
		case "/sign":
			requireDeadlineNear(t, req.Context(), defaultSignRequestTimeout)
			return mockResponse(200, jsonBody(t, signerapi.GroupSignResponse{Signed: []string{"aabb"}})), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})
	c.cacheApprovalWaitSeconds(60)

	if _, err := c.GetStatus(); err != nil {
		t.Fatalf("GetStatus() error = %v", err)
	}
	if _, err := c.RequestGroupSign([]signerapi.SignRequest{{TxnBytesHex: "aabb", AuthAddress: "ADDR1"}}); err != nil {
		t.Fatalf("RequestGroupSign() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("request calls = %d, want 2", calls)
	}
}

func jsonBody(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mockResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func newTestClient(t *testing.T, fn roundTripperFunc) *Client {
	t.Helper()
	c := NewSignerClientWithToken("http://signer.test", "test-token")
	c.Client = &http.Client{Transport: fn}
	c.ProgressOut = io.Discard
	return c
}

func requireDeadlineNear(t *testing.T, ctx context.Context, want time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("request context has no deadline; want about %s", want)
	}
	remaining := time.Until(deadline)
	const tolerance = 500 * time.Millisecond
	if remaining < want-tolerance || remaining > want+tolerance {
		t.Fatalf("deadline remaining = %s, want about %s", remaining, want)
	}
}

func requireDeadlineAtMost(t *testing.T, ctx context.Context, max time.Duration) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatalf("request context has no deadline; want at most %s", max)
	}
	remaining := time.Until(deadline)
	if remaining > max {
		t.Fatalf("deadline remaining = %s, want at most %s", remaining, max)
	}
}

// --- GetKeys ---

func TestGetKeys_Success(t *testing.T) {
	resp := signerapi.KeysResponse{
		Count: 2,
		Keys: []signerapi.KeyInfo{
			{Address: "ADDR1", KeyType: "ed25519"},
			{Address: "ADDR2", KeyType: "aplane.falcon1024.v1"},
		},
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/keys" {
			t.Errorf("path = %q, want /keys", req.URL.Path)
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	got, err := c.GetKeys()
	if err != nil {
		t.Fatalf("GetKeys() error = %v", err)
	}
	if got.Count != 2 {
		t.Errorf("Count = %d, want 2", got.Count)
	}
	if len(got.Keys) != 2 {
		t.Errorf("len(Keys) = %d, want 2", len(got.Keys))
	}
}

func TestGetKeys_Locked(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(403, `{"error":"signer is locked"}`), nil
	})

	got, err := c.GetKeys()
	if err != nil {
		t.Fatalf("GetKeys() error = %v", err)
	}
	if !got.Locked {
		t.Error("expected Locked = true for 403")
	}
}

func TestGetKeys_ForbiddenNonLocked(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(403, `{"error":"Forbidden"}`), nil
	})

	_, err := c.GetKeys()
	if err == nil {
		t.Fatal("expected error for non-locked 403")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("error = %v, want Forbidden", err)
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusForbidden {
		t.Fatalf("error = %T %[1]v, want HTTPStatusError 403", err)
	}
}

func TestGetKeys_ServerError(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(500, `internal error`), nil
	})

	_, err := c.GetKeys()
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should contain status code: %v", err)
	}
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("error = %T %[1]v, want HTTPStatusError 500", err)
	}
}

func TestGetKeys_InvalidJSONIsTyped(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(200, `{`), nil
	})

	_, err := c.GetKeys()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error = %T %[1]v, want ErrInvalidResponse", err)
	}
}

// --- GetKeyTypes ---

func TestGetKeyTypes_Success(t *testing.T) {
	resp := signerapi.KeyTypesResponse{
		KeyTypes: []signerapi.KeyTypeInfo{
			{KeyType: "ed25519", DisplayName: "Ed25519"},
		},
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/keytypes" {
			t.Errorf("path = %q, want /keytypes", req.URL.Path)
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	got, err := c.GetKeyTypes()
	if err != nil {
		t.Fatalf("GetKeyTypes() error = %v", err)
	}
	if len(got.KeyTypes) != 1 {
		t.Errorf("len(KeyTypes) = %d, want 1", len(got.KeyTypes))
	}
}

func TestGetKeyTypes_ServerError(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(500, `boom`), nil
	})

	_, err := c.GetKeyTypes()
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

// --- AdminGenerate ---

func TestAdminGenerate_Success(t *testing.T) {
	resp := signerapi.AdminGenerateResponse{
		Address: "NEWADDR123",
		KeyType: "ed25519",
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/admin/generate" || req.Method != "POST" {
			t.Errorf("request = %s %s, want POST /admin/generate", req.Method, req.URL.Path)
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	got, err := c.AdminGenerate("ed25519", nil)
	if err != nil {
		t.Fatalf("AdminGenerate() error = %v", err)
	}
	if got.Address != "NEWADDR123" {
		t.Errorf("Address = %q, want %q", got.Address, "NEWADDR123")
	}
}

func TestAdminGenerate_ErrorResponse(t *testing.T) {
	resp := signerapi.AdminGenerateResponse{
		Error: "unsupported key type",
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	_, err := c.AdminGenerate("badtype", nil)
	if err == nil {
		t.Fatal("expected error for error response")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAdminGenerate_ServerError(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(500, `server error`), nil
	})

	_, err := c.AdminGenerate("ed25519", nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

// --- AdminDeleteKey ---

func TestAdminDeleteKey_Success(t *testing.T) {
	resp := signerapi.AdminDeleteResponse{Success: true}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != "DELETE" {
			t.Errorf("method = %q, want DELETE", req.Method)
		}
		if !strings.Contains(req.URL.String(), "address=TESTADDR") {
			t.Errorf("URL should contain address param: %s", req.URL.String())
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	got, err := c.AdminDeleteKey("TESTADDR")
	if err != nil {
		t.Fatalf("AdminDeleteKey() error = %v", err)
	}
	if !got.Success {
		t.Error("expected Success = true")
	}
}

func TestAdminDeleteKey_ErrorResponse(t *testing.T) {
	resp := signerapi.AdminDeleteResponse{Error: "key not found"}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	_, err := c.AdminDeleteKey("NOADDR")
	if err == nil {
		t.Fatal("expected error for error response")
	}
	if !strings.Contains(err.Error(), "key not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- RequestGroupSign ---

func TestRequestGroupSign_Success(t *testing.T) {
	resp := signerapi.GroupSignResponse{
		Signed: []string{"aabb", "ccdd"},
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/sign" || req.Method != "POST" {
			t.Errorf("request = %s %s, want POST /sign", req.Method, req.URL.Path)
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})
	c.cacheApprovalWaitSeconds(60)

	got, err := c.RequestGroupSign([]signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err != nil {
		t.Fatalf("RequestGroupSign() error = %v", err)
	}
	if len(got.Signed) != 2 {
		t.Errorf("len(Signed) = %d, want 2", len(got.Signed))
	}
}

func TestRequestBoundedAdmin_Success(t *testing.T) {
	response := signerapi.BoundedAdminPartialResponse{
		Schema:        signerapi.BoundedAdminPartialSchemaV1,
		Operation:     signerapi.BoundedAdminOperationRekey,
		Transactions:  []string{"5458aa"},
		PartialSigned: []string{"aabb"},
		TargetIndex:   0,
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/sign/bounded-admin" || req.Method != http.MethodPost {
			t.Fatalf("request = %s %s, want POST /sign/bounded-admin", req.Method, req.URL.Path)
		}
		var got signerapi.BoundedAdminRequest
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.RequestID == "" || got.Operation != signerapi.BoundedAdminOperationRekey || len(got.Requests) != 1 {
			t.Fatalf("request = %#v", got)
		}
		return mockResponse(http.StatusOK, jsonBody(t, response)), nil
	})
	c.cacheApprovalWaitSeconds(60)

	got, err := c.RequestBoundedAdmin(signerapi.BoundedAdminOperationRekey, []signerapi.SignRequest{{TxnBytesHex: "aabb", AuthAddress: "ADDR1"}})
	if err != nil {
		t.Fatalf("RequestBoundedAdmin() error = %v", err)
	}
	if got.Schema != signerapi.BoundedAdminPartialSchemaV1 || got.PartialSigned[0] != "aabb" {
		t.Fatalf("response = %#v", got)
	}
}

func TestRequestUnifiedBoundedSentryEndpoints(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/sign/component":
			var got signerapi.ComponentRequest
			if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			return mockResponse(http.StatusOK, jsonBody(t, signerapi.ComponentResponse{
				RequestID:  got.RequestID,
				Components: []signerapi.Component{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: "ADDR1", BaseSignatures: []string{"aa"}, AssemblyReceipt: "bb", SignatureScheme: "aplane.falcon1024.v1"}},
			})), nil
		case "/sign/assemble":
			var got signerapi.AssemblyRequest
			if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			return mockResponse(http.StatusOK, jsonBody(t, signerapi.AssemblyResponse{RequestID: got.RequestID, SignedGroup: []string{"ccdd"}})), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})
	c.cacheApprovalWaitSeconds(60)
	component, err := c.RequestComponentsWithContext(t.Context(), signerapi.ComponentRequest{GroupBytesHex: []string{"5458aa"}, Targets: []signerapi.ComponentTarget{{TargetIndex: 0, Kind: signerapi.ComponentTargetKindBoundedBase, AuthAddress: "ADDR1"}}})
	if err != nil || len(component.Components) != 1 {
		t.Fatalf("RequestComponentsWithContext() = %#v, %v", component, err)
	}
	assembly, err := c.RequestAssembleWithContext(t.Context(), signerapi.AssemblyRequest{
		GroupBytesHex: []string{"5458aa"}, Targets: []signerapi.AssemblyTarget{{
			TargetIndex: 0, Kind: signerapi.AssemblyTargetKindBoundedSentry, AuthAddress: "ADDR1", BaseSignatures: []string{"aa"}, AssemblyReceipt: "bb", SentrySignature: "cc",
		}},
	})
	if err != nil || len(assembly.SignedGroup) != 1 {
		t.Fatalf("RequestAssembleWithContext() = %#v, %v", assembly, err)
	}
}

func TestRequestComponentsRejectsUnrequestedTargetKind(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		var got signerapi.ComponentRequest
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return mockResponse(http.StatusOK, jsonBody(t, signerapi.ComponentResponse{
			RequestID: got.RequestID,
			Components: []signerapi.Component{{
				TargetIndex: 0, Kind: signerapi.ComponentTargetKindUser,
				Signature: "aa", SignatureScheme: "aplane.falcon1024.v1",
			}},
		})), nil
	})

	_, err := c.RequestComponentsWithContext(t.Context(), signerapi.ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindSentry, ComponentKey: "SENTRY",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "indices or kinds do not match") {
		t.Fatalf("expected mismatched target error, got %v", err)
	}
}

func TestRequestComponentsRejectsOutOfGroupTargetIndex(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		var got signerapi.ComponentRequest
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return mockResponse(http.StatusOK, jsonBody(t, signerapi.ComponentResponse{
			RequestID: got.RequestID,
			Components: []signerapi.Component{{
				TargetIndex: 1, Kind: signerapi.ComponentTargetKindSentry,
				Signature: "aa", SignatureScheme: "aplane.falcon1024.v1",
			}},
		})), nil
	})

	_, err := c.RequestComponentsWithContext(t.Context(), signerapi.ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindSentry, ComponentKey: "SENTRY",
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "indices or kinds do not match") {
		t.Fatalf("expected out-of-group target error, got %v", err)
	}
}

func TestRequestGroupSign_ErrorField(t *testing.T) {
	resp := signerapi.GroupSignResponse{Error: "rejected by policy"}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(200, jsonBody(t, resp)), nil
	})
	c.cacheApprovalWaitSeconds(60)

	_, err := c.RequestGroupSign([]signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err == nil {
		t.Fatal("expected error for error response")
	}
	if !strings.Contains(err.Error(), "rejected by policy") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestGroupSign_ServerError(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(500, `server error`), nil
	})
	c.cacheApprovalWaitSeconds(60)

	_, err := c.RequestGroupSign([]signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestRequestGroupSignDoesNotExtendCallerDeadline(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		requireDeadlineAtMost(t, req.Context(), time.Second)
		return mockResponse(200, jsonBody(t, signerapi.GroupSignResponse{Signed: []string{"aabb"}})), nil
	})
	c.cacheApprovalWaitSeconds(60)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := c.RequestGroupSignWithContext(ctx, []signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err != nil {
		t.Fatalf("RequestGroupSignWithContext() error = %v", err)
	}
}

func TestRequestGroupSignCancelsApprovalWhenContextCanceled(t *testing.T) {
	signStarted := make(chan string, 1)
	cancelReceived := make(chan string, 1)
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/sign":
			var signReq signerapi.GroupSignRequest
			if err := json.NewDecoder(req.Body).Decode(&signReq); err != nil {
				t.Fatalf("decode /sign request: %v", err)
			}
			if signReq.RequestID == "" {
				t.Fatal("/sign request_id is empty")
			}
			signStarted <- signReq.RequestID
			<-req.Context().Done()
			return nil, req.Context().Err()
		case "/sign/cancel":
			var cancelReq signerapi.CancelSignRequest
			if err := json.NewDecoder(req.Body).Decode(&cancelReq); err != nil {
				t.Fatalf("decode /sign/cancel request: %v", err)
			}
			cancelReceived <- cancelReq.RequestID
			return mockResponse(200, jsonBody(t, signerapi.CancelSignResponse{Success: true})), nil
		default:
			t.Fatalf("unexpected request path %q", req.URL.Path)
			return nil, nil
		}
	})
	c.cacheApprovalWaitSeconds(60)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)

	go func() {
		_, err := c.RequestGroupSignWithContext(ctx, []signerapi.SignRequest{
			{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
		})
		result <- err
	}()

	var requestID string
	select {
	case requestID = <-signStarted:
	case <-time.After(time.Second):
		t.Fatal("/sign request was not sent")
	}
	cancel()

	select {
	case got := <-cancelReceived:
		if got != requestID {
			t.Fatalf("/sign/cancel request_id = %q, want %q", got, requestID)
		}
	case <-time.After(time.Second):
		t.Fatal("/sign/cancel was not sent after context cancellation")
	}

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("RequestGroupSignWithContext() error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("RequestGroupSignWithContext() did not return")
	}
}

func TestRequestComponentsPostsToComponentEndpoint(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/sign/component" || req.Method != http.MethodPost {
			t.Fatalf("request = %s %s, want POST /sign/component", req.Method, req.URL.Path)
		}
		if got := req.Header.Get("Authorization"); got != "aplane test-token" {
			t.Fatalf("authorization header = %q", got)
		}
		var got signerapi.ComponentRequest
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatalf("Decode(request body) error = %v", err)
		}
		if got.RequestID == "" {
			t.Fatal("request_id was not populated")
		}
		if got.TargetKind() != signerapi.ComponentTargetKindSentry || got.Targets[0].ComponentKey != "75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA" {
			t.Fatalf("component request = %+v, want sentry component_key 75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA", got)
		}
		resp := signerapi.ComponentResponse{
			RequestID: got.RequestID,
			Components: []signerapi.Component{{
				TargetIndex:     0,
				Kind:            signerapi.ComponentTargetKindSentry,
				Signature:       "aabb",
				SignatureScheme: "aplane.witness-falcon1024.v1",
			}},
		}
		return mockResponse(http.StatusOK, jsonBody(t, resp)), nil
	})

	got, err := c.RequestComponents(signerapi.ComponentRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.ComponentTarget{{
			TargetIndex: 0, Kind: signerapi.ComponentTargetKindSentry,
			ComponentKey: "75OU3CR55IDLKDFEZSFWLIRGE2I5Q337D3NTKAEHJ6K7FGYON5AA",
		}},
	})
	if err != nil {
		t.Fatalf("RequestComponents() error = %v", err)
	}
	if len(got.Components) != 1 || got.Components[0].Signature != "aabb" {
		t.Fatalf("RequestComponents() = %+v, want one signature aabb", got)
	}
}

func TestRequestAssemblePostsToAssembleEndpoint(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/sign/assemble" || req.Method != http.MethodPost {
			t.Fatalf("request = %s %s, want POST /sign/assemble", req.Method, req.URL.Path)
		}
		var got signerapi.AssemblyRequest
		if err := json.NewDecoder(req.Body).Decode(&got); err != nil {
			t.Fatalf("Decode(request body) error = %v", err)
		}
		if got.RequestID == "" {
			t.Fatal("request_id was not populated")
		}
		if len(got.Targets) != 1 || got.Targets[0].Kind != signerapi.AssemblyTargetKindGuarded || got.Targets[0].AuthAddress != "ADDR1" {
			t.Fatalf("assembly request targets = %+v, want ADDR1 target", got.Targets)
		}
		return mockResponse(http.StatusOK, jsonBody(t, signerapi.AssemblyResponse{
			RequestID:   got.RequestID,
			SignedGroup: []string{"ccdd"},
		})), nil
	})

	got, err := c.RequestAssemble(signerapi.AssemblyRequest{
		GroupBytesHex: []string{"5458aa"},
		Targets: []signerapi.AssemblyTarget{{
			TargetIndex:     0,
			Kind:            signerapi.AssemblyTargetKindGuarded,
			AuthAddress:     "ADDR1",
			UserSignature:   "aabb",
			SentrySignature: "bbcc",
		}},
	})
	if err != nil {
		t.Fatalf("RequestAssemble() error = %v", err)
	}
	if len(got.SignedGroup) != 1 || got.SignedGroup[0] != "ccdd" {
		t.Fatalf("RequestAssemble() = %+v, want signed group ccdd", got)
	}
}

// --- RequestGroupPlan ---

func TestRequestGroupPlan_Success(t *testing.T) {
	resp := signerapi.GroupPlanResponse{
		Transactions: []string{"TX:aabb", "TX:ccdd"},
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path != "/plan" || req.Method != "POST" {
			t.Errorf("request = %s %s, want POST /plan", req.Method, req.URL.Path)
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	got, err := c.RequestGroupPlan([]signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err != nil {
		t.Fatalf("RequestGroupPlan() error = %v", err)
	}
	if len(got.Transactions) != 2 {
		t.Errorf("len(Transactions) = %d, want 2", len(got.Transactions))
	}
}

func TestRequestGroupPlan_ErrorField(t *testing.T) {
	resp := signerapi.GroupPlanResponse{Error: "planning failed"}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return mockResponse(200, jsonBody(t, resp)), nil
	})

	_, err := c.RequestGroupPlan([]signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err == nil {
		t.Fatal("expected error for error response")
	}
	if !strings.Contains(err.Error(), "planning failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRequestGroupPlanDoesNotUseApprovalWaitDeadline(t *testing.T) {
	resp := signerapi.GroupPlanResponse{
		Transactions: []string{"TX:aabb"},
	}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		requireDeadlineNear(t, req.Context(), groupPlanTimeout)
		return mockResponse(200, jsonBody(t, resp)), nil
	})
	c.cacheApprovalWaitSeconds(20 * 60)

	_, err := c.RequestGroupPlan([]signerapi.SignRequest{
		{TxnBytesHex: "aabb", AuthAddress: "ADDR1"},
	})
	if err != nil {
		t.Fatalf("RequestGroupPlan() error = %v", err)
	}
}

// --- Auth header ---

func TestAuthorizationHeader(t *testing.T) {
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		got := req.Header.Get("Authorization")
		if got != "aplane test-token" {
			t.Errorf("Authorization = %q, want %q", got, "aplane test-token")
		}
		return mockResponse(200, jsonBody(t, signerapi.KeysResponse{})), nil
	})

	_, _ = c.GetKeys()
}

// --- sign cancel watcher ---

func TestRequestGroupSignDoesNotCancelAfterSuccess(t *testing.T) {
	var cancelCalls atomic.Int32
	resp := signerapi.GroupSignResponse{Signed: []string{"aabb"}}
	c := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/sign/cancel" {
			cancelCalls.Add(1)
			return mockResponse(200, "{}"), nil
		}
		return mockResponse(200, jsonBody(t, resp)), nil
	})
	c.cacheApprovalWaitSeconds(60)

	if _, err := c.RequestGroupSign([]signerapi.SignRequest{{TxnBytesHex: "aabb", AuthAddress: "ADDR1"}}); err != nil {
		t.Fatalf("RequestGroupSign() error = %v", err)
	}

	// Give the watcher goroutine a chance to misfire before asserting.
	time.Sleep(50 * time.Millisecond)
	if got := cancelCalls.Load(); got != 0 {
		t.Fatalf("cancel requests = %d, want 0 after a successful sign", got)
	}
}
