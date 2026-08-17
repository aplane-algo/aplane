// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signerclient provides a small HTTP client for Signer endpoints.
package signerclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aplane-algo/aplane/internal/signerapi"
)

// Client is an HTTP client for the Signer signing service.
type Client struct {
	BaseURL     string
	Token       string // Bearer token for authentication
	Client      *http.Client
	Ctx         context.Context // If set, used for HTTP requests (enables cancellation)
	ProgressOut io.Writer       // Progress/status output. Defaults to os.Stdout when nil.

	ctxMu             sync.RWMutex
	approvalMu        sync.RWMutex
	approvalWait      time.Duration
	approvalWaitKnown bool
}

type KeysResult = signerapi.KeysResult

// ErrInvalidResponse marks a syntactically invalid response from a signer
// endpoint after the HTTP request itself succeeded.
var ErrInvalidResponse = errors.New("invalid signer response")

// HTTPStatusError preserves non-success signer HTTP status codes and the
// machine-readable error code for callers that need to distinguish
// auth/lock/config/server failures without matching message text.
type HTTPStatusError struct {
	StatusCode int
	Code       string // stable wire code from ErrorResponse; empty on old servers
	Message    string
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "signer error"
	}
	return fmt.Sprintf("signer error (%d): %s", e.StatusCode, e.Message)
}

// IsLocked reports whether the signer rejected the request because the
// keystore is locked. The message fallback covers servers that predate
// wire error codes.
func (e *HTTPStatusError) IsLocked() bool {
	if e == nil {
		return false
	}
	if e.Code != "" {
		return e.Code == signerapi.ErrCodeLocked
	}
	return e.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(e.Message), "locked")
}

// httpStatusError reads a non-2xx response body into a typed error carrying
// status, wire code, and human-readable message.
func httpStatusError(resp *http.Response) *HTTPStatusError {
	code, message := readErrorResponseParts(resp)
	return &HTTPStatusError{StatusCode: resp.StatusCode, Code: code, Message: message}
}

const (
	healthTimeout             = 3 * time.Second
	statusTimeout             = 5 * time.Second
	inventoryTimeout          = 30 * time.Second
	mutationTimeout           = 60 * time.Second
	groupPlanTimeout          = 60 * time.Second
	componentSignTimeout      = 2 * time.Minute
	guardedAssemblyTimeout    = 2 * time.Minute
	signCancelTimeout         = 5 * time.Second
	signApprovalSlack         = 30 * time.Second
	defaultSignRequestTimeout = 6 * time.Minute
	maxDiscoveredApprovalWait = 30 * time.Minute
)

// NewSignerClientWithToken creates a new Signer client with authentication token.
func NewSignerClientWithToken(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		Client:  &http.Client{},
	}
}

// SetToken sets the authentication token.
func (c *Client) SetToken(token string) {
	c.Token = token
}

// SetContext sets the fallback request context used when a call does not pass
// an explicit context.
func (c *Client) SetContext(ctx context.Context) {
	c.ctxMu.Lock()
	defer c.ctxMu.Unlock()
	c.Ctx = ctx
}

// ClearContext clears the fallback request context.
func (c *Client) ClearContext() {
	c.ctxMu.Lock()
	defer c.ctxMu.Unlock()
	c.Ctx = nil
}

// Context returns the fallback request context used when a call does not pass
// an explicit context.
func (c *Client) Context() context.Context {
	c.ctxMu.RLock()
	defer c.ctxMu.RUnlock()
	return c.Ctx
}

// doRequest performs an HTTP request with authentication.
// Explicit ctx takes precedence; otherwise c.Ctx is used when set.
func (c *Client) doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	if ctx != nil {
		req = req.WithContext(ctx)
	} else if clientCtx := c.Context(); clientCtx != nil {
		req = req.WithContext(clientCtx)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "aplane "+c.Token)
	}
	return c.Client.Do(req)
}

func (c *Client) requestContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = c.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return withDefaultTimeout(ctx, timeout)
}

func withDefaultTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}
	defaultDeadline := time.Now().Add(timeout)
	if callerDeadline, ok := ctx.Deadline(); ok && !callerDeadline.After(defaultDeadline) {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// doJSON performs one JSON request/response round-trip against a signer
// endpoint: build the request (with body when non-nil), apply the endpoint
// timeout, send, map non-2xx to *HTTPStatusError, and decode the body into T.
// failMsg labels transport-level failures for the endpoint.
// Endpoints with bespoke status handling (locked /keys results, cancel
// wording, the /sign approval watcher) intentionally do not use it.
func doJSON[T any](c *Client, ctx context.Context, method, path string, body any, timeout time.Duration, failMsg string) (*T, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	reqCtx, cancel := c.requestContext(ctx, timeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", failMsg, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError(resp)
	}

	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &out, nil
}

func newSignRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "cli-" + hex.EncodeToString(random[:]), nil
}

func readErrorResponse(resp *http.Response) string {
	_, message := readErrorResponseParts(resp)
	return message
}

func readErrorResponseParts(resp *http.Response) (code, message string) {
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := strings.TrimSpace(string(bodyBytes))
	if body == "" {
		return "", http.StatusText(resp.StatusCode)
	}

	var errorResp signerapi.ErrorResponse
	if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && errorResp.Error != "" {
		return errorResp.Code, errorResp.Error
	}
	return "", body
}

func (c *Client) cacheApprovalWaitSeconds(seconds int64) {
	wait := time.Duration(0)
	if seconds > 0 && seconds <= int64(maxDiscoveredApprovalWait/time.Second) {
		wait = time.Duration(seconds) * time.Second
	}

	c.approvalMu.Lock()
	c.approvalWait = wait
	c.approvalWaitKnown = true
	c.approvalMu.Unlock()
}

func (c *Client) cachedApprovalWait() (time.Duration, bool) {
	c.approvalMu.RLock()
	defer c.approvalMu.RUnlock()
	if !c.approvalWaitKnown || c.approvalWait <= 0 {
		return 0, false
	}
	return c.approvalWait, true
}

func (c *Client) needsApprovalWaitDiscovery() bool {
	c.approvalMu.RLock()
	defer c.approvalMu.RUnlock()
	return !c.approvalWaitKnown
}

func (c *Client) discoverApprovalWait(ctx context.Context) {
	if !c.needsApprovalWaitDiscovery() {
		return
	}
	_, _ = c.GetStatusWithContext(ctx)
}

func (c *Client) signRequestTimeout() time.Duration {
	wait, ok := c.cachedApprovalWait()
	if !ok {
		return defaultSignRequestTimeout
	}
	return wait + signApprovalSlack
}

// Health checks if the Signer service is healthy and responding.
func (c *Client) Health() error {
	return c.HealthWithContext(context.Background())
}

func (c *Client) HealthWithContext(ctx context.Context) error {
	req, err := http.NewRequest("GET", c.BaseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, healthTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return fmt.Errorf("signer not responding at %s: %w", c.BaseURL, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signer health check failed (status %d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	return nil
}

// GetStatus fetches authenticated signer status and keyset revision from Signer.
func (c *Client) GetStatus() (*signerapi.StatusResponse, error) {
	return c.GetStatusWithContext(context.Background())
}

func (c *Client) GetStatusWithContext(ctx context.Context) (*signerapi.StatusResponse, error) {
	statusResp, err := doJSON[signerapi.StatusResponse](c, ctx, "GET", "/status", nil, statusTimeout, "failed to get signer status")
	if err != nil {
		return nil, err
	}
	c.cacheApprovalWaitSeconds(statusResp.ApprovalWaitSeconds)
	return statusResp, nil
}

// RequestGroupPlan sends transactions to the /plan endpoint for group planning.
// The server computes the canonical group (dummies, fee pooling, group ID) without
// signing or triggering approval. Returns unsigned canonical transactions.
func (c *Client) RequestGroupPlan(requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	return c.RequestGroupPlanWithContext(context.Background(), requests)
}

func (c *Client) RequestGroupPlanWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupPlanResponse, error) {
	groupReq := signerapi.GroupSignRequest{Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid group plan request: %w", err)
	}

	planResp, err := doJSON[signerapi.GroupPlanResponse](c, ctx, "POST", "/plan", groupReq, groupPlanTimeout, "failed to make request to Signer")
	if err != nil {
		return nil, err
	}
	if planResp.Error != "" {
		return nil, fmt.Errorf("group planning failed: %s", planResp.Error)
	}
	return planResp, nil
}

// RequestGroupSign sends transactions to the /sign endpoint for group signing.
// The server handles dummy transaction creation, fee pooling, and group ID computation.
// Returns the signed transactions (including any dummies added by the server).
func (c *Client) RequestGroupSign(requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	return c.RequestGroupSignWithContext(context.Background(), requests)
}

func (c *Client) RequestGroupSignWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSignResponse, error) {
	requestID, err := newSignRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request ID: %w", err)
	}
	groupReq := signerapi.GroupSignRequest{RequestID: requestID, Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid group sign request: %w", err)
	}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var groupResp signerapi.GroupSignResponse
	err = c.postSignApprovalRequest(ctx, "/sign", requestID, jsonBody, func(resp *http.Response) error {
		if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
		if groupResp.Error != "" {
			return fmt.Errorf("group signing failed: %s", groupResp.Error)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &groupResp, nil
}

// postSignApprovalRequest POSTs a sign-family request that may park on
// operator approval and owns the shared cancel/timeout choreography for every
// such endpoint: the approval-wait progress lines, the request deadline, and
// canceling the pending approval server-side when the context ends while the
// request is in flight. decode consumes the 200 response body; the request
// context stays alive until it returns.
func (c *Client) postSignApprovalRequest(ctx context.Context, path, requestID string, jsonBody []byte, decode func(*http.Response) error) error {
	c.discoverApprovalWait(ctx)

	w := c.progressWriter()
	_, _ = fmt.Fprintln(w, "Waiting for approval from Signer...")

	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, c.signRequestTimeout())
	defer cancel()

	var cancelOnce sync.Once
	sendCancel := func() {
		cancelOnce.Do(func() {
			cancelCtx, cancel := context.WithTimeout(context.Background(), signCancelTimeout)
			defer cancel()
			if err := c.CancelSignRequestWithContext(cancelCtx, requestID); err != nil {
				slog.Debug("failed to cancel sign request", "request_id", requestID, "error", err)
			}
		})
	}
	// done is closed the instant doRequest returns. The watcher only cancels
	// when the context ends while the request is still in flight; checking a
	// flag stored after return left a window where a deadline racing a
	// successful response cancelled a request the server had already
	// processed.
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-reqCtx.Done():
		}
		select {
		case <-done:
			// Request finished in the same instant; nothing to cancel.
		default:
			sendCancel()
		}
	}()

	resp, err := c.doRequest(reqCtx, req)
	close(done)
	if err != nil {
		if reqCtx.Err() != nil {
			sendCancel()
		}
		return fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return httpStatusError(resp)
	}
	if err := decode(resp); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(w, "Approved by Signer")
	return nil
}

// RequestBoundedAdmin asks the signer for the spending half of one external
// contract-admin operation. The returned object is not submission-ready.
func (c *Client) RequestBoundedAdmin(operation string, requests []signerapi.SignRequest) (*signerapi.BoundedAdminPartialResponse, error) {
	return c.RequestBoundedAdminWithContext(context.Background(), operation, requests)
}

func (c *Client) RequestBoundedAdminWithContext(ctx context.Context, operation string, requests []signerapi.SignRequest) (*signerapi.BoundedAdminPartialResponse, error) {
	requestID, err := newSignRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request ID: %w", err)
	}
	reqBody := signerapi.BoundedAdminRequest{RequestID: requestID, Operation: operation, Requests: requests}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid bounded-admin request: %w", err)
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal bounded-admin request: %w", err)
	}

	var partial signerapi.BoundedAdminPartialResponse
	err = c.postSignApprovalRequest(ctx, "/sign/bounded-admin", requestID, jsonBody, func(resp *http.Response) error {
		decoder := json.NewDecoder(io.LimitReader(resp.Body, 512*1024))
		if err := decoder.Decode(&partial); err != nil {
			return fmt.Errorf("failed to decode bounded-admin response: %w", err)
		}
		if partial.Schema != signerapi.BoundedAdminPartialSchemaV1 {
			return fmt.Errorf("unsupported bounded-admin partial schema %q", partial.Schema)
		}
		if partial.Operation != operation {
			return fmt.Errorf("bounded-admin response operation %q does not match request %q", partial.Operation, operation)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &partial, nil
}

func (c *Client) RequestAssemble(req signerapi.AssemblyRequest) (*signerapi.AssemblyResponse, error) {
	return c.RequestAssembleWithContext(context.Background(), req)
}

func (c *Client) RequestAssembleWithContext(ctx context.Context, reqBody signerapi.AssemblyRequest) (*signerapi.AssemblyResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create assembly request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid assembly request: %w", err)
	}
	result, err := doJSON[signerapi.AssemblyResponse](c, ctx, "POST", "/sign/assemble", reqBody, guardedAssemblyTimeout, "failed to make request to Signer")
	if err != nil {
		return nil, err
	}
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid assembly response: %w", err)
	}
	if result.RequestID != reqBody.RequestID {
		return nil, fmt.Errorf("assembly response request_id does not match request")
	}
	return result, nil
}

func (c *Client) RequestComponents(req signerapi.ComponentRequest) (*signerapi.ComponentResponse, error) {
	return c.RequestComponentsWithContext(context.Background(), req)
}

func (c *Client) RequestComponentsWithContext(ctx context.Context, reqBody signerapi.ComponentRequest) (*signerapi.ComponentResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create component request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component request: %w", err)
	}
	var result signerapi.ComponentResponse
	if reqBody.TargetKind() == signerapi.ComponentTargetKindSentry {
		response, err := doJSON[signerapi.ComponentResponse](c, ctx, "POST", "/sign/component", reqBody, componentSignTimeout, "failed to make request to Signer")
		if err != nil {
			return nil, err
		}
		result = *response
	} else {
		body, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal component request: %w", err)
		}
		err = c.postSignApprovalRequest(ctx, "/sign/component", reqBody.RequestID, body, func(resp *http.Response) error {
			return json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&result)
		})
		if err != nil {
			return nil, err
		}
	}
	if err := result.ValidateForRequest(reqBody); err != nil {
		return nil, fmt.Errorf("invalid component response: %w", err)
	}
	if result.RequestID != reqBody.RequestID {
		return nil, fmt.Errorf("component response request_id does not match request")
	}
	return &result, nil
}

// CancelSignRequestWithContext asks apsigner to cancel a pending manual
// approval prompt created by a previous /sign request.
func (c *Client) CancelSignRequestWithContext(ctx context.Context, requestID string) error {
	cancelReq := signerapi.CancelSignRequest{RequestID: requestID}
	if err := cancelReq.Validate(); err != nil {
		return fmt.Errorf("invalid sign cancel request: %w", err)
	}

	jsonBody, err := json.Marshal(cancelReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/sign/cancel", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, signCancelTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return fmt.Errorf("failed to make sign cancel request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("signer cancel error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var cancelResp signerapi.CancelSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&cancelResp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	if cancelResp.Error != "" {
		return fmt.Errorf("sign cancel failed: %s", cancelResp.Error)
	}
	return nil
}

func (c *Client) progressWriter() io.Writer {
	if c.ProgressOut != nil {
		return c.ProgressOut
	}
	return os.Stdout
}

// GetKeys fetches the list of available signing keys from Signer.
func (c *Client) GetKeys() (*KeysResult, error) {
	return c.GetKeysWithContext(context.Background())
}

func (c *Client) GetKeysWithContext(ctx context.Context) (*KeysResult, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/keys", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, inventoryTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get keys: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		herr := httpStatusError(resp)
		if herr.IsLocked() {
			return &KeysResult{Locked: true}, nil
		}
		return nil, herr
	}

	var keysResp signerapi.KeysResponse
	if err := json.NewDecoder(resp.Body).Decode(&keysResp); err != nil {
		return nil, fmt.Errorf("%w: failed to decode response: %v", ErrInvalidResponse, err)
	}

	return &KeysResult{KeysResponse: keysResp}, nil
}

// AdminGenerate requests key generation from Signer.
func (c *Client) AdminGenerate(keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	return c.AdminGenerateWithContext(context.Background(), keyType, params)
}

func (c *Client) AdminGenerateWithContext(ctx context.Context, keyType string, params map[string]string) (*signerapi.AdminGenerateResponse, error) {
	reqBody := signerapi.AdminGenerateRequest{
		KeyType:    keyType,
		Parameters: params,
	}

	genResp, err := doJSON[signerapi.AdminGenerateResponse](c, ctx, "POST", "/admin/generate", reqBody, mutationTimeout, "failed to generate key")
	if err != nil {
		return nil, err
	}
	if genResp.Error != "" {
		return nil, fmt.Errorf("key generation failed: %s", genResp.Error)
	}
	return genResp, nil
}

// AdminDeleteKey requests key deletion from Signer.
func (c *Client) AdminDeleteKey(address string) (*signerapi.AdminDeleteResponse, error) {
	return c.AdminDeleteKeyWithContext(context.Background(), address)
}

func (c *Client) AdminDeleteKeyWithContext(ctx context.Context, address string) (*signerapi.AdminDeleteResponse, error) {
	path := "/admin/keys?" + url.Values{"address": []string{address}}.Encode()
	delResp, err := doJSON[signerapi.AdminDeleteResponse](c, ctx, "DELETE", path, nil, mutationTimeout, "failed to delete key")
	if err != nil {
		return nil, err
	}
	if delResp.Error != "" {
		return nil, fmt.Errorf("key deletion failed: %s", delResp.Error)
	}
	return delResp, nil
}

// GetKeyTypes fetches available key types from Signer.
func (c *Client) GetKeyTypes() (*signerapi.KeyTypesResponse, error) {
	return c.GetKeyTypesWithContext(context.Background())
}

func (c *Client) GetKeyTypesWithContext(ctx context.Context) (*signerapi.KeyTypesResponse, error) {
	return doJSON[signerapi.KeyTypesResponse](c, ctx, "GET", "/keytypes", nil, inventoryTimeout, "failed to get key types")
}
