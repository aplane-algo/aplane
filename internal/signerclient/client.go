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

// HTTPStatusError preserves non-success signer HTTP status codes for callers
// that need to distinguish auth/config/server failures.
type HTTPStatusError struct {
	StatusCode int
	Message    string
}

func (e *HTTPStatusError) Error() string {
	if e == nil {
		return "signer error"
	}
	return fmt.Sprintf("signer error (%d): %s", e.StatusCode, e.Message)
}

const (
	healthTimeout             = 3 * time.Second
	statusTimeout             = 5 * time.Second
	inventoryTimeout          = 30 * time.Second
	mutationTimeout           = 60 * time.Second
	groupPlanTimeout          = 60 * time.Second
	groupSimulateTimeout      = 60 * time.Second
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

func newSignRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "cli-" + hex.EncodeToString(random[:]), nil
}

func readErrorResponse(resp *http.Response) string {
	bodyBytes, _ := io.ReadAll(resp.Body)
	body := strings.TrimSpace(string(bodyBytes))
	if body == "" {
		return http.StatusText(resp.StatusCode)
	}

	var errorResp signerapi.ErrorResponse
	if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && errorResp.Error != "" {
		return errorResp.Error
	}
	return body
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
	req, err := http.NewRequest("GET", c.BaseURL+"/status", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, statusTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer status: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var statusResp signerapi.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	c.cacheApprovalWaitSeconds(statusResp.ApprovalWaitSeconds)

	return &statusResp, nil
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

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/plan", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, groupPlanTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var planResp signerapi.GroupPlanResponse
	if err := json.NewDecoder(resp.Body).Decode(&planResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if planResp.Error != "" {
		return nil, fmt.Errorf("group planning failed: %s", planResp.Error)
	}

	return &planResp, nil
}

// RequestGroupSimulate sends transactions to the /simulate endpoint.
// The server signs internally, calls algod simulate, and returns simulation
// output without returning signed transaction bytes.
func (c *Client) RequestGroupSimulate(requests []signerapi.SignRequest) (*signerapi.GroupSimulateResponse, error) {
	return c.RequestGroupSimulateWithContext(context.Background(), requests)
}

func (c *Client) RequestGroupSimulateWithContext(ctx context.Context, requests []signerapi.SignRequest) (*signerapi.GroupSimulateResponse, error) {
	groupReq := signerapi.GroupSignRequest{Requests: requests}
	if err := groupReq.Validate(); err != nil {
		return nil, fmt.Errorf("invalid group simulate request: %w", err)
	}

	jsonBody, err := json.Marshal(groupReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/simulate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, groupSimulateTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var simulateResp signerapi.GroupSimulateResponse
	if err := json.NewDecoder(resp.Body).Decode(&simulateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if simulateResp.Error != "" {
		return nil, fmt.Errorf("group simulation failed: %s", simulateResp.Error)
	}

	return &simulateResp, nil
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

	c.discoverApprovalWait(ctx)

	w := c.progressWriter()
	_, _ = fmt.Fprintln(w, "Waiting for approval from Signer...")

	req, err := http.NewRequest("POST", c.BaseURL+"/sign", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
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
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var groupResp signerapi.GroupSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&groupResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if groupResp.Error != "" {
		return nil, fmt.Errorf("group signing failed: %s", groupResp.Error)
	}

	_, _ = fmt.Fprintln(w, "Approved by Signer")
	return &groupResp, nil
}

// RequestComponentSign sends a role-specific component-signing request to
// /sign/component.
func (c *Client) RequestComponentSign(req signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error) {
	return c.RequestComponentSignWithContext(context.Background(), req)
}

func (c *Client) RequestComponentSignWithContext(ctx context.Context, reqBody signerapi.ComponentSignRequest) (*signerapi.ComponentSignResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create component sign request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component sign request: %w", err)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/sign/component", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, componentSignTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var componentResp signerapi.ComponentSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&componentResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if err := componentResp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid component sign response: %w", err)
	}
	return &componentResp, nil
}

// RequestGuardedAssemble sends a verified guarded transaction assembly
// request to /sign/assemble.
func (c *Client) RequestGuardedAssemble(req signerapi.GuardedAssemblyRequest) (*signerapi.GuardedAssemblyResponse, error) {
	return c.RequestGuardedAssembleWithContext(context.Background(), req)
}

func (c *Client) RequestGuardedAssembleWithContext(ctx context.Context, reqBody signerapi.GuardedAssemblyRequest) (*signerapi.GuardedAssemblyResponse, error) {
	if reqBody.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create guarded assembly request ID: %w", err)
		}
		reqBody.RequestID = requestID
	}
	if err := reqBody.Validate(); err != nil {
		return nil, fmt.Errorf("invalid guarded assembly request: %w", err)
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/sign/assemble", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, guardedAssemblyTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request to Signer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var assemblyResp signerapi.GuardedAssemblyResponse
	if err := json.NewDecoder(resp.Body).Decode(&assemblyResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if err := assemblyResp.Validate(); err != nil {
		return nil, fmt.Errorf("invalid guarded assembly response: %w", err)
	}
	return &assemblyResp, nil
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

	if resp.StatusCode == http.StatusForbidden {
		msg := readErrorResponse(resp)
		if strings.Contains(strings.ToLower(msg), "locked") {
			return &KeysResult{Locked: true}, nil
		}
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Message: msg}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{StatusCode: resp.StatusCode, Message: readErrorResponse(resp)}
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

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/admin/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, mutationTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var genResp signerapi.AdminGenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if genResp.Error != "" {
		return nil, fmt.Errorf("key generation failed: %s", genResp.Error)
	}

	return &genResp, nil
}

// AdminDeleteKey requests key deletion from Signer.
func (c *Client) AdminDeleteKey(address string) (*signerapi.AdminDeleteResponse, error) {
	return c.AdminDeleteKeyWithContext(context.Background(), address)
}

func (c *Client) AdminDeleteKeyWithContext(ctx context.Context, address string) (*signerapi.AdminDeleteResponse, error) {
	req, err := http.NewRequest("DELETE", c.BaseURL+"/admin/keys?"+url.Values{"address": []string{address}}.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, mutationTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to delete key: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var delResp signerapi.AdminDeleteResponse
	if err := json.NewDecoder(resp.Body).Decode(&delResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if delResp.Error != "" {
		return nil, fmt.Errorf("key deletion failed: %s", delResp.Error)
	}

	return &delResp, nil
}

// AdminSyncSentryReferences syncs public sentry reference candidates into
// the connected signer identity.
func (c *Client) AdminSyncSentryReferences(candidates []signerapi.SentryReferenceCandidate) (*signerapi.AdminSyncSentryReferencesResponse, error) {
	return c.AdminSyncSentryReferencesWithContext(context.Background(), candidates)
}

func (c *Client) AdminSyncSentryReferencesWithContext(ctx context.Context, candidates []signerapi.SentryReferenceCandidate) (*signerapi.AdminSyncSentryReferencesResponse, error) {
	reqBody := signerapi.AdminSyncSentryReferencesRequest{Candidates: candidates}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/admin/sentries/sync", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	reqCtx, cancel := c.requestContext(ctx, mutationTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to sync sentry references: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var syncResp signerapi.AdminSyncSentryReferencesResponse
	if err := json.NewDecoder(resp.Body).Decode(&syncResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if syncResp.Error != "" {
		return nil, fmt.Errorf("sentry reference sync failed: %s", syncResp.Error)
	}
	return &syncResp, nil
}

// GetKeyTypes fetches available key types from Signer.
func (c *Client) GetKeyTypes() (*signerapi.KeyTypesResponse, error) {
	return c.GetKeyTypesWithContext(context.Background())
}

func (c *Client) GetKeyTypesWithContext(ctx context.Context) (*signerapi.KeyTypesResponse, error) {
	req, err := http.NewRequest("GET", c.BaseURL+"/keytypes", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	reqCtx, cancel := c.requestContext(ctx, inventoryTimeout)
	defer cancel()

	resp, err := c.doRequest(reqCtx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get key types: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Debug("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("signer error (%d): %s", resp.StatusCode, readErrorResponse(resp))
	}

	var ktResp signerapi.KeyTypesResponse
	if err := json.NewDecoder(resp.Body).Decode(&ktResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &ktResp, nil
}
