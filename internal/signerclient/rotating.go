// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aplane-algo/aplane/pkg/signerapi"
)

// PrepareRotatingWithContext asks the signer to prepare one rotating account
// spend. Preparation reads the chain and stores nothing; it needs no
// approval.
func (c *Client) PrepareRotatingWithContext(ctx context.Context, req signerapi.RotatingPrepareRequest) (*signerapi.RotatingPrepareResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rotating prepare request: %w", err)
	}
	return doJSON[signerapi.RotatingPrepareResponse](c, ctx, http.MethodPost, "/sign/rotating/prepare", req, groupPlanTimeout, "failed to make request to Signer")
}

// SignRotatingWithContext asks the signer to sign a prepared rotating group.
// It waits for operator approval and cancels the pending approval if ctx
// ends first.
func (c *Client) SignRotatingWithContext(ctx context.Context, req signerapi.RotatingSignRequest) (*signerapi.RotatingSignResponse, error) {
	if req.RequestID == "" {
		requestID, err := newSignRequestID()
		if err != nil {
			return nil, fmt.Errorf("failed to create sign request ID: %w", err)
		}
		req.RequestID = requestID
	}
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rotating sign request: %w", err)
	}
	jsonBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	var resp signerapi.RotatingSignResponse
	err = c.postSignApprovalRequest(ctx, "/sign/rotating/sign", req.RequestID, jsonBody, func(r *http.Response) error {
		if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
