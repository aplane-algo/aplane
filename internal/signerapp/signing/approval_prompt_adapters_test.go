// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"time"

	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

// The signer asks the operator through RequestSigningApprovalPrompt alone.
// These adapters let a test state its decision in terms of the prompt's
// fields.

// promptFromDecision answers each prompt with decide's approval.
func promptFromDecision(decide func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error)) RequestSigningApprovalPromptFunc {
	return func(_ context.Context, p signerapproval.Prompt, timeout time.Duration) (signerapproval.SignResponse, error) {
		approved, err := decide(p.RequestID, p.Address, p.TxnSender, p.Description, p.FirstValid, p.LastValid, p.Violations, timeout)
		return signerapproval.SignResponse{ID: p.RequestID, Approved: approved}, err
	}
}

// promptFromResponse answers each prompt with respond's response.
func promptFromResponse(respond func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error)) RequestSigningApprovalPromptFunc {
	return func(_ context.Context, p signerapproval.Prompt, timeout time.Duration) (signerapproval.SignResponse, error) {
		return respond(p.RequestID, p.Address, p.TxnSender, p.Description, p.FirstValid, p.LastValid, p.Violations, timeout)
	}
}

// promptFromContextDecision is promptFromDecision for a decision that also
// reads the request's context.
func promptFromContextDecision(decide func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error)) RequestSigningApprovalPromptFunc {
	return func(ctx context.Context, p signerapproval.Prompt, timeout time.Duration) (signerapproval.SignResponse, error) {
		approved, err := decide(ctx, p.RequestID, p.Address, p.TxnSender, p.Description, p.FirstValid, p.LastValid, p.Violations, timeout)
		return signerapproval.SignResponse{ID: p.RequestID, Approved: approved}, err
	}
}

// promptFromContextResponse is promptFromResponse for a response that also
// reads the request's context.
func promptFromContextResponse(respond func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error)) RequestSigningApprovalPromptFunc {
	return func(ctx context.Context, p signerapproval.Prompt, timeout time.Duration) (signerapproval.SignResponse, error) {
		return respond(ctx, p.RequestID, p.Address, p.TxnSender, p.Description, p.FirstValid, p.LastValid, p.Violations, timeout)
	}
}
