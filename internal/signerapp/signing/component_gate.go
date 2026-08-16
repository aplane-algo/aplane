// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// gateUserComponentSigning runs the shared signer-domain approval gates for a
// user-role component signing plan: the same hard rejection, always-review,
// and operator approval semantics as ordinary /sign, with the guarded account
// as the policy key for each target position. Every non-target group position
// is a foreign leg this signer does not sign but the operator still reviews.
// It returns the matched always-review rule ID for approval audit events.
func (s *Service) gateUserComponentSigning(ctx context.Context, identityID string, plan *ComponentSignPlan) (string, *ServiceError) {
	if plan == nil || plan.Group == nil {
		return "", internal("component sign plan is nil")
	}
	if s.Approval == nil {
		return "", internal("signing service approval is not configured")
	}

	allTxns := make([]types.Transaction, len(plan.Group.Entries))
	for i, entry := range plan.Group.Entries {
		allTxns[i] = entry.Txn
	}
	targetIndices := make(map[int]bool, len(plan.Targets))
	for _, target := range plan.Targets {
		targetIndices[target.TargetIndex] = true
	}
	foreignIndices := make(map[int]bool)
	authKeys := make([]string, len(allTxns))
	for i := range allTxns {
		if targetIndices[i] {
			authKeys[i] = plan.ComponentKey
			continue
		}
		foreignIndices[i] = true
	}

	console := consoleOf(s.Console)
	groupDesc, firstValid, lastValid := buildComponentApprovalDescription(plan, allTxns, targetIndices, s.GenerateTxnDescriptionFromTxn)

	console.Println("\n" + strings.Repeat("-", 60))
	console.Println("GUARDED COMPONENT SIGNATURE REQUEST")
	console.Println(strings.Repeat("=", 60))
	console.Println(groupDesc)
	console.Sync()

	return s.runApprovalGates(ctx, gateInput{
		AllTxns:        allTxns,
		EvalCount:      len(allTxns),
		ForeignIndices: foreignIndices,
		IsGroup:        len(allTxns) > 1,
		AuthKeys:       authKeys,
		KnownAddresses: s.knownAddresses(nil),
		LogRejection: func(reason string) {
			s.logUserComponentRejections(identityID, plan, "policy_engine_rejected: "+reason)
		},
		RequestOperatorApproval: func(ctx context.Context, forceReviewRuleID string) *ServiceError {
			return s.Approval.requestComponentApprovalWithContext(ctx, identityID, plan, allTxns, groupDesc, firstValid, lastValid, forceReviewRuleID)
		},
	}, console)
}

// preflightGuardedAccountKeyMetadata verifies from signer inventory metadata
// that the requested guarded account key exists locally and is a guarded
// account key. It deliberately reads no private key material: it runs before
// the approval gates, so rejected requests and operator prompts never trigger
// key decryption. The key is decrypted only after the gates pass, under the
// operation lease.
func (s *Service) preflightGuardedAccountKeyMetadata(identityID, guardedAccount string) *ServiceError {
	if s.Planner == nil || s.Planner.Snapshot == nil {
		return internal("signing service planner is not configured")
	}
	snapshot := s.Planner.Snapshot(identityID)
	if _, ok := snapshot.KeyFiles[guardedAccount]; !ok {
		return badRequest(fmt.Sprintf("guarded account key %q not found", guardedAccount))
	}
	keyType := snapshot.KeyTypes[guardedAccount]
	if !keytypes.IsGuardedAccountKeyType(keyType) {
		return badRequest(fmt.Sprintf("key %q is %s, not a guarded account key", guardedAccount, keyType))
	}
	return nil
}

func buildComponentApprovalDescription(plan *ComponentSignPlan, allTxns []types.Transaction, targetIndices map[int]bool, generateTxnDescriptionFromTxn GenerateTxnDescriptionFromTxnFunc) (groupDesc string, firstValid, lastValid uint64) {
	var b strings.Builder
	total := len(allTxns)

	if total == 1 {
		b.WriteString("=== GUARDED SINGLE TRANSACTION ===\n\n")
	} else {
		b.WriteString(fmt.Sprintf("=== GUARDED TRANSACTION GROUP (%d transactions) ===\n", total))
		b.WriteString(fmt.Sprintf("[GUARDED COMPONENT: %d target(s) to sign, %d foreign (not signing)]\n", len(targetIndices), total-len(targetIndices)))
		b.WriteString("\n")
	}

	for i, txn := range allTxns {
		if total > 1 {
			if targetIndices[i] {
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [GUARDED TARGET] ---\n", i+1, total))
			} else {
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [FOREIGN - not signing] ---\n", i+1, total))
			}
		}
		b.WriteString(describeTxnForApproval(txn, signerapi.SignRequest{}, generateTxnDescriptionFromTxn))
		b.WriteString("\n")
	}

	firstValid, lastValid = approvalWindow(allTxns)
	return b.String(), firstValid, lastValid
}

func (s *ApprovalService) requestComponentApprovalWithContext(ctx context.Context, identityID string, plan *ComponentSignPlan, allTxns []types.Transaction, groupDesc string, firstValid, lastValid uint64, forceReviewRuleID string) *ServiceError {
	console := consoleOf(s.Console)
	if s.userAutoApprove() && forceReviewRuleID == "" {
		console.Println("[USER AUTO-APPROVE] Guarded component request approved without operator prompt")
		console.Sync()
		return nil
	}
	if forceReviewRuleID != "" {
		console.Printf("[POLICY] Guarded component request requires manual review (%s)\n", forceReviewRuleID)
		console.Sync()
	}

	if s.HasClient == nil || !s.HasClient() {
		return unavailable("no apadmin connected - cannot approve guarded component request")
	}

	for i, txn := range allTxns {
		if reason := reviewabilityReason(txn); reason != "" {
			console.Printf("[REVIEWABILITY] Blocked guarded component approval: tx %d/%d: %s\n", i+1, len(allTxns), reason)
			console.Sync()
			s.logComponentRejected(identityID, plan, "reviewability_blocked: "+reason, forceReviewRuleID)
			return forbidden(fmt.Sprintf("guarded component approval blocked: tx %d/%d: %s", i+1, len(allTxns), reason))
		}
	}

	requestID := approvalRequestID("cmp", plan.RequestID)
	console.Printf("[IPC] GUARDED COMPONENT APPROVAL: Waiting for approval from apadmin TUI (request %s)...\n", requestIDPreview(requestID))
	console.Sync()

	displaySender := fmt.Sprintf("GUARDED(%d txns)", len(allTxns))
	if len(allTxns) == 1 && len(plan.Targets) == 1 {
		displaySender = plan.Targets[0].Sender
	}

	var knownAddresses map[string]bool
	if s.KnownAddresses != nil {
		knownAddresses = s.KnownAddresses()
	}
	violations := approvalpolicy.CheckGroupWarnings(allTxns, knownAddresses)
	approved, err := s.requestSigningApproval(
		ctx,
		identityID,
		requestID,
		plan.ComponentKey,
		displaySender,
		"[GUARDED COMPONENT APPROVAL]\n"+groupDesc,
		firstValid,
		lastValid,
		violations,
		s.approvalWait(),
	)
	if err != nil {
		if errors.Is(err, signerapproval.ErrApprovalTimeout) {
			s.logComponentRejected(identityID, plan, "component_approval_timeout", forceReviewRuleID)
		}
		console.Printf("[X] Guarded component approval error: %v\n", err)
		console.Sync()
		return unavailable(fmt.Sprintf("guarded component approval error: %v", err))
	}
	if !approved {
		console.Println("[X] GUARDED COMPONENT REQUEST REJECTED")
		console.Sync()
		s.logComponentRejected(identityID, plan, "component_rejected_by_operator", forceReviewRuleID)
		return forbidden("Guarded component request rejected by operator")
	}

	console.Println("[OK] GUARDED COMPONENT REQUEST APPROVED")
	console.Sync()
	return nil
}

func (s *ApprovalService) logComponentRejected(identityID string, plan *ComponentSignPlan, reason, policyRuleID string) {
	for _, target := range plan.Targets {
		s.logSignRejected(identityID, plan.ComponentKey, target.Sender, reason, policyRuleID)
	}
}

func (s *Service) logUserComponentRejections(identityID string, plan *ComponentSignPlan, reason string) {
	rejectLogger, ok := s.AuditLog.(policyAuditLogger)
	if !ok || rejectLogger == nil || plan == nil {
		return
	}
	for _, target := range plan.Targets {
		rejectLogger.LogSignRejected(identityID, plan.ComponentKey, target.Sender, reason)
	}
}

func (s *Service) logUserComponentApproved(identityID string, plan *ComponentSignPlan, policyRuleID string) {
	if s.AuditLog == nil || plan == nil {
		return
	}
	for _, target := range plan.Targets {
		details := fmt.Sprintf("user component signature target %d signed", target.TargetIndex)
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditApprovePolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignApprovedWithPolicyRule(identityID, plan.ComponentKey, target.Sender, details, policyRuleID)
				continue
			}
		}
		s.AuditLog.LogSignApproved(identityID, plan.ComponentKey, target.Sender, details)
	}
}
