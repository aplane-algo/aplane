// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/policy"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/pkg/signerapi"
)

type AuditRejectLogger interface {
	LogSignRejected(authAddress, txnSender, reason string)
}

type AuditRejectPolicyRuleLogger interface {
	LogSignRejectedWithPolicyRule(authAddress, txnSender, reason, policyRuleID string)
}

// AuditCosignerRejectLogger records cosigner policy rejections under the
// audit log's rate limit, so a caller provoking rejections cannot rotate the
// record of what the cosigner signed out of the log.
type AuditCosignerRejectLogger interface {
	LogCosignerComponentRejected(witnessKeyID, txnSender, reason, policyRuleID string)
}

type GenerateTxnDescriptionFromTxnFunc func(txn types.Transaction) string
type KnownAddressesFunc func() map[string]bool
type HasClientFunc func() bool
type RequestSigningApprovalFunc func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error)
type RequestSigningApprovalResponseFunc func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error)
type RequestSigningApprovalContextFunc func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error)
type RequestSigningApprovalResponseContextFunc func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error)

const defaultApprovalWait = 60 * time.Second

type ApprovalService struct {
	UserAutoApprove                       *bool
	ApprovalWait                          func() time.Duration
	AuditLog                              AuditRejectLogger
	Console                               Console
	GenerateTxnDescriptionFromTxn         GenerateTxnDescriptionFromTxnFunc
	KnownAddresses                        KnownAddressesFunc
	HasClient                             HasClientFunc
	RequestSigningApproval                RequestSigningApprovalFunc
	RequestSigningApprovalResponse        RequestSigningApprovalResponseFunc
	RequestSigningApprovalContext         RequestSigningApprovalContextFunc
	RequestSigningApprovalResponseContext RequestSigningApprovalResponseContextFunc
}

func (s *ApprovalService) userAutoApprove() bool {
	if s == nil || s.UserAutoApprove == nil {
		return false
	}
	return *s.UserAutoApprove
}

type approvalResponseRecorder interface {
	RecordApprovalResponse(response signerapproval.SignResponse)
}

// requestSigningApproval is the one way a signing prompt reaches the operator.
// Much of what it shows comes from the client or from the chain: an asset's
// name, an ABI method label, an auth address. Every string is escaped here, so
// none of it can drive the operator's terminal or reorder what they read.
func (s *ApprovalService) requestSigningApproval(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
	address, txnSender, description = termsafe.Line(address), termsafe.Line(txnSender), termsafe.Lines(description)
	violations = operatorSafeViolations(violations)
	var response signerapproval.SignResponse
	var err error
	if s.RequestSigningApprovalResponseContext != nil {
		response, err = s.RequestSigningApprovalResponseContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	} else if s.RequestSigningApprovalContext != nil {
		var approved bool
		approved, err = s.RequestSigningApprovalContext(ctx, requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		response = signerapproval.SignResponse{ID: requestID, Approved: approved}
	} else if s.RequestSigningApprovalResponse != nil {
		response, err = s.RequestSigningApprovalResponse(requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
	} else if s.RequestSigningApproval != nil {
		var approved bool
		approved, err = s.RequestSigningApproval(requestID, address, txnSender, description, firstValid, lastValid, violations, timeout)
		response = signerapproval.SignResponse{ID: requestID, Approved: approved}
	} else {
		return false, fmt.Errorf("signing approval callback not configured")
	}
	if err != nil {
		return false, err
	}
	if recorder, ok := s.AuditLog.(approvalResponseRecorder); ok && recorder != nil {
		recorder.RecordApprovalResponse(response)
	}
	return response.Approved, nil
}

// operatorSafeViolations is violations with every string escaped for the
// operator's terminal.
func operatorSafeViolations(violations []signerapproval.Violation) []signerapproval.Violation {
	if len(violations) == 0 {
		return violations
	}
	safe := make([]signerapproval.Violation, len(violations))
	for i, v := range violations {
		v.Field, v.Value, v.Message = termsafe.Line(v.Field), termsafe.Line(v.Value), termsafe.Lines(v.Message)
		safe[i] = v
	}
	return safe
}

func (s *ApprovalService) approvalWait() time.Duration {
	if s.ApprovalWait != nil {
		if wait := s.ApprovalWait(); wait > 0 {
			return wait
		}
	}
	return defaultApprovalWait
}

func (s *ApprovalService) logSignRejected(authAddress, txnSender, reason, policyRuleID string) {
	if s.AuditLog == nil {
		return
	}
	if policyRuleID != "" {
		if ruleLogger, ok := s.AuditLog.(AuditRejectPolicyRuleLogger); ok && ruleLogger != nil {
			ruleLogger.LogSignRejectedWithPolicyRule(authAddress, txnSender, reason, policyRuleID)
			return
		}
	}
	s.AuditLog.LogSignRejected(authAddress, txnSender, reason)
}

func reviewabilityReason(txn types.Transaction) string {
	switch txn.Type {
	case types.PaymentTx, types.AssetTransferTx, types.AssetConfigTx, types.AssetFreezeTx, types.KeyRegistrationTx:
		return ""
	case types.ApplicationCallTx:
		if txn.ApplicationID == 0 || txn.OnCompletion == types.UpdateApplicationOC {
			if len(txn.ApprovalProgram) == 0 || len(txn.ClearStateProgram) == 0 {
				return "app create/update is not reviewable without both approval and clear program bytes"
			}
		}
		return ""
	default:
		return fmt.Sprintf("transaction type %s is not reviewable in the current approval UI", txn.Type)
	}
}

func approvalWindow(txns []types.Transaction) (firstValid, lastValid uint64) {
	if len(txns) == 0 {
		return 0, 0
	}

	maxFirstValid := txns[0].FirstValid
	minLastValid := txns[0].LastValid
	for _, txn := range txns[1:] {
		if txn.FirstValid > maxFirstValid {
			maxFirstValid = txn.FirstValid
		}
		if txn.LastValid < minLastValid {
			minLastValid = txn.LastValid
		}
	}

	return uint64(maxFirstValid), uint64(minLastValid)
}

func groupApprovalAddress(req signerapi.GroupSignRequest) string {
	seen := make(map[string]struct{})
	for _, txReq := range req.Requests {
		if txReq.AuthAddress == "" {
			continue
		}
		seen[txReq.AuthAddress] = struct{}{}
	}

	switch len(seen) {
	case 0:
		return ""
	case 1:
		for addr := range seen {
			return addr
		}
	}

	return fmt.Sprintf("%d auth addresses (see details)", len(seen))
}

func BuildApprovalDescription(req signerapi.GroupSignRequest, plan *PlanResult, allTxns []types.Transaction, generateTxnDescriptionFromTxn GenerateTxnDescriptionFromTxnFunc) (groupDesc string, firstValid, lastValid uint64) {
	var b strings.Builder
	isSingleTxn := len(req.Requests) == 1

	if isSingleTxn {
		b.WriteString("=== SINGLE TRANSACTION ===\n\n")
		hasAuthorizationFeeRequirement := plan.FeeInfo.ProgramFeeContribution > 0 || plan.FeeInfo.NativePQFeeContribution > 0
		if plan.DummiesNeeded > 0 {
			b.WriteString("[MODIFIED BY SERVER]\n")
			b.WriteString(fmt.Sprintf("  • Added %d dummy transaction(s) for LogicSig arguments/opcode budget\n", plan.DummiesNeeded))
		}
		if plan.FeeInfo.TotalFees > 0 {
			if plan.DummiesNeeded == 0 {
				b.WriteString("[MODIFIED BY SERVER]\n")
			}
			b.WriteString(fmt.Sprintf("  • Group fee adjustment: +%d microAlgos\n", plan.FeeInfo.TotalFees))
		} else if plan.DummiesNeeded == 0 && hasAuthorizationFeeRequirement {
			b.WriteString("[FEE REQUIREMENT COVERED BY EXISTING FEES]\n")
		}
		if plan.FeeInfo.ProgramFeeContribution > 0 {
			b.WriteString(fmt.Sprintf("  • Required LogicSig program contribution: %d microAlgos (%d charged byte(s))\n", plan.FeeInfo.ProgramFeeContribution, plan.LogicSigResourcePlan.ChargedProgramBytes))
		}
		if plan.FeeInfo.NativePQFeeContribution > 0 {
			b.WriteString(fmt.Sprintf("  • Required native Falcon contribution: %d microAlgos\n", plan.FeeInfo.NativePQFeeContribution))
		}
		if (plan.DummiesNeeded > 0 || plan.FeeInfo.TotalFees > 0) && len(allTxns) > 1 {
			b.WriteString("  • Group ID recomputed\n")
		}
		if plan.DummiesNeeded > 0 || plan.FeeInfo.TotalFees > 0 || plan.FeeInfo.ProgramFeeContribution > 0 || plan.FeeInfo.NativePQFeeContribution > 0 {
			b.WriteString("\n")
		}
	} else {
		totalTxns := len(req.Requests)
		b.WriteString(fmt.Sprintf("=== TRANSACTION GROUP (%d transactions) ===\n", totalTxns))
		if plan.HasPassthrough {
			b.WriteString(fmt.Sprintf("[MIXED MODE: %d to sign, %d passthrough]\n", len(req.Requests)-len(plan.PassthroughIndices), len(plan.PassthroughIndices)))
		}
		if plan.HasForeign {
			signCount := len(req.Requests) - len(plan.ForeignIndices)
			if held := sendersHeld(plan.HeldForeign); held > 0 {
				b.WriteString(fmt.Sprintf("[MULTI-PARTY: %d to sign, %d not signed in this request: %d whose key this signer holds, %d foreign]\n",
					signCount, len(plan.ForeignIndices), held, len(plan.ForeignIndices)-held))
			} else {
				b.WriteString(fmt.Sprintf("[MULTI-PARTY: %d to sign, %d foreign (not signing)]\n", signCount, len(plan.ForeignIndices)))
			}
		}
		if plan.DummiesNeeded > 0 {
			b.WriteString("[MODIFIED BY SERVER]\n")
			b.WriteString(fmt.Sprintf("  • Added %d dummy transaction(s) for LogicSig arguments/opcode budget\n", plan.DummiesNeeded))
		}
		if plan.FeeInfo.TotalFees > 0 {
			if plan.DummiesNeeded == 0 {
				b.WriteString("[MODIFIED BY SERVER]\n")
			}
			b.WriteString(fmt.Sprintf("  • Group fee adjustment: +%d microAlgos across transaction(s) %v\n", plan.FeeInfo.TotalFees, approvalTransactionNumbers(plan.FeeInfo.FeeIndices)))
		} else if plan.DummiesNeeded == 0 && (plan.FeeInfo.ProgramFeeContribution > 0 || plan.FeeInfo.NativePQFeeContribution > 0) {
			b.WriteString("[FEE REQUIREMENT COVERED BY EXISTING FEES]\n")
		}
		if plan.FeeInfo.ProgramFeeContribution > 0 {
			b.WriteString(fmt.Sprintf("  • Required LogicSig program contribution: %d microAlgos (%d charged byte(s))\n", plan.FeeInfo.ProgramFeeContribution, plan.LogicSigResourcePlan.ChargedProgramBytes))
		}
		if plan.FeeInfo.NativePQFeeContribution > 0 {
			b.WriteString(fmt.Sprintf("  • Required native Falcon contribution: %d microAlgos\n", plan.FeeInfo.NativePQFeeContribution))
		}
		if (plan.DummiesNeeded > 0 || plan.FeeInfo.TotalFees > 0) && len(allTxns) > 1 {
			b.WriteString("  • Group ID recomputed\n")
		}
		b.WriteString("\n")
	}

	totalTxns := len(req.Requests)
	for i, txn := range allTxns[:len(req.Requests)] {
		if !isSingleTxn {
			var under []string
			switch held := plan.HeldForeign[i]; {
			case plan.PassthroughIndices[i]:
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [PASSTHROUGH] ---\n", i+1, totalTxns))
			case held != nil:
				var label string
				label, under = heldPositionHeading(held)
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [%s] ---\n", i+1, totalTxns, label))
			case plan.ForeignIndices[i]:
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [FOREIGN - not signing] ---\n", i+1, totalTxns))
			default:
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d ---\n", i+1, totalTxns))
			}
			for _, line := range under {
				b.WriteString(line + "\n")
			}
		}
		txReq := req.Requests[i]
		b.WriteString(describeTxnForApproval(txn, txReq, generateTxnDescriptionFromTxn))
		b.WriteString(boundedRekeyApprovalLines(boundedItemAt(plan, i)))
		if i == 0 && plan.Rotating != nil {
			b.WriteString(plan.Rotating.describe())
		}
		b.WriteString("\n")
	}

	firstValid, lastValid = approvalWindow(allTxns)
	// The daemon prints this to its console as well as prompting with it.
	return termsafe.Lines(b.String()), firstValid, lastValid
}

func approvalTransactionNumbers(indices []int) []int {
	numbers := make([]int, len(indices))
	for i, index := range indices {
		numbers[i] = index + 1
	}
	return numbers
}

// boundedItemAt is a plan's bounded item for position i, or nil.
func boundedItemAt(plan *PlanResult, i int) *boundedPlanItem {
	if plan == nil || i < 0 || i >= len(plan.BoundedItems) {
		return nil
	}
	return plan.BoundedItems[i]
}

// boundedRekeyApprovalLines names a bounded rekey's authorization for the
// operator: the group and the single-request prompts both carry it. It is
// empty for anything but a bounded rekey.
func boundedRekeyApprovalLines(item *boundedPlanItem) string {
	if item == nil || item.Path == boundedPathPureSpend {
		return ""
	}
	lines := "\n  Bounded authorization operation: REKEY" +
		"\n  Authorization: " + boundedAuthorizationLabel(item)
	if item.Metadata != nil && item.Metadata.MaxFee != nil {
		lines += fmt.Sprintf("\n  Profile maximum fee: %d microAlgos", *item.Metadata.MaxFee)
	}
	return lines
}

// boundedAuthorizationLabel names who authorizes a bounded rekey: on a cosigned
// account a declared rekey needs the cosigner too, while a listed rekey never
// asks it.
func boundedAuthorizationLabel(item *boundedPlanItem) string {
	switch item.Path {
	case boundedPathSpendingKeyRekey:
		if item.Metadata != nil && item.Metadata.Cosigner != nil {
			return "spending key and cosigner"
		}
		return "spending key only"
	case boundedPathListedRekey:
		return "spending key only, to an address on the account's rekey-to list"
	default:
		return "unknown"
	}
}

// PolicyResolver returns the policy that governs a key selector, or nil when
// policy is not loaded.
type PolicyResolver func(selector string) *policy.Config

// resolvePolicy returns the policy for position i. A nil resolver or a nil
// result means policy is not loaded; callers fail closed on nil.
func resolvePolicy(policyFor PolicyResolver, authKeys []string, i int) *policy.Config {
	if policyFor == nil {
		return nil
	}
	selector := ""
	if i < len(authKeys) {
		selector = authKeys[i]
	}
	return policyFor(selector)
}

// clientSlots returns the positions client signing judges, AllTxns[:requestCount],
// with each signer position's policy resolved through authKeys.
func clientSlots(allTxns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyFor PolicyResolver, authKeys []string, listed map[int]map[string]bool) []policyeval.Slot {
	limit := requestCount
	if limit > len(allTxns) {
		limit = len(allTxns)
	}
	slots := make([]policyeval.Slot, 0, limit)
	for i := 0; i < limit; i++ {
		switch {
		case passthroughIndices[i]:
			slots = append(slots, policyeval.Slot{Index: i, Class: policyeval.SlotPassthrough})
		case foreignIndices[i]:
			slots = append(slots, policyeval.Slot{Index: i, Class: policyeval.SlotForeign})
		default:
			slots = append(slots, policyeval.Slot{Index: i, Class: policyeval.SlotSigner, Policy: resolvePolicy(policyFor, authKeys, i), ListedRekeyTargets: listed[i]})
		}
	}
	return slots
}

// planFacts is what Always Approve reads from a /sign plan.
func planFacts(req signerapi.GroupSignRequest, plan *PlanResult) *policyeval.PlanFacts {
	if plan == nil {
		return nil
	}
	return &policyeval.PlanFacts{
		RequestCount:            len(req.Requests),
		AuthAddressPresent:      len(req.Requests) > 0 && req.Requests[0].AuthAddress != "",
		HasPassthrough:          plan.HasPassthrough,
		HasForeign:              plan.HasForeign,
		IsPreGrouped:            plan.IsPreGrouped,
		DummiesNeeded:           plan.DummiesNeeded,
		DummyCount:              len(plan.DummyTxns),
		LsigIndices:             plan.LsigIndices,
		LSigCount:               plan.FeeInfo.LSigCount,
		TotalFees:               plan.FeeInfo.TotalFees,
		ProgramFeeContribution:  plan.FeeInfo.ProgramFeeContribution,
		NativePQFeeContribution: plan.FeeInfo.NativePQFeeContribution,
	}
}

// policyRejection reports Always Deny violations as the signer's policy
// rejection.
func policyRejection(violations []policy.LintViolation, console Console) *ServiceError {
	errText := policy.JoinLintViolations(violations)
	console.Printf("[POLICY ENGINE] Rejected: %s\n", errText)
	console.Sync()
	return forbidden(fmt.Sprintf("policy engine rejected request: %s", errText))
}

// EvaluateAutoRejectionRules evaluates hard policy rules against each signable
// transaction. authKeys[i] holds the key selector whose policy governs request
// i; an empty string or a short slice resolves to the node default.
// knownAddresses is the signer-local address set used to distinguish local
// rekeys from foreign rekeys. A position whose policy cannot be resolved
// fails closed. It evaluates as if no account had a rekey-to list, so a listed
// rekey reads as foreign here; the signer's own gates (runApprovalGates) give
// each position its account's list.
func EvaluateAutoRejectionRules(allTxns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, policyFor PolicyResolver, authKeys []string, knownAddresses map[string]bool, console Console) *ServiceError {
	violations, err := policyeval.Deny(policyeval.Input{
		Group:          allTxns,
		Slots:          clientSlots(allTxns, requestCount, passthroughIndices, foreignIndices, policyFor, authKeys, nil),
		KnownAddresses: knownAddresses,
	})
	if err != nil {
		return internal(err.Error())
	}
	if len(violations) > 0 {
		return policyRejection(violations, consoleOf(console))
	}
	return nil
}

func matchesSelfNoOpTransferPlanAutoApproval(plan *PlanResult, allTxns []types.Transaction) bool {
	return policyeval.MatchesSelfNoOpPlan(allTxns, *planFacts(signerapi.GroupSignRequest{}, plan))
}

func approvalRequestID(prefix, supplied string) string {
	if supplied != "" {
		return supplied
	}
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func requestIDPreview(requestID string) string {
	if len(requestID) <= 20 {
		return requestID
	}
	return requestID[:20]
}

func (s *ApprovalService) RequestGroupApproval(req signerapi.GroupSignRequest, plan *PlanResult, groupDesc string, firstValid, lastValid uint64, txns []types.Transaction) *ServiceError {
	return s.RequestGroupApprovalWithContext(context.Background(), req, plan, groupDesc, firstValid, lastValid, txns)
}

func (s *ApprovalService) RequestGroupApprovalWithContext(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult, groupDesc string, firstValid, lastValid uint64, txns []types.Transaction) *ServiceError {
	return s.requestGroupApprovalWithContext(ctx, req, plan, groupDesc, firstValid, lastValid, txns, "")
}

func (s *ApprovalService) requestGroupApprovalWithContext(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult, groupDesc string, firstValid, lastValid uint64, txns []types.Transaction, forceReviewRuleID string) *ServiceError {
	console := consoleOf(s.Console)
	if s.userAutoApprove() {
		if forceReviewRuleID != "" {
			console.Printf("[USER AUTO-APPROVE] Satisfying review requirement (%s) without operator prompt\n", forceReviewRuleID)
		}
		console.Println("[USER AUTO-APPROVE] Group approved without operator prompt")
		console.Sync()
		return nil
	}
	if forceReviewRuleID != "" {
		console.Printf("[POLICY] Group requires manual review (%s)\n", forceReviewRuleID)
		console.Sync()
	}

	if s.HasClient == nil || !s.HasClient() {
		return unavailable("no apadmin connected - cannot approve group request")
	}

	for i, txn := range txns {
		if reason := reviewabilityReason(txn); reason != "" {
			console.Printf("[REVIEWABILITY] Blocked group approval: tx %d/%d: %s\n", i+1, len(txns), reason)
			console.Sync()
			for j, txReq := range req.Requests {
				authAddr := txReq.AuthAddress
				if plan.ForeignIndices[j] {
					authAddr = ""
				}
				s.logSignRejected(authAddr, txns[j].Sender.String(), "reviewability_blocked: "+reason, forceReviewRuleID)
			}
			return forbidden(fmt.Sprintf("group approval blocked: tx %d/%d: %s", i+1, len(txns), reason))
		}
	}

	requestID := approvalRequestID("grp", req.RequestID)
	console.Printf("[IPC] GROUP APPROVAL: Waiting for approval from apadmin TUI (request %s)...\n", requestIDPreview(requestID))
	console.Sync()

	displaySender := fmt.Sprintf("GROUP(%d txns)", len(txns))
	groupAuthAddr := groupApprovalAddress(req)

	violations := approvalpolicy.CheckGroupWarningsIn(txns, approvalpolicy.Context{
		KnownAddresses: s.groupKnownAddresses(plan), ProtocolRekeyTargets: protocolRekeyTargetsForPlan(plan),
	}, warningRekeyTargetsForPlan(plan))
	approved, err := s.requestSigningApproval(
		ctx,

		requestID,
		groupAuthAddr,
		displaySender,
		"[GROUP APPROVAL]\n"+groupDesc,
		firstValid,
		lastValid,
		violations,
		s.approvalWait(),
	)
	if err != nil {
		if errors.Is(err, signerapproval.ErrApprovalTimeout) {
			s.logGroupApprovalTimeout(req, plan, txns, forceReviewRuleID)
		}
		console.Printf("[X] Group approval error: %v\n", err)
		console.Sync()
		return unavailable(fmt.Sprintf("group approval error: %v", err))
	}
	if !approved {
		console.Println("[X] GROUP REQUEST REJECTED")
		console.Sync()
		for i, txReq := range req.Requests {
			authAddr := txReq.AuthAddress
			if plan.ForeignIndices[i] {
				authAddr = ""
			}
			s.logSignRejected(authAddr, txns[i].Sender.String(), "group_rejected_by_operator", forceReviewRuleID)
		}
		return forbidden("Group request rejected by operator")
	}

	console.Println("[OK] GROUP APPROVED")
	console.Sync()
	return nil
}

func (s *ApprovalService) RequestSingleTxnApproval(txReq signerapi.SignRequest, allTxns, txns []types.Transaction, dummiesNeeded int, firstValid, lastValid uint64) *ServiceError {
	return s.requestSingleTxnApprovalWithContext(context.Background(), "", txReq, allTxns, txns, dummiesNeeded, firstValid, lastValid, "", nil)
}

func (s *ApprovalService) RequestSingleTxnApprovalWithContext(ctx context.Context, txReq signerapi.SignRequest, allTxns, txns []types.Transaction, dummiesNeeded int, firstValid, lastValid uint64) *ServiceError {
	return s.requestSingleTxnApprovalWithContext(ctx, "", txReq, allTxns, txns, dummiesNeeded, firstValid, lastValid, "", nil)
}

// requestSingleTxnApprovalWithContext prompts for one request. bounded is its
// bounded plan item, or nil: a bounded rekey's prompt names who authorizes it,
// and the account's rekey-to list lets the warning name a listed handover as one.
func (s *ApprovalService) requestSingleTxnApprovalWithContext(ctx context.Context, suppliedRequestID string, txReq signerapi.SignRequest, allTxns, txns []types.Transaction, dummiesNeeded int, firstValid, lastValid uint64, forceReviewRuleID string, bounded *boundedPlanItem) *ServiceError {
	var listed map[string]bool
	if bounded != nil {
		listed = bounded.ListedRekeyTargets
	}
	console := consoleOf(s.Console)
	txnApproved := false
	approvalReason := ""
	decodedSender := txns[0].Sender.String()

	if s.userAutoApprove() {
		if forceReviewRuleID != "" {
			console.Printf("[USER AUTO-APPROVE] Satisfying review requirement (%s) without operator prompt\n", forceReviewRuleID)
		}
		txnApproved = true
		approvalReason = "user_auto_approve: true"
	}

	if txnApproved {
		console.Printf("[USER AUTO-APPROVE] Txn approved without operator prompt (%s)\n", approvalReason)
		console.Sync()
		return nil
	}
	if forceReviewRuleID != "" {
		console.Printf("[POLICY] Txn requires manual review (%s)\n", forceReviewRuleID)
		console.Sync()
	}

	if s.HasClient == nil || !s.HasClient() {
		return unavailable("no apadmin connected - cannot approve transaction")
	}
	if reason := reviewabilityReason(allTxns[0]); reason != "" {
		console.Printf("[REVIEWABILITY] Blocked txn approval: %s\n", reason)
		console.Sync()
		s.logSignRejected(txReq.AuthAddress, decodedSender, "reviewability_blocked: "+reason, forceReviewRuleID)
		return forbidden("transaction approval blocked: " + reason)
	}

	requestID := approvalRequestID("txn", suppliedRequestID)
	console.Println("[IPC] TXN APPROVAL: Waiting for approval from apadmin TUI...")
	console.Sync()

	txnDesc := "[TXN APPROVAL]\n"
	if dummiesNeeded > 0 {
		txnDesc += "[MODIFIED: Fee adjusted for dummy transactions]\n"
	}
	txnDesc += describeTxnForApproval(allTxns[0], txReq, s.GenerateTxnDescriptionFromTxn)
	txnDesc += boundedRekeyApprovalLines(bounded)

	violations := approvalpolicy.CheckDecodedTxnWarningsIn(allTxns[0], approvalpolicy.Context{
		KnownAddresses: s.KnownAddresses(), ListedRekeyTargets: listed,
	})
	txnDesc = appendViolationHighlights(txnDesc, violations)

	approved, err := s.requestSigningApproval(
		ctx,

		requestID,
		txReq.AuthAddress,
		decodedSender,
		txnDesc,
		firstValid,
		lastValid,
		violations,
		s.approvalWait(),
	)
	if err != nil {
		if errors.Is(err, signerapproval.ErrApprovalTimeout) {
			s.logSignRejected(txReq.AuthAddress, decodedSender, "txn_approval_timeout", forceReviewRuleID)
		}
		console.Printf("[X] Txn approval error: %v\n", err)
		console.Sync()
		return unavailable(fmt.Sprintf("txn approval error: %v", err))
	}
	if !approved {
		console.Println("[X] TXN REJECTED")
		console.Sync()
		s.logSignRejected(txReq.AuthAddress, decodedSender, "txn_rejected_by_operator", forceReviewRuleID)
		return forbidden("Transaction rejected by operator")
	}

	console.Println("[OK] TXN APPROVED")
	console.Sync()
	return nil
}

func (s *ApprovalService) logGroupApprovalTimeout(req signerapi.GroupSignRequest, plan *PlanResult, txns []types.Transaction, policyRuleID string) {
	if s.AuditLog == nil {
		return
	}
	for i, txReq := range req.Requests {
		authAddr := txReq.AuthAddress
		if plan != nil && plan.ForeignIndices[i] {
			authAddr = ""
		}
		txnSender := ""
		if i < len(txns) {
			txnSender = txns[i].Sender.String()
		}
		s.logSignRejected(authAddr, txnSender, "group_approval_timeout", policyRuleID)
	}
}

func describeTxnForApproval(txn types.Transaction, txReq signerapi.SignRequest, generateTxnDescriptionFromTxn GenerateTxnDescriptionFromTxnFunc) string {
	desc := generateTxnDescriptionFromTxn(txn)
	meta := txReq.AppCallInfo
	if meta == nil || txn.Type != types.ApplicationCallTx {
		return desc
	}

	if strings.EqualFold(strings.TrimSpace(meta.Mode), "raw") {
		return insertAppCallMetadata(desc, []string{"Mode: Raw"})
	}

	methodSig := strings.TrimSpace(meta.Method)
	if methodSig == "" {
		return desc
	}
	// An ABI call's first argument is the selector and nothing else. A longer
	// argument that merely starts with the label's selector is not an ABI
	// call of that method. A label that doesn't fit is not shown, but the
	// review says one was offered: a client naming a method the call doesn't
	// make is itself worth knowing.
	wantSelector, err := appspec.SignatureSelector(methodSig)
	if err != nil || len(txn.ApplicationArgs) == 0 || !bytes.Equal(wantSelector, txn.ApplicationArgs[0]) {
		return insertAppCallMetadata(desc, []string{abiLabelMismatchLine})
	}

	// The label is the client's. The signer holds no contract for the app, so
	// the selector is all that ties the name to the call, and a different
	// name with the same four bytes can be found by search. The review says
	// so, and shows the selector, the part the app acts on.
	return insertAppCallMetadata(desc, []string{
		abiModeLine,
		abiMethodLabel + termsafe.Line(methodSig),
		fmt.Sprintf("Selector: %x (all that ties the label to this call)", wantSelector),
	})
}

func appendViolationHighlights(desc string, violations []signerapproval.Violation) string {
	if len(violations) == 0 {
		return desc
	}

	lines := make([]string, 0, len(violations))
	for _, violation := range violations {
		switch violation.Field {
		case "CloseRemainderTo", "AssetCloseTo":
			line := "  Close remainder to: " + violation.Value
			if !strings.Contains(desc, line) {
				lines = append(lines, line)
			}
		}
	}

	if len(lines) == 0 {
		return desc
	}
	if !strings.HasSuffix(desc, "\n") {
		desc += "\n"
	}
	return desc + strings.Join(lines, "\n")
}

// The lines an ABI app call's review adds. Each says whose word it is: the
// signer verifies none of this beyond the selector bytes.
const (
	abiModeLine          = "Mode: ABI (the client's claim)"
	abiMethodLabel       = "Method (the client's label, not verified): "
	abiLabelMismatchLine = "Note: the client named an ABI method that does not match this call's first argument; the name is not shown"
)

func insertAppCallMetadata(desc string, extraLines []string) string {
	lines := strings.Split(desc, "\n")
	if len(lines) == 0 {
		return desc
	}
	insertAt := len(lines)
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "  ") {
			insertAt = i
			break
		}
	}
	lines = append(lines[:insertAt], append(extraLines, lines[insertAt:]...)...)

	return strings.Join(lines, "\n")
}
