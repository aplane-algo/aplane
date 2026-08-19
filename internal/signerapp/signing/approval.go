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
	"github.com/aplane-algo/aplane/internal/signerapi"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	signingutil "github.com/aplane-algo/aplane/internal/signing"
)

type AuditRejectLogger interface {
	LogSignRejected(authAddress, txnSender, reason string)
}

type AuditRejectPolicyRuleLogger interface {
	LogSignRejectedWithPolicyRule(authAddress, txnSender, reason, policyRuleID string)
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
	EncodeTxnToHex                        func(txn types.Transaction) string
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

func (s *ApprovalService) requestSigningApproval(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error) {
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
			b.WriteString(fmt.Sprintf("[MULTI-PARTY: %d to sign, %d foreign (not signing)]\n", signCount, len(plan.ForeignIndices)))
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
			if plan.PassthroughIndices[i] {
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [PASSTHROUGH] ---\n", i+1, totalTxns))
			} else if plan.ForeignIndices[i] {
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d [FOREIGN - not signing] ---\n", i+1, totalTxns))
			} else {
				b.WriteString(fmt.Sprintf("--- Transaction %d of %d ---\n", i+1, totalTxns))
			}
		}
		txReq := req.Requests[i]
		b.WriteString(describeTxnForApproval(txn, txReq, generateTxnDescriptionFromTxn))
		if i < len(plan.BoundedItems) && plan.BoundedItems[i] != nil && plan.BoundedItems[i].Path != boundedPathPureSpend {
			item := plan.BoundedItems[i]
			b.WriteString("\n  Bounded authorization contract admin operation: REKEY")
			b.WriteString("\n  Authorization: " + boundedAuthorizationLabel(item))
			b.WriteString(fmt.Sprintf("\n  Profile maximum fee: %d microAlgos", item.Metadata.MaxFee))
		}
		b.WriteString("\n")
	}

	firstValid, lastValid = approvalWindow(allTxns)
	return b.String(), firstValid, lastValid
}

func approvalTransactionNumbers(indices []int) []int {
	numbers := make([]int, len(indices))
	for i, index := range indices {
		numbers[i] = index + 1
	}
	return numbers
}

func boundedAuthorizationLabel(item *boundedPlanItem) string {
	switch item.Path {
	case boundedPathSpendingKeyRekey:
		return "spending key only"
	case boundedPathAdminKeyRekey:
		return "external contract admin key " + item.Metadata.AdminKeyID
	default:
		return "unknown"
	}
}

// EvaluateAutoRejectionRules evaluates hard policy rules against each signable transaction.
// authKeys[i] holds the concrete signing authority key for request i and is
// used to pick a key override from policyCfg.KeyOverrides; an empty string or a
// nil slice selects the identity-wide config. knownAddresses is the signer-local
// address set used to distinguish local rekeys from foreign rekeys.
func EvaluateAutoRejectionRules(allTxns []types.Transaction, requestCount int, passthroughIndices, foreignIndices map[int]bool, isGroup bool, policyCfg *policy.Config, authKeys []string, knownAddresses map[string]bool, routingExemptIndices map[int]bool, console Console) *ServiceError {
	console = consoleOf(console)
	var violations []policy.LintViolation

	if isGroup {
		violations = append(violations, policy.CheckGroupPolicyLints(allTxns, policyCfg)...)
	}

	limit := requestCount
	if limit > len(allTxns) {
		limit = len(allTxns)
	}
	for i := 0; i < limit; i++ {
		if passthroughIndices[i] || foreignIndices[i] {
			continue
		}
		txn := allTxns[i]
		cfg := policyCfg
		if policyCfg != nil && i < len(authKeys) && authKeys[i] != "" {
			cfg = policyCfg.ForKey(authKeys[i])
		}
		txnViolations := policy.CheckTxnPolicyLintsWithKnownAddresses(txn, txn.Sender.String(), cfg, knownAddresses)
		txnViolations = append(txnViolations, policy.CheckTxnTransferRoutingPolicyLints(txn, cfg, routingExemptIndices[i])...)
		for j := range txnViolations {
			txnViolations[j].TxnIndex = i
		}
		violations = append(violations, txnViolations...)
	}

	if len(violations) > 0 {
		errText := policy.JoinLintViolations(violations)
		console.Printf("[POLICY ENGINE] Rejected: %s\n", errText)
		console.Sync()
		return forbidden(fmt.Sprintf("policy engine rejected request: %s", errText))
	}

	return nil
}

// EvaluateAutoApprovalRules evaluates explicit low-risk approval rules after
// hard rejection policy has passed and before the default approval path runs.
func EvaluateAutoApprovalRules(req signerapi.GroupSignRequest, plan *PlanResult, allTxns []types.Transaction, policyCfg *policy.Config) (ruleID string, approved bool) {
	if policyCfg == nil || plan == nil {
		return "", false
	}
	if len(req.Requests) != 1 || len(allTxns) == 0 {
		return "", false
	}
	if plan.HasPassthrough || plan.HasForeign || plan.IsPreGrouped {
		return "", false
	}
	if plan.PassthroughIndices[0] || plan.ForeignIndices[0] {
		return "", false
	}
	if req.Requests[0].AuthAddress == "" {
		return "", false
	}

	cfg := policyCfg
	if req.Requests[0].AuthAddress != "" {
		cfg = policyCfg.ForKey(req.Requests[0].AuthAddress)
	}
	if cfg == nil || !cfg.AutoApproveSelfNoOpTransfer {
		return "", false
	}
	if !matchesSelfNoOpTransferPlanAutoApproval(plan, allTxns) {
		return "", false
	}
	return policy.AutoApproveSelfNoOpTransferRuleID, true
}

func routingExemptIndicesForPlan(plan *PlanResult, allTxns []types.Transaction) map[int]bool {
	if !matchesSelfNoOpTransferPlanAutoApproval(plan, allTxns) {
		return nil
	}
	return map[int]bool{0: true}
}

func matchesSelfNoOpTransferPlanAutoApproval(plan *PlanResult, allTxns []types.Transaction) bool {
	if plan.FeeInfo.ProgramFeeContribution != 0 || plan.FeeInfo.NativePQFeeContribution != 0 {
		return false
	}
	dummyCount := len(plan.DummyTxns)
	if plan.DummiesNeeded != dummyCount || len(allTxns) != 1+dummyCount {
		return false
	}
	if dummyCount == 0 {
		return plan.FeeInfo.TotalFees == 0 && policy.MatchesSelfNoOpTransferAutoApproval(allTxns[0])
	}

	if len(plan.LsigIndices) != 1 || plan.LsigIndices[0] != 0 || plan.FeeInfo.LSigCount != 1 {
		return false
	}
	maxDummyFees := uint64(dummyCount) * policy.SelfNoOpTransferMaxFeeMicroAlgos
	if plan.FeeInfo.TotalFees == 0 || plan.FeeInfo.TotalFees > maxDummyFees {
		return false
	}

	normalized := allTxns[0]
	if uint64(normalized.Fee) < plan.FeeInfo.TotalFees {
		return false
	}
	normalized.Fee = types.MicroAlgos(uint64(normalized.Fee) - plan.FeeInfo.TotalFees)
	normalized.Group = types.Digest{}
	if !policy.MatchesSelfNoOpTransferAutoApproval(normalized) {
		return false
	}

	for i, dummy := range allTxns[1:] {
		if !matchesSignerAddedDummyForSelfNoOp(dummy, allTxns[0], i) {
			return false
		}
	}
	return true
}

func matchesSignerAddedDummyForSelfNoOp(dummy, original types.Transaction, index int) bool {
	if dummy.Type != types.PaymentTx {
		return false
	}
	dummyAddr, err := signingutil.DummyAddress()
	if err != nil {
		return false
	}
	if dummy.Sender != dummyAddr || dummy.Receiver != dummyAddr || dummy.Amount != 0 {
		return false
	}
	if dummy.Fee != 0 || !dummy.RekeyTo.IsZero() || !dummy.CloseRemainderTo.IsZero() {
		return false
	}
	if dummy.GenesisID != original.GenesisID || dummy.GenesisHash != original.GenesisHash {
		return false
	}
	if dummy.FirstValid != original.FirstValid || dummy.LastValid != original.LastValid {
		return false
	}
	if original.Group == (types.Digest{}) || dummy.Group != original.Group {
		return false
	}
	if len(dummy.Note) != 1 || dummy.Note[0] != byte(index) {
		return false
	}
	if dummy.Lease != ([32]byte{}) {
		return false
	}
	return true
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
	if s.userAutoApprove() && forceReviewRuleID == "" {
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

	violations := approvalpolicy.CheckGroupWarnings(txns, s.KnownAddresses())
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
	return s.requestSingleTxnApprovalWithContext(context.Background(), "", txReq, allTxns, txns, dummiesNeeded, firstValid, lastValid, "")
}

func (s *ApprovalService) RequestSingleTxnApprovalWithContext(ctx context.Context, txReq signerapi.SignRequest, allTxns, txns []types.Transaction, dummiesNeeded int, firstValid, lastValid uint64) *ServiceError {
	return s.requestSingleTxnApprovalWithContext(ctx, "", txReq, allTxns, txns, dummiesNeeded, firstValid, lastValid, "")
}

func (s *ApprovalService) requestSingleTxnApprovalWithContext(ctx context.Context, suppliedRequestID string, txReq signerapi.SignRequest, allTxns, txns []types.Transaction, dummiesNeeded int, firstValid, lastValid uint64, forceReviewRuleID string) *ServiceError {
	console := consoleOf(s.Console)
	txnApproved := false
	approvalReason := ""
	decodedSender := txns[0].Sender.String()

	if s.userAutoApprove() && forceReviewRuleID == "" {
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

	modifiedTxnHex := s.EncodeTxnToHex(allTxns[0])
	violations := approvalpolicy.CheckTxnWarnings(modifiedTxnHex, s.KnownAddresses())
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
	if len(txn.ApplicationArgs) == 0 || len(txn.ApplicationArgs[0]) < 4 {
		return desc
	}

	wantSelector, err := appspec.SignatureSelector(methodSig)
	if err != nil || !bytes.Equal(wantSelector, txn.ApplicationArgs[0][:4]) {
		return desc
	}

	return insertAppCallMetadata(desc, []string{"Mode: ABI", "Method: " + methodSig})
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

func insertAppCallMetadata(desc string, extraLines []string) string {
	lines := strings.Split(desc, "\n")
	if len(lines) == 0 {
		return desc
	}
	if len(extraLines) > 0 && extraLines[0] == "Mode: ABI" && strings.HasPrefix(lines[0], "App Call:") {
		lines[0] = strings.Replace(lines[0], "App Call:", "App Call [ABI]:", 1)
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
