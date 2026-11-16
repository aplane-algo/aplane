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

	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/appspec"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/internal/txnreview"
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

// DescribeTxnFunc describes a transaction for review, as data.
type DescribeTxnFunc func(txn types.Transaction) txnreview.Details

// KnownAddressesFunc returns every address the signer holds an aplane key
// for, of any key type. The daemon supplies Runtime.KnownAddresses.
type KnownAddressesFunc func() map[string]bool

type HasClientFunc func() bool
type RequestSigningApprovalFunc func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error)
type RequestSigningApprovalResponseFunc func(requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error)
type RequestSigningApprovalContextFunc func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (bool, error)
type RequestSigningApprovalResponseContextFunc func(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, timeout time.Duration) (signerapproval.SignResponse, error)

// RequestSigningApprovalPromptFunc shows a whole prompt, its review included.
// The daemon supplies it; the four forms above carry the text alone.
type RequestSigningApprovalPromptFunc func(ctx context.Context, prompt signerapproval.Prompt, timeout time.Duration) (signerapproval.SignResponse, error)

const defaultApprovalWait = 60 * time.Second

type ApprovalService struct {
	UserAutoApprove                       *bool
	ApprovalWait                          func() time.Duration
	AuditLog                              AuditRejectLogger
	Console                               Console
	KnownAddresses                        KnownAddressesFunc
	HasClient                             HasClientFunc
	RequestSigningApproval                RequestSigningApprovalFunc
	RequestSigningApprovalResponse        RequestSigningApprovalResponseFunc
	RequestSigningApprovalContext         RequestSigningApprovalContextFunc
	RequestSigningApprovalResponseContext RequestSigningApprovalResponseContextFunc
	RequestSigningApprovalPrompt          RequestSigningApprovalPromptFunc
	// Chain reads the review's accounts from the signer's node before an
	// operator is asked. nil reads nothing.
	Chain ReviewChain
	// ReviewChainTimeout bounds that read. Zero means
	// DefaultReviewChainTimeout.
	ReviewChainTimeout time.Duration
}

// planKnownAddresses is the address set the gates and the approval warnings
// treat as the signer's own: the plan's, from the key snapshot it was planned
// with (a rotating plan names its rotation target in it), or the runtime's
// key-file addresses when there is no plan set.
func (s *ApprovalService) planKnownAddresses(plan *PlanResult) map[string]bool {
	if plan != nil && plan.KnownAddresses != nil {
		return plan.KnownAddresses
	}
	if s == nil || s.KnownAddresses == nil {
		return nil
	}
	return s.KnownAddresses()
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
func (s *ApprovalService) requestSigningApproval(ctx context.Context, requestID, address, txnSender, description string, firstValid, lastValid uint64, violations []signerapproval.Violation, review *txnreview.Review, timeout time.Duration) (bool, error) {
	address, txnSender, description = termsafe.Line(address), termsafe.Line(txnSender), termsafe.Lines(description)
	violations = operatorSafeViolations(violations)
	if review != nil {
		safe := review.Safe()
		review = &safe
	}
	var response signerapproval.SignResponse
	var err error
	if s.RequestSigningApprovalPrompt != nil {
		response, err = s.RequestSigningApprovalPrompt(ctx, signerapproval.Prompt{
			RequestID: requestID, Address: address, TxnSender: txnSender, Description: description,
			FirstValid: firstValid, LastValid: lastValid, Violations: violations, Review: review,
		}, timeout)
	} else if s.RequestSigningApprovalResponseContext != nil {
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

// review is the review a request's prompt is made from: buildReview, completed
// with what the signer knows beyond the request. The prompt's text and its
// warnings both come from it, so they cannot disagree with what the review
// shows.
func (s *ApprovalService) review(req signerapi.GroupSignRequest, plan *PlanResult, allTxns []types.Transaction, describe DescribeTxnFunc) txnreview.Review {
	review := buildReview(req, plan, allTxns, describe)
	s.completeReview(&review, plan, allTxns[:len(req.Requests)])
	return review
}

// buildReview is what the operator is shown of a request: how it is made up,
// what planning did to it, and each requested transaction. The text of every
// prompt is printed from it.
func buildReview(req signerapi.GroupSignRequest, plan *PlanResult, allTxns []types.Transaction, describe DescribeTxnFunc) txnreview.Review {
	total := len(req.Requests)
	review := txnreview.Review{Group: total != 1}
	review.Changes = planChanges(plan, allTxns, review.Group)
	if review.Group {
		if plan.HasPassthrough {
			review.Banners = append(review.Banners, fmt.Sprintf("[MIXED MODE: %d to sign, %d passthrough]", total-len(plan.PassthroughIndices), len(plan.PassthroughIndices)))
		}
		if plan.HasForeign {
			signCount := total - len(plan.ForeignIndices)
			if held := sendersHeld(plan.HeldForeign); held > 0 {
				review.Banners = append(review.Banners, fmt.Sprintf("[MULTI-PARTY: %d to sign, %d not signed in this request: %d whose key this signer holds, %d foreign]",
					signCount, len(plan.ForeignIndices), held, len(plan.ForeignIndices)-held))
			} else {
				review.Banners = append(review.Banners, fmt.Sprintf("[MULTI-PARTY: %d to sign, %d foreign (not signing)]", signCount, len(plan.ForeignIndices)))
			}
		}
	}

	for i, txn := range allTxns[:total] {
		item := reviewItem(txn, req.Requests[i], describe, boundedItemAt(plan, i))
		switch held := plan.HeldForeign[i]; {
		case plan.PassthroughIndices[i]:
			item.Position = txnreview.PositionPassthrough
			item.Label = "PASSTHROUGH"
			item.Notes = []txnreview.Field{passthroughAuthorization(plan.PassthroughSignedTxns[i])}
		case held != nil:
			item.Position = txnreview.PositionHeld
			item.Label, item.Notes = heldPositionHeading(held)
		case plan.ForeignIndices[i]:
			item.Position = txnreview.PositionForeign
			item.Label = "FOREIGN - not signing"
		default:
			item.Position = txnreview.PositionSign
			// The header names one key or a count of them; each
			// position says which of this signer's keys signs it.
			item.Notes = []txnreview.Field{{Label: protocol.ReviewNoteSigningKey, Value: req.Requests[i].AuthAddress}}
		}
		if i == 0 && plan.Rotating != nil {
			item.Details.Fields = append(item.Details.Fields, plan.Rotating.describe())
		}
		review.Items = append(review.Items, item)
	}
	return review
}

// completeReview adds to a review what the signer knows beyond the request:
// each transaction's findings, judged as the prompt's warnings judge them,
// the severity those findings give its effects, and which of the accounts
// are this signer's own.
func (s *ApprovalService) completeReview(review *txnreview.Review, plan *PlanResult, txns []types.Transaction) {
	known := s.planKnownAddresses(plan)
	ctx := approvalpolicy.Context{
		KnownAddresses: known, InvalidRekeyTargets: invalidRekeyTargetsForPlan(plan),
		ProtocolRekeyTargets: protocolRekeyTargetsForPlan(plan),
	}
	listed := warningRekeyTargetsForPlan(plan)
	for i := range review.Items {
		if i >= len(txns) {
			break
		}
		txnCtx := ctx
		txnCtx.ListedRekeyTargets = listed[i]
		findings := txnreview.Findings(txns[i], txnCtx)
		review.Items[i].Findings = findings
		review.Items[i].Details.Mark(findings)
	}
	review.SetParties(
		func(address string) bool { return known[address] },
		func(item int) string {
			if plan == nil || item >= len(plan.AuthKeyTypes) {
				return ""
			}
			return plan.AuthKeyTypes[item]
		},
	)
	review.SetFindings()
}

// reviewViolations are a review's findings as the prompt's warnings: each
// transaction's, then the request's as a whole. positioned prefixes each
// transaction's field with its position, as the group prompt does.
func reviewViolations(review *txnreview.Review, positioned bool) []signerapproval.Violation {
	var violations []signerapproval.Violation
	for i, item := range review.Items {
		for _, finding := range item.Findings {
			v := approvalpolicy.Violation(finding)
			if positioned {
				v.Field = fmt.Sprintf("Tx %d/%d: %s", i+1, len(review.Items), v.Field)
			}
			violations = append(violations, v)
		}
	}
	for _, finding := range review.Findings {
		violations = append(violations, approvalpolicy.Violation(finding))
	}
	return violations
}

// planChanges tells the operator what planning did to the request: the
// dummies it added, the fee it raised and what for, and a recomputed group
// ID. The single-transaction prompt and the group prompt both carry it. A
// frozen request is changed by nothing here: it is shown as checked, with
// what its fees already pay, the fee added when it was prepared included,
// and a lone transaction is not called a group.
func planChanges(plan *PlanResult, allTxns []types.Transaction, group bool) txnreview.Changes {
	fees := plan.FeeInfo
	changes := txnreview.Changes{Frozen: plan.Frozen, Dummies: plan.DummiesNeeded, FeeAdded: fees.TotalFees}
	add := func(format string, args ...any) {
		changes.Lines = append(changes.Lines, fmt.Sprintf(format, args...))
	}
	contributions := fees.ProgramFeeContribution > 0 || fees.NativePQFeeContribution > 0
	// What authorization requires the fees to pay beyond the dummies. Each
	// contribution is rounded up to a whole microAlgo on its own, while the
	// fee adjustment rounds the group's total once, so the listed parts need
	// not add up to it. The program contribution, the one that is usually a
	// fraction of a microAlgo per byte, is given as approximate.
	addContributions := func() {
		if c := fees.ProgramFeeContribution; c > 0 {
			add("Required LogicSig program contribution: about %d microAlgos (%d charged byte(s))", c, plan.LogicSigResourcePlan.ChargedProgramBytes)
		}
		if c := fees.NativePQFeeContribution; c > 0 {
			add("Required native Falcon contribution: %d microAlgos", c)
		}
	}
	if plan.Frozen {
		if len(allTxns) > 1 {
			changes.Heading = "[FROZEN GROUP: checked as sent, not changed by this request]"
		} else {
			changes.Heading = "[FROZEN TRANSACTION: checked as sent, not changed by this request]"
		}
		if plan.DummiesNeeded > 0 {
			add("%d dummy transaction(s) for LogicSig arguments/opcode budget", plan.DummiesNeeded)
		}
		// Only a rotating spend reaches here with a raised fee: prepare
		// added it, to the spend. A /sign/component group is never raised.
		// It is worded as something done earlier, not as the planning
		// prompt's "Group fee adjustment", which under this header would read
		// as a change this request made; and it names the spend, since the
		// header may call the request a lone transaction.
		if fees.TotalFees > 0 {
			add("%d microAlgos of fee added when the spend was prepared", fees.TotalFees)
		}
		addContributions()
		if plan.DummiesNeeded > 0 || fees.TotalFees > 0 || contributions {
			add("The fees shown already include these; this request adds no dummies or fees")
		}
		return changes
	}
	if plan.DummiesNeeded > 0 || fees.TotalFees > 0 {
		changes.Heading = "[MODIFIED BY SERVER]"
	} else if contributions {
		changes.Heading = "[FEE REQUIREMENT COVERED BY EXISTING FEES]"
	}
	if plan.DummiesNeeded > 0 {
		add("Added %d dummy transaction(s) for LogicSig arguments/opcode budget", plan.DummiesNeeded)
	}
	// The fee this request's planning added for the signer's authorization
	// charge, and where, when it added one.
	if fees.TotalFees > 0 {
		if group {
			add("Group fee adjustment: +%d microAlgos across transaction(s) %v", fees.TotalFees, approvalTransactionNumbers(fees.FeeIndices))
		} else {
			add("Group fee adjustment: +%d microAlgos", fees.TotalFees)
		}
	}
	addContributions()
	if (plan.DummiesNeeded > 0 || fees.TotalFees > 0) && len(allTxns) > 1 {
		add("Group ID recomputed")
	}
	return changes
}

// passthroughAuthorization names who authorizes a passthrough position, and
// with what kind of signature, from its signed bytes. This signer does not
// check that signature; the network does.
func passthroughAuthorization(signed []byte) txnreview.Field {
	var stxn types.SignedTxn
	if err := msgpack.Decode(signed, &stxn); err != nil {
		return txnreview.Field{Label: "Authorized by", Value: "(the signed transaction could not be read)"}
	}
	return txnreview.Field{Label: "Authorized by", Value: txnreview.Authorization(stxn)}
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

// boundedRekeyFields names a bounded rekey's authorization for the operator:
// the group and the single-request prompts both carry it. It is empty for
// anything but a bounded rekey.
func boundedRekeyFields(item *boundedPlanItem) []txnreview.Field {
	if item == nil || item.Path == boundedPathPureSpend {
		return nil
	}
	fields := []txnreview.Field{
		{Label: "Bounded authorization operation", Value: "REKEY"},
		{Label: "Authorization", Value: boundedAuthorizationLabel(item)},
	}
	if item.Metadata != nil && item.Metadata.MaxFee != nil {
		fields = append(fields, txnreview.Field{Label: "Profile maximum fee", Value: fmt.Sprintf("%d microAlgos", *item.Metadata.MaxFee)})
	}
	return fields
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

func requestIDPreview(requestID string) string {
	if len(requestID) <= 20 {
		return requestID
	}
	return requestID[:20]
}

// requestGroupApprovalWithContext prompts for a group, or for a lone request
// that only the group prompt can show. review is the request's completed
// review (ApprovalService.review): the prompt's text and warnings are its own.
func (s *ApprovalService) requestGroupApprovalWithContext(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult, firstValid, lastValid uint64, txns []types.Transaction, forceReviewRuleID string, review *txnreview.Review) *ServiceError {
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

	s.addChainState(ctx, review, txns[0].GenesisHash[:], s.planKnownAddresses(plan), signersOf(req.Requests, txns, plan))

	// A direct caller may supply no ID; the prompt is never held under an
	// empty one.
	requestID := RequestID(req.RequestID)
	console.Printf("[IPC] GROUP APPROVAL: Waiting for approval from apadmin TUI (request %s)...\n", requestIDPreview(requestID))
	console.Sync()

	displaySender := fmt.Sprintf("GROUP(%d txns)", len(txns))
	groupAuthAddr := groupApprovalAddress(req)

	approved, err := s.requestSigningApproval(
		ctx,

		requestID,
		groupAuthAddr,
		displaySender,
		"[GROUP APPROVAL]\n"+review.Text(),
		firstValid,
		lastValid,
		reviewViolations(review, true),
		review,
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

// requestSingleTxnApprovalWithContext prompts for one request. review is the
// request's completed review (ApprovalService.review): the prompt's text and
// warnings are its own, what planning changed shown above the transaction as
// the group prompt shows it.
func (s *ApprovalService) requestSingleTxnApprovalWithContext(ctx context.Context, requestID string, txReq signerapi.SignRequest, allTxns, txns []types.Transaction, firstValid, lastValid uint64, forceReviewRuleID string, review *txnreview.Review) *ServiceError {
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

	s.addChainState(ctx, review, txns[0].GenesisHash[:], s.planKnownAddresses(nil), signersOf([]signerapi.SignRequest{txReq}, txns, nil))

	// A direct caller may supply no ID; the prompt is never held under an
	// empty one.
	requestID = RequestID(requestID)
	console.Printf("[IPC] TXN APPROVAL: Waiting for approval from apadmin TUI (request %s)...\n", requestIDPreview(requestID))
	console.Sync()

	txnDesc := "[TXN APPROVAL]\n"
	if changes := review.Changes.Text(); changes != "" {
		txnDesc += changes + "\n"
	}
	txnDesc += review.Items[0].Text()
	if accounts := review.AccountsText(); accounts != "" {
		txnDesc += "\n" + strings.TrimSuffix(accounts, "\n")
	}
	violations := reviewViolations(review, false)
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
		review,
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

// reviewItem describes one requested transaction: what it does, the client's
// claims about an app call, and a bounded rekey's authorization.
func reviewItem(txn types.Transaction, txReq signerapi.SignRequest, describe DescribeTxnFunc, bounded *boundedPlanItem) txnreview.Item {
	item := txnreview.Item{Details: describe(txn), Claims: appCallClaims(txn, txReq)}
	item.Details.Fields = append(item.Details.Fields, boundedRekeyFields(bounded)...)
	return item
}

// appCallClaims are the lines a review adds for what the client says of an
// app call.
func appCallClaims(txn types.Transaction, txReq signerapi.SignRequest) []string {
	meta := txReq.AppCallInfo
	if meta == nil || txn.Type != types.ApplicationCallTx {
		return nil
	}

	if strings.EqualFold(strings.TrimSpace(meta.Mode), "raw") {
		return []string{"Mode: Raw"}
	}

	methodSig := strings.TrimSpace(meta.Method)
	if methodSig == "" {
		return nil
	}
	// An ABI call's first argument is the selector and nothing else. A longer
	// argument that merely starts with the label's selector is not an ABI
	// call of that method. A label that doesn't fit is not shown, but the
	// review says one was offered: a client naming a method the call doesn't
	// make is itself worth knowing.
	wantSelector, err := appspec.SignatureSelector(methodSig)
	if err != nil || len(txn.ApplicationArgs) == 0 || !bytes.Equal(wantSelector, txn.ApplicationArgs[0]) {
		return []string{abiLabelMismatchLine}
	}

	// The label is the client's. The signer holds no contract for the app, so
	// the selector is all that ties the name to the call, and a different
	// name with the same four bytes can be found by search. The review says
	// so, and shows the selector, the part the app acts on.
	return []string{
		abiModeLine,
		abiMethodLabel + termsafe.Line(methodSig),
		fmt.Sprintf("Selector: %x (all that ties the label to this call)", wantSelector),
	}
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
