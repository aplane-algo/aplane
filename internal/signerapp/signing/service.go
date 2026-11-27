// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/termsafe"
	"github.com/aplane-algo/aplane/pkg/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// AuditApproveLogger records each transaction a request signed, as signed,
// a signature so recorded that then never left the signer, and a refusal
// that names one transaction of the request.
type AuditApproveLogger interface {
	LogSignApproved(record SignedRecord)
	// LogSignWithheld records, as SIGN_FAILED, a signature already recorded
	// as signed that never left the signer. The entry carries the record's
	// txid and group_id, the fields its SIGN_APPROVED has, so a search on
	// either finds both entries.
	LogSignWithheld(record SignedRecord, reason string)
	// LogSignRejectedRecord records, as SIGN_REJECTED, a refusal that names
	// one transaction of the request, which the signer did not sign. record
	// identifies it as planned, in the group the signer was asked to sign,
	// with the fields a SIGN_APPROVED for it would have carried: its txid
	// and the group's group_id and group_txids.
	LogSignRejectedRecord(record SignedRecord, reason string)
}

type IsUnlockedFunc func() bool

type Service struct {
	Planner                       *Planner
	Approval                      *ApprovalService
	Executor                      *Executor
	AuditLog                      AuditApproveLogger
	Console                       Console
	GenerateTxnDescriptionFromTxn DescribeTxnFunc
	IsUnlocked                    IsUnlockedFunc
	// PolicyFor resolves the policy that governs a key selector: the key's
	// own document, or the node default. It is bound to one policy snapshot
	// for the life of this service, so every slot of a request is judged
	// against the same policy. A nil resolver, or one that returns nil,
	// means policy is not loaded and every request fails closed.
	PolicyFor func(selector string) *policy.Config
	// HoldsCosignerKey reports whether the node holds a cosigner key,
	// without loading it.
	HoldsCosignerKey func(witnessKeyID string) bool
	// Rotating holds the rotating flow's dependencies; nil disables it.
	Rotating *RotatingDeps
	// ExternalChecks runs a cosigner document's external checks. Nil means
	// this node cannot run them, and a document that has any signs nothing.
	ExternalChecks ExternalCheckRunner
	// KeyUse registers a holder of key material for as long as the returned
	// release is not called: the context it returns ends when the node
	// locks or enters recovery, and a lock waits for the release before
	// clearing the session. Every post-approval signing and assembly path
	// (/sign, base and cosigner /sign/component, /sign/assemble)
	// and the external check step hold a key use while they load or use
	// secret material, releasing it before blocking audit or console writes.
	// Signing and assembly refuse when KeyUse is nil.
	KeyUse func(ctx context.Context) (context.Context, func())
}

type SignGroupResult struct {
	Signed    []string
	Mutations *signerapi.MutationReport
}

type ComponentSignResult struct {
	RequestID    string
	ComponentKey string
	Signatures   []ComponentSignature
}

type ComponentSignature struct {
	TargetIndex     int
	Signature       string
	SignatureScheme string
}

type AssemblyResult struct {
	RequestID   string
	SignedGroup []string
}

type policyAuditLogger interface {
	LogSignRejected(authAddress, txnSender, reason string)
}

func (s *Service) SignGroupWithContext(ctx context.Context, req signerapi.GroupSignRequest, session *keystore.KeySession) (*SignGroupResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Planner == nil || s.Approval == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}

	plan, err := s.planGroupWhileSignable(req)
	if err != nil {
		return nil, err
	}
	if planHasCosignedBoundedTarget(plan) {
		return nil, boundedCosignerRequired()
	}
	return s.signGroupWithPlanContext(ctx, req, session, plan)
}

// planGroupWhileSignable gives a lock transition priority over a planner
// error. A request can pass its outer unlocked precondition immediately before
// lock-on-disconnect clears the published key index; in that race, a missing-
// key planning error is only a symptom of the authoritative locked state.
func (s *Service) planGroupWhileSignable(req signerapi.GroupSignRequest) (*PlanResult, *ServiceError) {
	plan, err := s.Planner.PlanGroup(req)
	if err != nil && s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	return plan, err
}

func (s *Service) signComponentWithContext(ctx context.Context, req componentPlanRequest, session *keystore.KeySession) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}

	plan, planErr := prepareComponentSigning(req)
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	if planErr != nil {
		return nil, planErr
	}
	if err := s.runCosignerGates(ctx, plan); err != nil {
		return nil, err
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	useCtx, endKeyUse, useErr := s.openKeyUse(ctx)
	if useErr != nil {
		return nil, useErr
	}
	defer endKeyUse()
	result, signErr := signPreparedCosignerComponents(useCtx, plan, session)
	if signErr != nil {
		return nil, s.classifyKeyUseError(ctx, useCtx, signErr)
	}
	if refused := s.keyUseRefused(ctx, useCtx); refused != nil {
		return nil, refused
	}
	// Release the key use before the blocking audit write so a stalled disk
	// cannot hold a lock's drain, then recheck the session before returning.
	endKeyUse()
	records := s.logCosignerComponentApproved(plan, result)
	if refused := s.keyUseRefused(ctx, nil); refused != nil {
		s.logWithheldRecords(records, refused)
		return nil, refused
	}
	return result, nil
}

func (s *Service) AssembleWithContext(ctx context.Context, req signerapi.AssemblyRequest, session *keystore.KeySession) (*AssemblyResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
	// The response returns the request's ID, so a direct caller that
	// supplies none gets one.
	req.RequestID = RequestID(req.RequestID)
	if err := req.Validate(); err != nil {
		return nil, badRequest(err.Error())
	}
	group, decodeErr := canonical.DecodeGroupHex(req.GroupBytesHex)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	useCtx, endKeyUse, useErr := s.openKeyUse(ctx)
	if useErr != nil {
		return nil, useErr
	}
	defer endKeyUse()
	result, err := assembleDecoded(useCtx, req, group, session)
	if err != nil {
		return nil, s.classifyKeyUseError(ctx, useCtx, err)
	}
	endKeyUse()
	if refused := s.keyUseRefused(ctx, nil); refused != nil {
		return nil, refused
	}
	return result, nil
}

func (s *Service) signGroupWithPlanContext(ctx context.Context, req signerapi.GroupSignRequest, session *keystore.KeySession, plan *PlanResult) (*SignGroupResult, *ServiceError) {
	if err := rejectOrdinarySignKeyTypes(plan); err != nil {
		return nil, err
	}
	outcome, gateErr := s.approveGroupWithPlanContext(ctx, req, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	if bindErr := checkApprovalBinding(req, plan); bindErr != nil {
		return nil, bindErr
	}

	useCtx, endKeyUse, useErr := s.openKeyUse(ctx)
	if useErr != nil {
		s.logSessionEndedAfterApproval(req, plan, useErr)
		return nil, useErr
	}
	defer endKeyUse()

	execResult, deferred, err := s.Executor.executeGroupSigning(useCtx, plan, req, session)
	if err != nil {
		classified := s.classifyKeyUseError(ctx, useCtx, err)
		endKeyUse()
		if classified.Kind == ErrorLocked {
			s.logSessionEndedAfterApproval(req, plan, classified)
		} else {
			deferred.flushFailure(s.Executor.AuditLog)
		}
		return nil, classified
	}
	if refused := s.keyUseRefused(ctx, useCtx); refused != nil {
		endKeyUse()
		s.logSessionEndedAfterApproval(req, plan, refused)
		return nil, refused
	}
	// All loaded key material was zeroed before executeGroupSigning returned.
	// End the key use before writing console output or audit logs so a stalled
	// terminal or disk cannot hold a lock's drain, then recheck the session
	// before releasing signatures.
	endKeyUse()
	deferred.flushConsole(s.Executor.Console)
	s.logSummary(req, plan, execResult.SignedTxns, consoleOf(s.Console))

	var records []SignedRecord
	if s.AuditLog != nil {
		records = s.logSuccessfulSignatures(req, plan, auditedGroup(plan), outcome)
	}
	if refused := s.keyUseRefused(ctx, nil); refused != nil {
		s.logWithheldRecords(records, refused)
		return nil, refused
	}

	return &SignGroupResult{
		Signed:    execResult.SignedTxns,
		Mutations: BuildMutationReport(plan, len(req.Requests)),
	}, nil
}

func rejectOrdinarySignKeyTypes(plan *PlanResult) *ServiceError {
	if plan == nil {
		return internal("signing plan is nil")
	}
	for i, keyType := range plan.AuthKeyTypes {
		if message, rejected := cosignerSignRejectMessage(keyType); rejected {
			return badRequest(fmt.Sprintf("transaction %d: %s", i+1, message))
		}
	}
	return nil
}

func (s *Service) approveGroupWithPlanContext(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult) (approvalOutcome, *ServiceError) {
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]
	// What the gates below judge and the operator is shown.
	approvedDigest := approvalDigest(req, plan)

	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return approvalOutcome{}, lockedError()
	}

	review := s.Approval.review(req, plan, allTxns, s.GenerateTxnDescriptionFromTxn)
	// The daemon prints this to its console as well as prompting with it.
	groupDesc := termsafe.Lines(review.Text())
	firstValid, lastValid := approvalWindow(allTxns)
	isGroup := len(req.Requests) > 1
	console := consoleOf(s.Console)

	console.Println("\n" + strings.Repeat("-", 60))
	if isGroup {
		console.Println("GROUP SIGNATURE REQUEST")
	} else {
		console.Println("SIGNATURE REQUEST")
	}
	console.Println(strings.Repeat("=", 60))
	console.Println(groupDesc)
	console.Sync()

	outcome, gateErr := s.runApprovalGates(ctx, gateInput{
		AllTxns:              allTxns,
		EvalCount:            len(req.Requests),
		PassthroughIndices:   plan.PassthroughIndices,
		ForeignIndices:       plan.ForeignIndices,
		AuthKeys:             authPolicyKeysFromRequest(req, plan),
		KnownAddresses:       s.Approval.planKnownAddresses(plan),
		InvalidRekeyTargets:  invalidRekeyTargetsForPlan(plan),
		ProtocolRekeyTargets: protocolRekeyTargetsForPlan(plan),
		ListedRekeyTargets:   listedRekeyTargetsForPlan(plan),
		ForcedReviewRuleID: func() string {
			if planHasBoundedRekey(plan) {
				return policy.HostRekeyRequiresReviewRuleID
			}
			return ""
		}(),
		Plan: planFacts(req, plan),
		LogRejection: func(reason string, refusal *ServiceError) {
			s.logSignRejections(req, plan, txns, reason, refusal)
		},
		RequestOperatorApproval: func(ctx context.Context, forceReviewRuleID string) *ServiceError {
			// A rotating spend is one request, but its prompt must carry the
			// rotation description and judge warnings against the plan's own
			// addresses, which only the group prompt does.
			if isGroup || plan.Rotating != nil {
				return s.Approval.requestGroupApprovalWithContext(ctx, req, plan, firstValid, lastValid, txns, forceReviewRuleID, &review)
			}
			return s.Approval.requestSingleTxnApprovalWithContext(ctx, req.RequestID, req.Requests[0], plan, txns, firstValid, lastValid, forceReviewRuleID, &review)
		},
	}, console)
	if gateErr != nil {
		return approvalOutcome{}, gateErr
	}

	if err := ctx.Err(); err != nil {
		return approvalOutcome{}, unavailable(fmt.Sprintf("sign request canceled: %v", err))
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		err := lockedError()
		// The request passed its gates, an operator approval among them,
		// but the signer locked or its session ended before it could sign.
		s.logSignRejections(req, plan, txns, "session_ended_after_approval", err)
		return approvalOutcome{}, err
	}
	plan.bindApproval(approvedDigest)
	return outcome, nil
}

// policyFor resolves a selector's policy through the request's snapshot. It
// returns nil when policy is not loaded.
func (s *Service) policyFor(selector string) *policy.Config {
	if s == nil || s.PolicyFor == nil {
		return nil
	}
	return s.PolicyFor(selector)
}

// protocolRekeyTargetsForPlan returns the rekeys the signer issued itself for
// plan, or nil.
func protocolRekeyTargetsForPlan(plan *PlanResult) map[string]bool {
	if plan == nil {
		return nil
	}
	return plan.ProtocolRekeyTargets
}

func authPolicyKeysFromRequest(req signerapi.GroupSignRequest, plan *PlanResult) []string {
	if len(req.Requests) == 0 {
		return nil
	}
	out := make([]string, len(req.Requests))
	for i, txReq := range req.Requests {
		if plan != nil && (plan.PassthroughIndices[i] || plan.ForeignIndices[i]) {
			continue
		}
		out[i] = txReq.AuthAddress
	}
	return out
}

// openKeyUse registers a key-use window covering a signing or assembly
// operation's key load and use, and checks that the request's session is
// still active. It refuses when KeyUse is nil so no signing or assembly path
// can load key material unregistered. The returned release is safe to call
// more than once and must be called once loaded key material has been zeroed
// and before any blocking audit or console write.
func (s *Service) openKeyUse(ctx context.Context) (context.Context, func(), *ServiceError) {
	if s.KeyUse == nil {
		return nil, nil, internal("signing service key use is not configured")
	}
	useCtx, release := s.KeyUse(ctx)
	release = sync.OnceFunc(release)
	// Recheck after registration: KeyUse checks current unlocked state, not
	// the request's session generation, so a lock+unlock or recovery+reconcile
	// round-trip before registration passes KeyUse and is caught here by
	// IsUnlocked; a racing lock/recovery or shutdown is caught by useCtx.Err().
	if refused := s.keyUseRefused(ctx, useCtx); refused != nil {
		release()
		return nil, nil, refused
	}
	return useCtx, release, nil
}

// keyUseRefused reports why a signing or assembly request must stop and
// withhold output: the request's session ended (lock, recovery, or round-trip),
// the caller canceled requestCtx, or (while a key-use window is open) useCtx
// was canceled. Pass nil for useCtx after the key-use window has been released.
func (s *Service) keyUseRefused(requestCtx, useCtx context.Context) *ServiceError {
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return lockedError()
	}
	if err := requestCtx.Err(); err != nil {
		return canceledSignRequest(err)
	}
	if useCtx != nil && useCtx.Err() != nil {
		return lockedError()
	}
	return nil
}

// classifyKeyUseError prefers a session-end or caller-cancellation refusal
// over a downstream error caused by a canceled key-use context (such as a
// context-canceled key read).
func (s *Service) classifyKeyUseError(requestCtx, useCtx context.Context, err *ServiceError) *ServiceError {
	if err == nil {
		return nil
	}
	if refused := s.keyUseRefused(requestCtx, useCtx); refused != nil {
		return refused
	}
	return err
}

func (s *Service) logSessionEndedAfterApproval(req signerapi.GroupSignRequest, plan *PlanResult, err *ServiceError) {
	if err != nil && err.Kind == ErrorLocked {
		s.logSignRejections(req, plan, plan.AllTxns[:len(req.Requests)], "session_ended_after_approval", err)
	}
}

// logWithheldRecords writes SIGN_FAILED entries countermanding signatures that
// were already audited as SIGN_APPROVED before the final check stopped return.
func (s *Service) logWithheldRecords(records []SignedRecord, refused *ServiceError) {
	if s.AuditLog == nil || refused == nil || len(records) == 0 {
		return
	}
	reason := "signature withheld after it was recorded as signed: " + refused.Message
	for _, record := range records {
		s.AuditLog.LogSignWithheld(record, reason)
	}
}

func (s *Service) logSummary(req signerapi.GroupSignRequest, plan *PlanResult, signedTxns []string, console Console) {
	signedCount := len(req.Requests) - len(plan.PassthroughIndices) - len(plan.ForeignIndices)
	if plan.HasPassthrough || plan.HasForeign {
		parts := []string{fmt.Sprintf("%d signed", signedCount)}
		if plan.HasPassthrough {
			parts = append(parts, fmt.Sprintf("%d passthrough", len(plan.PassthroughIndices)))
		}
		if plan.HasForeign {
			parts = append(parts, fmt.Sprintf("%d foreign", len(plan.ForeignIndices)))
		}
		console.Printf("[GROUP] Successfully processed %d transaction(s) (%s)\n",
			len(signedTxns), strings.Join(parts, ", "))
		return
	}

	console.Printf("[GROUP] Successfully signed %d transaction(s)\n", len(signedTxns))
}

// logSuccessfulSignatures records each position this signer signed with its
// key, as signed: group is the final group, as the executor signed it, with
// the trailing dummies it signed. It returns the logged records so a post-audit
// refusal can countermand each one with LogSignWithheld.
func (s *Service) logSuccessfulSignatures(req signerapi.GroupSignRequest, plan *PlanResult, group signedGroup, outcome approvalOutcome) []SignedRecord {
	if s.AuditLog == nil {
		return nil
	}

	records := make([]SignedRecord, 0, len(req.Requests))
	for i, txReq := range req.Requests {
		if plan.PassthroughIndices[i] || plan.ForeignIndices[i] {
			continue
		}
		details := fmt.Sprintf("txn %d/%d signed", i+1, len(req.Requests))
		record := group.record(i, txReq.AuthAddress, details, outcome)
		s.AuditLog.LogSignApproved(record)
		records = append(records, record)
	}
	return records
}

// logSignRejections audits a refused sign. reason carries its own audit
// prefix.
//
// A refusal that names a position (its RefusedPosition: every signer
// invariant names one) writes a SIGN_REJECTED for each position this signer
// would have signed and one for the named position whatever its kind and
// wherever it is in the group, so a refusal caused by a passthrough, foreign
// or trailing position, or by the only position of a request that signs
// nothing, is on record. Every one of those entries identifies its
// transaction as planned, in the group the signer was asked to sign, the way
// a SIGN_APPROVED identifies a signed one (auditedGroup), so they join by
// group. The entry for a position this signer does not sign has no
// txn_auth, and a position it signs gets one entry, not two.
//
// Any other refusal, a policy rejection, writes one entry per position this
// signer would have signed, naming the auth address, sender, reason, and the
// first matched policy rule ID when present.
func (s *Service) logSignRejections(req signerapi.GroupSignRequest, plan *PlanResult, txns []types.Transaction, reason string, refusal *ServiceError) {
	if refusal != nil && refusal.RefusedPosition != nil {
		s.logPositionRefusal(req, plan, *refusal.RefusedPosition, reason)
		return
	}
	rejectLogger, ok := s.AuditLog.(policyAuditLogger)
	if !ok || rejectLogger == nil {
		return
	}
	policyRuleID := ""
	if refusal != nil {
		policyRuleID = refusal.PolicyRuleID
	}
	ruleLogger, hasRuleLogger := s.AuditLog.(AuditRejectPolicyRuleLogger)
	for i, txReq := range req.Requests {
		if plan.PassthroughIndices[i] || plan.ForeignIndices[i] {
			continue
		}
		if policyRuleID != "" && hasRuleLogger && ruleLogger != nil {
			ruleLogger.LogSignRejectedWithPolicyRule(txReq.AuthAddress, txns[i].Sender.String(), reason, policyRuleID)
			continue
		}
		rejectLogger.LogSignRejected(txReq.AuthAddress, txns[i].Sender.String(), reason)
	}
}

// logPositionRefusal writes logSignRejections' entries for a refusal that
// names position named of plan's group.
func (s *Service) logPositionRefusal(req signerapi.GroupSignRequest, plan *PlanResult, named int, reason string) {
	if s.AuditLog == nil {
		return
	}
	group := auditedGroup(plan)
	for i := range plan.AllTxns {
		authAddress, signs := "", false
		if i < len(req.Requests) && !plan.PassthroughIndices[i] && !plan.ForeignIndices[i] {
			authAddress, signs = req.Requests[i].AuthAddress, true
		}
		if signs || i == named {
			s.AuditLog.LogSignRejectedRecord(group.record(i, authAddress, "", approvalOutcome{}), reason)
		}
	}
}
