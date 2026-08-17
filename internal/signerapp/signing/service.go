// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/sentry/canonical"
	"github.com/aplane-algo/aplane/internal/signerapi"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

type AuditApproveLogger interface {
	LogSignApproved(identityID, authAddress, txnSender, details string)
}

type AuditApprovePolicyRuleLogger interface {
	LogSignApprovedWithPolicyRule(identityID, authAddress, txnSender, details, policyRuleID string)
}

type IsUnlockedFunc func() bool
type BeforeExecuteFunc func() (release func(), err *ServiceError)

type Service struct {
	Planner                       *Planner
	Approval                      *ApprovalService
	Executor                      *Executor
	AuditLog                      AuditApproveLogger
	Console                       Console
	GenerateTxnDescriptionFromTxn GenerateTxnDescriptionFromTxnFunc
	IsUnlocked                    IsUnlockedFunc
	BeforeExecute                 BeforeExecuteFunc
	Policy                        *policy.Config
	SentryPolicy                  *policy.Config
}

type SignGroupResult struct {
	Signed    []string
	Mutations *signerapi.MutationReport
}

type ComponentSignResult struct {
	RequestID    string
	ComponentKey string
	Signatures   []signerapi.ComponentSignature
}

type AssemblyResult struct {
	RequestID   string
	SignedGroup []string
}

type GuardedAssemblyResult = AssemblyResult

type policyAuditLogger interface {
	LogSignRejected(identityID, authAddress, txnSender, reason string)
}

func (s *Service) PlanGroup(identityID string, req signerapi.GroupSignRequest) (*PlanResult, *ServiceError) {
	if s.Planner == nil {
		return nil, internal("planner not configured")
	}
	return s.planGroupWhileSignable(identityID, req)
}

func (s *Service) SignGroupWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*SignGroupResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Planner == nil || s.Approval == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}

	plan, err := s.planGroupWhileSignable(identityID, req)
	if err != nil {
		return nil, err
	}
	if planHasBoundedAdminKeyOperation(plan) {
		return nil, boundedAdminRequired()
	}
	if planHasBoundedSentrySpend(plan) {
		return nil, boundedSentryRequired()
	}
	return s.signGroupWithPlanContext(ctx, identityID, req, session, plan)
}

func (s *Service) PrepareBoundedAdminWithContext(ctx context.Context, identityID string, request signerapi.BoundedAdminRequest, session *keystore.KeySession) (*BoundedAdminResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Planner == nil || s.Approval == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}
	req := request.GroupSignRequest()
	plan, err := s.planGroupWhileSignable(identityID, req)
	if err != nil {
		return nil, err
	}
	targetIndex, item, validationErr := validateBoundedAdminPlan(request, plan)
	if validationErr != nil {
		return nil, validationErr
	}
	policyRuleID, release, gateErr := s.approveGroupWithPlanContext(ctx, identityID, req, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()

	partials, signErr := s.Executor.ExecuteBoundedAdminPartial(ctx, plan, req, identityID, session, targetIndex, item)
	if signErr != nil {
		return nil, signErr
	}
	result, buildErr := buildBoundedAdminResult(plan, len(req.Requests), targetIndex, item, partials)
	if buildErr != nil {
		return nil, buildErr
	}
	consoleOf(s.Console).Printf("[GROUP] Prepared bounded-admin spending partial; external contract-admin signature required\n")
	s.logBoundedAdminPartialApproved(identityID, req, plan.AllTxns[targetIndex], targetIndex, policyRuleID)
	return result, nil
}

// planGroupWhileSignable gives a lock transition priority over a planner
// error. A request can pass its outer unlocked precondition immediately before
// lock-on-disconnect clears the published key index; in that race, a missing-
// key planning error is only a symptom of the authoritative locked state.
func (s *Service) planGroupWhileSignable(identityID string, req signerapi.GroupSignRequest) (*PlanResult, *ServiceError) {
	plan, err := s.Planner.PlanGroup(identityID, req)
	if err != nil && s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	return plan, err
}

func (s *Service) SignComponentWithContext(ctx context.Context, identityID string, req signerapi.ComponentSignRequest, session *keystore.KeySession) (*ComponentSignResult, *ServiceError) {
	var getter componentKeyGetter
	if session != nil {
		getter = session
	}
	return s.signComponentWithSession(ctx, identityID, req, getter)
}

func (s *Service) signComponentWithSession(ctx context.Context, identityID string, req signerapi.ComponentSignRequest, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}

	plan, err := PrepareComponentSigning(req)
	if err != nil {
		return nil, err
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	switch plan.Role {
	case signerapi.ComponentSignRoleUser:
		if session == nil {
			return nil, internal("key session is nil")
		}
		if err := s.preflightGuardedAccountKeyMetadata(identityID, plan.ComponentKey); err != nil {
			return nil, err
		}
		reviewRuleID, gateErr := s.gateUserComponentSigning(ctx, identityID, plan)
		if gateErr != nil {
			return nil, gateErr
		}
		release, leaseErr := s.beforeExecute()
		if leaseErr != nil {
			return nil, leaseErr
		}
		defer release()
		result, signErr := signPreparedUserComponents(ctx, plan, session)
		if signErr != nil {
			return nil, signErr
		}
		s.logUserComponentApproved(identityID, plan, reviewRuleID)
		return result, nil
	case signerapi.ComponentSignRoleSentry:
		if err := s.evaluateSentryComponentPolicy(identityID, plan); err != nil {
			return nil, err
		}
		if session == nil {
			return nil, internal("key session is nil")
		}
		release, leaseErr := s.beforeExecute()
		if leaseErr != nil {
			return nil, leaseErr
		}
		defer release()
		result, signErr := signPreparedSentryComponents(ctx, plan, session)
		if signErr != nil {
			return nil, signErr
		}
		s.logSentryComponentApproved(identityID, plan, result)
		return result, nil
	default:
		return nil, badRequest("unsupported component signing role")
	}
}

func (s *Service) AssembleWithContext(ctx context.Context, identityID string, req signerapi.AssemblyRequest, session *keystore.KeySession) (*AssemblyResult, *ServiceError) {
	_ = identityID
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}
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
	release, leaseErr := s.beforeExecute()
	if leaseErr != nil {
		return nil, leaseErr
	}
	defer release()
	return assembleDecoded(ctx, req, group, session)
}

func (s *Service) AssembleGuardedWithContext(ctx context.Context, identityID string, req signerapi.GuardedAssemblyRequest, session *keystore.KeySession) (*GuardedAssemblyResult, *ServiceError) {
	return s.AssembleWithContext(ctx, identityID, req.AssemblyRequest(), session)
}

func (s *Service) signGroupWithPlanContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession, plan *PlanResult) (*SignGroupResult, *ServiceError) {
	if err := rejectOrdinarySignKeyTypes(plan); err != nil {
		return nil, err
	}
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]
	alwaysReviewRuleID, release, gateErr := s.approveGroupWithPlanContext(ctx, identityID, req, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()

	execResult, err := s.Executor.ExecuteGroupSigning(ctx, plan, req, identityID, session)
	if err != nil {
		return nil, err
	}

	console := consoleOf(s.Console)
	s.logSummary(req, plan, execResult.SignedTxns, console)
	s.logSuccessfulSignatures(identityID, req, plan, txns, alwaysReviewRuleID)

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
		if message, rejected := sentrySignRejectMessage(keyType); rejected {
			return badRequest(fmt.Sprintf("transaction %d: %s", i+1, message))
		}
	}
	return nil
}

func (s *Service) approveGroupWithPlanContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, plan *PlanResult) (string, func(), *ServiceError) {
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]

	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return "", nil, lockedError()
	}

	groupDesc, firstValid, lastValid := BuildApprovalDescription(req, plan, allTxns, s.GenerateTxnDescriptionFromTxn)
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

	alwaysReviewRuleID, gateErr := s.runApprovalGates(ctx, gateInput{
		AllTxns:              allTxns,
		EvalCount:            len(req.Requests),
		PassthroughIndices:   plan.PassthroughIndices,
		ForeignIndices:       plan.ForeignIndices,
		IsGroup:              isGroup,
		AuthKeys:             authPolicyKeysFromRequest(req, plan),
		KnownAddresses:       s.knownAddresses(plan),
		RoutingExemptIndices: routingExemptIndicesForPlan(plan, allTxns),
		ForcedReviewRuleID: func() string {
			if planHasBoundedAdminOperation(plan) {
				return policy.BoundedAdminOperationRequiresReviewRuleID
			}
			return ""
		}(),
		AutoApprove: func() (string, bool) {
			return EvaluateAutoApprovalRules(req, plan, allTxns, s.Policy)
		},
		LogRejection: func(reason string) {
			s.logPolicyRejections(identityID, req, plan, txns, reason)
		},
		RequestOperatorApproval: func(ctx context.Context, forceReviewRuleID string) *ServiceError {
			if isGroup {
				return s.Approval.requestGroupApprovalWithContext(ctx, identityID, req, plan, groupDesc, firstValid, lastValid, txns, forceReviewRuleID)
			}
			return s.Approval.requestSingleTxnApprovalWithContext(ctx, identityID, req.RequestID, req.Requests[0], allTxns, txns, plan.DummiesNeeded, firstValid, lastValid, forceReviewRuleID)
		},
	}, console)
	if gateErr != nil {
		return "", nil, gateErr
	}

	if err := ctx.Err(); err != nil {
		return "", nil, unavailable(fmt.Sprintf("sign request canceled: %v", err))
	}
	release, err := s.beforeExecute()
	if err != nil {
		return "", nil, err
	}
	return alwaysReviewRuleID, release, nil
}

func (s *Service) knownAddresses(plan *PlanResult) map[string]bool {
	if plan != nil && plan.KnownAddresses != nil {
		return plan.KnownAddresses
	}
	if s.Approval == nil || s.Approval.KnownAddresses == nil {
		return nil
	}
	return s.Approval.KnownAddresses()
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

func (s *Service) beforeExecute() (func(), *ServiceError) {
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	if s.BeforeExecute == nil {
		return func() {}, nil
	}
	release, err := s.BeforeExecute()
	if err != nil {
		return nil, err
	}
	if release == nil {
		release = func() {}
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		release()
		return nil, lockedError()
	}
	return release, nil
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

func (s *Service) logSuccessfulSignatures(identityID string, req signerapi.GroupSignRequest, plan *PlanResult, txns []types.Transaction, policyRuleID string) {
	if s.AuditLog == nil {
		return
	}

	for i, txReq := range req.Requests {
		if plan.PassthroughIndices[i] || plan.ForeignIndices[i] {
			continue
		}
		details := fmt.Sprintf("txn %d/%d signed", i+1, len(req.Requests))
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditApprovePolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignApprovedWithPolicyRule(identityID, txReq.AuthAddress, txns[i].Sender.String(), details, policyRuleID)
				continue
			}
		}
		s.AuditLog.LogSignApproved(identityID, txReq.AuthAddress, txns[i].Sender.String(), details)
	}
}

func (s *Service) logBoundedAdminPartialApproved(identityID string, req signerapi.GroupSignRequest, txn types.Transaction, targetIndex int, policyRuleID string) {
	if s.AuditLog == nil || targetIndex < 0 || targetIndex >= len(req.Requests) {
		return
	}
	txReq := req.Requests[targetIndex]
	const details = "bounded-admin spending partial prepared; external contract-admin signature required"
	if policyRuleID != "" {
		if ruleLogger, ok := s.AuditLog.(AuditApprovePolicyRuleLogger); ok && ruleLogger != nil {
			ruleLogger.LogSignApprovedWithPolicyRule(identityID, txReq.AuthAddress, txn.Sender.String(), details, policyRuleID)
			return
		}
	}
	s.AuditLog.LogSignApproved(identityID, txReq.AuthAddress, txn.Sender.String(), details)
}

func (s *Service) logPolicyRejections(identityID string, req signerapi.GroupSignRequest, plan *PlanResult, txns []types.Transaction, reason string) {
	rejectLogger, ok := s.AuditLog.(policyAuditLogger)
	if !ok || rejectLogger == nil {
		return
	}

	for i, txReq := range req.Requests {
		if plan.PassthroughIndices[i] || plan.ForeignIndices[i] {
			continue
		}
		rejectLogger.LogSignRejected(identityID, txReq.AuthAddress, txns[i].Sender.String(), "policy_engine_rejected: "+reason)
	}
}
