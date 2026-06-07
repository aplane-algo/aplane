// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"

	attestorverify "github.com/aplane-algo/aplane/internal/attestor/verify"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
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

type GuardedAssemblyResult struct {
	RequestID   string
	SignedGroup []string
}

type policyAuditLogger interface {
	LogSignRejected(identityID, authAddress, txnSender, reason string)
}

func (s *Service) PlanGroup(identityID string, req signerapi.GroupSignRequest) (*PlanResult, *ServiceError) {
	if s.Planner == nil {
		return nil, internal("planner not configured")
	}
	return s.Planner.PlanGroup(identityID, req)
}

func (s *Service) SignGroupWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*SignGroupResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Planner == nil || s.Approval == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}

	plan, err := s.Planner.PlanGroup(identityID, req)
	if err != nil {
		return nil, err
	}
	return s.signGroupWithPlanContext(ctx, identityID, req, session, plan, false)
}

func (s *Service) SignGroupForSimulationWithContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession) (*SignGroupResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.Planner == nil || s.Executor == nil {
		return nil, internal("signing service not fully configured")
	}

	plan, err := s.Planner.PlanGroup(identityID, req)
	if err != nil {
		return nil, err
	}
	return s.signGroupWithPlanContext(ctx, identityID, req, session, plan, true)
}

func (s *Service) SignComponentWithContext(ctx context.Context, identityID string, req signerapi.ComponentSignRequest, session *keystore.KeySession) (*ComponentSignResult, *ServiceError) {
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
		return nil, forbidden("signer is locked")
	}
	switch plan.Role {
	case signerapi.ComponentSignRoleUser:
		if session == nil {
			return nil, internal("key session is nil")
		}
		return signPreparedUserComponents(ctx, plan, session)
	case signerapi.ComponentSignRoleSentry:
		if err := s.evaluateAttestorComponentPolicy(identityID, plan); err != nil {
			return nil, err
		}
		if session == nil {
			return nil, internal("key session is nil")
		}
		result, signErr := signPreparedAttestorComponents(ctx, plan, session)
		if signErr != nil {
			return nil, signErr
		}
		s.logAttestorComponentApproved(identityID, plan, result)
		return result, nil
	default:
		return nil, badRequest("unsupported component signing role")
	}
}

func (s *Service) AssembleGuardedWithContext(ctx context.Context, identityID string, req signerapi.GuardedAssemblyRequest, session *keystore.KeySession) (*GuardedAssemblyResult, *ServiceError) {
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
	group, decodeErr := attestorverify.DecodeCanonicalGroupHex(req.GroupBytesHex)
	if decodeErr != nil {
		return nil, badRequest(decodeErr.Error())
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, forbidden("signer is locked")
	}
	if session == nil {
		return nil, internal("key session is nil")
	}
	return assembleDecodedGuarded(ctx, req, group, session)
}

func (s *Service) signGroupWithPlanContext(ctx context.Context, identityID string, req signerapi.GroupSignRequest, session *keystore.KeySession, plan *PlanResult, simulation bool) (*SignGroupResult, *ServiceError) {
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]

	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, forbidden("signer is locked")
	}

	groupDesc, firstValid, lastValid := BuildApprovalDescription(req, plan, allTxns, s.GenerateTxnDescriptionFromTxn)
	isGroup := len(req.Requests) > 1
	console := consoleOf(s.Console)

	console.Println("\n" + strings.Repeat("-", 60))
	if isGroup {
		if simulation {
			console.Println("GROUP SIMULATION SIGNATURE REQUEST")
		} else {
			console.Println("GROUP SIGNATURE REQUEST")
		}
	} else if simulation {
		console.Println("SIMULATION SIGNATURE REQUEST")
	} else {
		console.Println("SIGNATURE REQUEST")
	}
	console.Println(strings.Repeat("=", 60))
	console.Println(groupDesc)
	console.Sync()

	knownAddresses := s.knownAddresses(identityID, plan)
	routingExemptIndices := routingExemptIndicesForPlan(plan, allTxns)
	authKeys := authPolicyKeysFromRequest(req, plan)
	if err := EvaluateAutoRejectionRules(allTxns, len(req.Requests), plan.PassthroughIndices, plan.ForeignIndices, isGroup, s.Policy, authKeys, knownAddresses, routingExemptIndices, console); err != nil {
		s.logPolicyRejections(identityID, req, plan, txns, err.Error())
		return nil, err
	}

	alwaysReviewRuleID, alwaysReview := EvaluateAlwaysReviewRules(txns, len(req.Requests), plan.PassthroughIndices, plan.ForeignIndices, s.Policy, authKeys, knownAddresses, routingExemptIndices)
	if simulation {
		console.Println("[SIMULATE] Auto-approved inside Signer; signed bytes will not be returned")
		console.Sync()
	} else if alwaysReview {
		if isGroup {
			if err := s.Approval.requestGroupApprovalWithContext(ctx, identityID, req, plan, groupDesc, firstValid, lastValid, txns, alwaysReviewRuleID); err != nil {
				return nil, err
			}
		} else {
			if err := s.Approval.requestSingleTxnApprovalWithContext(ctx, identityID, req.RequestID, req.Requests[0], allTxns, txns, plan.DummiesNeeded, firstValid, lastValid, alwaysReviewRuleID); err != nil {
				return nil, err
			}
		}
	} else if ruleID, approved := EvaluateAutoApprovalRules(req, plan, allTxns, s.Policy); approved {
		console.Printf("[POLICY] Txn auto-approved (%s)\n", ruleID)
		console.Sync()
	} else if isGroup {
		if err := s.Approval.RequestGroupApprovalWithContext(ctx, identityID, req, plan, groupDesc, firstValid, lastValid, txns); err != nil {
			return nil, err
		}
	} else {
		if err := s.Approval.requestSingleTxnApprovalWithContext(ctx, identityID, req.RequestID, req.Requests[0], allTxns, txns, plan.DummiesNeeded, firstValid, lastValid, ""); err != nil {
			return nil, err
		}
	}
	console.Sync()

	if err := ctx.Err(); err != nil {
		return nil, unavailable(fmt.Sprintf("sign request canceled: %v", err))
	}
	release, err := s.beforeExecute()
	if err != nil {
		return nil, err
	}
	defer release()

	execResult, err := s.Executor.ExecuteGroupSigning(ctx, plan, req, identityID, session)
	if err != nil {
		return nil, err
	}

	s.logSummary(req, plan, execResult.SignedTxns, console)
	if !simulation {
		s.logSuccessfulSignatures(identityID, req, plan, txns, alwaysReviewRuleID)
	}

	return &SignGroupResult{
		Signed:    execResult.SignedTxns,
		Mutations: BuildMutationReport(plan, len(req.Requests)),
	}, nil
}

func (s *Service) knownAddresses(identityID string, plan *PlanResult) map[string]bool {
	if plan != nil && plan.KnownAddresses != nil {
		return plan.KnownAddresses
	}
	if s.Approval == nil || s.Approval.KnownAddresses == nil {
		return nil
	}
	return s.Approval.KnownAddresses(identityID)
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
		return nil, forbidden("signer is locked")
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
		return nil, forbidden("signer is locked")
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
