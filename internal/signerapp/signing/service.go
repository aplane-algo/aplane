// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/cosigner/canonical"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/policy"
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

func (s *Service) PlanGroup(req signerapi.GroupSignRequest) (*PlanResult, *ServiceError) {
	if s.Planner == nil {
		return nil, internal("planner not configured")
	}
	return s.planGroupWhileSignable(req)
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
	var getter componentKeyGetter
	if session != nil {
		getter = session
	}
	return s.signComponentWithSession(ctx, req, getter)
}

func (s *Service) signComponentWithSession(ctx context.Context, req componentPlanRequest, session componentKeyGetter) (*ComponentSignResult, *ServiceError) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, canceledSignRequest(err)
	}

	plan, err := prepareComponentSigning(req)
	if err != nil {
		return nil, err
	}
	if s.IsUnlocked != nil && !s.IsUnlocked() {
		return nil, lockedError()
	}
	switch plan.Role {
	case ComponentSignRoleCosigner:
		if err := s.runCosignerGates(plan); err != nil {
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
		result, signErr := signPreparedCosignerComponents(ctx, plan, session)
		if signErr != nil {
			return nil, signErr
		}
		s.logCosignerComponentApproved(plan, result)
		return result, nil
	default:
		return nil, badRequest("unsupported component signing role")
	}
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
	release, leaseErr := s.beforeExecute()
	if leaseErr != nil {
		return nil, leaseErr
	}
	defer release()
	return assembleDecoded(ctx, req, group, session)
}

func (s *Service) signGroupWithPlanContext(ctx context.Context, req signerapi.GroupSignRequest, session *keystore.KeySession, plan *PlanResult) (*SignGroupResult, *ServiceError) {
	if err := rejectOrdinarySignKeyTypes(plan); err != nil {
		return nil, err
	}
	alwaysReviewRuleID, release, gateErr := s.approveGroupWithPlanContext(ctx, req, plan)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()
	if bindErr := checkApprovalBinding(req, plan); bindErr != nil {
		return nil, bindErr
	}

	execResult, err := s.Executor.ExecuteGroupSigning(ctx, plan, req, session)
	if err != nil {
		return nil, err
	}

	console := consoleOf(s.Console)
	s.logSummary(req, plan, execResult.SignedTxns, console)
	if s.AuditLog != nil {
		s.logSuccessfulSignatures(req, plan, signedGroupOf(plan.AllTxns, len(plan.DummyTxns)), alwaysReviewRuleID)
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

func (s *Service) approveGroupWithPlanContext(ctx context.Context, req signerapi.GroupSignRequest, plan *PlanResult) (string, func(), *ServiceError) {
	allTxns := plan.AllTxns
	txns := allTxns[:len(req.Requests)]
	// What the gates below judge and the operator is shown.
	approvedDigest := approvalDigest(req, plan)

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
		AuthKeys:             authPolicyKeysFromRequest(req, plan),
		KnownAddresses:       s.Approval.planKnownAddresses(plan),
		InvalidRekeyTargets:  invalidRekeyTargetsForPlan(plan),
		ProtocolRekeyTargets: protocolRekeyTargetsForPlan(plan),
		ListedRekeyTargets:   listedRekeyTargetsForPlan(plan),
		ForcedReviewRuleID: func() string {
			if planHasBoundedRekey(plan) {
				return policy.BoundedRekeyRequiresReviewRuleID
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
				return s.Approval.requestGroupApprovalWithContext(ctx, req, plan, groupDesc, firstValid, lastValid, txns, forceReviewRuleID)
			}
			return s.Approval.requestSingleTxnApprovalWithContext(ctx, req.RequestID, req.Requests[0], allTxns, txns, planChangeLines(plan, allTxns, false), firstValid, lastValid, forceReviewRuleID,
				plan)
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
	plan.bindApproval(approvedDigest)
	return alwaysReviewRuleID, release, nil
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

// logSuccessfulSignatures records each position this signer signed with its
// key, as signed: group is the final group, as the executor signed it, with
// the trailing dummies it signed.
func (s *Service) logSuccessfulSignatures(req signerapi.GroupSignRequest, plan *PlanResult, group signedGroup, policyRuleID string) {
	if s.AuditLog == nil {
		return
	}

	for i, txReq := range req.Requests {
		if plan.PassthroughIndices[i] || plan.ForeignIndices[i] {
			continue
		}
		details := fmt.Sprintf("txn %d/%d signed", i+1, len(req.Requests))
		s.AuditLog.LogSignApproved(group.record(i, txReq.AuthAddress, details, policyRuleID))
	}
}

// logSignRejections audits a refused sign: a SIGN_REJECTED at each position
// this signer would have signed, as every refusal writes, and, when the
// refusal names a position (its RefusedPosition, which a
// rekey_target_not_valid refusal sets), one for that position whatever its
// kind. That entry identifies the transaction as planned, in the group the
// signer was asked to sign, the way a SIGN_APPROVED identifies a signed one:
// its txid and the group's group_id and group_txids. So a refusal caused by a
// passthrough or foreign position, or by the only position of a request that
// signs nothing, is on record. Its txn_auth is empty unless this signer signs
// the position, and a position it signs gets that one entry, not two. reason
// carries its own audit prefix.
func (s *Service) logSignRejections(req signerapi.GroupSignRequest, plan *PlanResult, txns []types.Transaction, reason string, refusal *ServiceError) {
	if s.AuditLog == nil {
		return
	}
	rejectLogger, _ := s.AuditLog.(policyAuditLogger)
	named := refusal != nil && refusal.RefusedPosition != nil
	for i, txReq := range req.Requests {
		signs := !plan.PassthroughIndices[i] && !plan.ForeignIndices[i]
		switch {
		case named && i == *refusal.RefusedPosition:
			authAddress := ""
			if signs {
				authAddress = txReq.AuthAddress
			}
			group := signedGroupOf(plan.AllTxns, signerSignedDummies(plan))
			s.AuditLog.LogSignRejectedRecord(group.record(i, authAddress, "", ""), reason)
		case signs && rejectLogger != nil:
			rejectLogger.LogSignRejected(txReq.AuthAddress, txns[i].Sender.String(), reason)
		}
	}
}

// signerSignedDummies is how many of plan's trailing transactions are dummies
// the signer added and signs itself: the dummy_count its SIGN_APPROVED
// entries carry. A cosigned component's frozen group carries dummies the
// client signs, so it has none.
func signerSignedDummies(plan *PlanResult) int {
	if plan.Frozen && plan.Rotating == nil {
		return 0
	}
	return len(plan.DummyTxns)
}
