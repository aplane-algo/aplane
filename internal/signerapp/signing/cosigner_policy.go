// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/witness"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// evaluateCosignerComponentPolicy applies the cosigner key's policy (its own
// document, or the node default) to every target. A cosigner has no operator,
// so every verdict is sign or reject: a review verdict, which the document
// format cannot express on a cosigner node, is treated as a rejection.
func (s *Service) evaluateCosignerComponentPolicy(plan *ComponentSignPlan) *ServiceError {
	if plan == nil {
		return internal("component sign plan is nil")
	}
	componentKey, err := witness.NormalizeID(plan.ComponentKey)
	if err != nil {
		return badRequest(err.Error())
	}
	if s.HoldsCosignerKey == nil || !s.HoldsCosignerKey(componentKey) {
		return badRequest(fmt.Sprintf("Cosigner Key ID %q not found", componentKey))
	}
	cfg := s.policyFor(componentKey)
	if cfg == nil {
		return internal("policy is not loaded")
	}

	slots := make([]policyeval.Slot, len(plan.Targets))
	for i, target := range plan.Targets {
		slots[i] = policyeval.Slot{Index: target.TargetIndex, Policy: cfg}
	}
	verdict, evalErr := policyeval.Evaluate(policyeval.Input{
		Role:     policyeval.RoleCosigner,
		Group:    componentPlanTxns(plan),
		Slots:    slots,
		Networks: s.genesisHashResolver(),
	})
	if evalErr != nil {
		return internal(evalErr.Error())
	}
	violations := verdict.Violations
	if len(violations) > 0 {
		return s.rejectCosignerComponentPolicy(plan, violations)
	}
	return nil
}

func (s *Service) rejectCosignerComponentPolicy(plan *ComponentSignPlan, violations []policy.LintViolation) *ServiceError {
	reason := policy.JoinLintViolations(violations)
	if reason == "" {
		reason = "cosigner policy rejected request"
	}
	s.logCosignerPolicyRejections(plan, reason, firstPolicyRuleID(violations))
	return forbidden("cosigner policy rejected request: " + reason)
}

func firstPolicyRuleID(violations []policy.LintViolation) string {
	if len(violations) == 0 {
		return ""
	}
	return violations[0].RuleID
}

func (s *Service) logCosignerPolicyRejections(plan *ComponentSignPlan, reason, policyRuleID string) {
	rejectLogger, ok := s.AuditLog.(policyAuditLogger)
	if !ok || rejectLogger == nil || plan == nil {
		return
	}
	for _, target := range plan.Targets {
		sender := target.Sender
		if sender == "" && plan.Group != nil && target.TargetIndex >= 0 && target.TargetIndex < len(plan.Group.Entries) {
			sender = plan.Group.Entries[target.TargetIndex].Txn.Sender.String()
		}
		if limited, ok := s.AuditLog.(AuditCosignerRejectLogger); ok && limited != nil {
			limited.LogCosignerComponentRejected(plan.ComponentKey, sender, "cosigner_policy_rejected: "+reason, policyRuleID)
			continue
		}
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditRejectPolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignRejectedWithPolicyRule(plan.ComponentKey, sender, "cosigner_policy_rejected: "+reason, policyRuleID)
				continue
			}
		}
		rejectLogger.LogSignRejected(plan.ComponentKey, sender, "cosigner_policy_rejected: "+reason)
	}
}

func (s *Service) logCosignerComponentApproved(plan *ComponentSignPlan, result *ComponentSignResult) {
	if s.AuditLog == nil || plan == nil || result == nil {
		return
	}
	componentKey := result.ComponentKey
	if componentKey == "" {
		componentKey = plan.ComponentKey
	}
	for _, target := range plan.Targets {
		s.AuditLog.LogSignApproved(componentKey,
			target.Sender,
			fmt.Sprintf("cosigner component signature target %d signed", target.TargetIndex),
		)
	}
}

// genesisHashResolver is the node's network map, shared with /sign planning.
// A zero resolver resolves the built-in networks only.
func (s *Service) genesisHashResolver() apconfig.GenesisHashNetworkResolver {
	if s == nil || s.Planner == nil {
		return apconfig.GenesisHashNetworkResolver{}
	}
	return s.Planner.GenesisHashResolver
}

// componentPlanTxns returns every transaction in a component plan's group.
func componentPlanTxns(plan *ComponentSignPlan) []types.Transaction {
	if plan == nil || plan.Group == nil {
		return nil
	}
	txns := make([]types.Transaction, len(plan.Group.Entries))
	for i, entry := range plan.Group.Entries {
		txns[i] = entry.Txn
	}
	return txns
}
