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

// runCosignerGates is the cosigner's gate sequence for a component request.
// It checks that this node holds the component key, then runs the signer
// invariants over the targets, then applies the cosigner key's policy (its
// own document, or the node default) to every target. The invariants come
// after the key check, so a request for a key this node doesn't hold is
// refused as such and never audited, and before the policy, so no policy can
// allow what they refuse. A cosigner has no operator, so every verdict is sign
// or reject: a review verdict, which the document format cannot express on a
// cosigner node, is treated as a rejection.
func (s *Service) runCosignerGates(plan *ComponentSignPlan) *ServiceError {
	if plan == nil {
		return internal("component sign plan is nil")
	}
	componentKey, err := witness.NormalizeID(plan.ComponentKey)
	if err != nil {
		return badRequest(err.Error())
	}
	if s.HoldsCosignerKey == nil || !s.HoldsCosignerKey(componentKey) {
		return badRequest(fmt.Sprintf("Witness Key ID %q not found", componentKey))
	}
	group := componentPlanTxns(plan)
	targets := componentTargetPositions(plan)
	// A group the network could never accept gets no witness signature. This
	// route reaches neither the planner nor the frozen-component validation,
	// which make the same check.
	if err := validateTransactionBounds(group); err != nil {
		return err
	}
	// A cosigner holds only witness keys, whose 52-character IDs never equal a
	// 58-character RekeyTo address, so no rekey target is held, or invalid:
	// the valid-target invariant, which judges every position of the group,
	// has nothing to refuse here and gets no set to build.
	if err := s.rejectSignerInvariants(group, targets, nil); err != nil {
		s.logCosignerRejections(plan, auditSignerInvariant+err.Message, "")
		return err
	}
	cfg := s.policyFor(componentKey)
	if cfg == nil {
		return internal("policy is not loaded")
	}

	slots := make([]policyeval.Slot, len(targets))
	for i, target := range targets {
		slots[i] = policyeval.Slot{Index: target, Policy: cfg}
	}
	verdict, evalErr := policyeval.Evaluate(policyeval.Input{
		Role:     policyeval.RoleCosigner,
		Group:    group,
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
	s.logCosignerRejections(plan, auditCosignerPolicyRejected+reason, firstPolicyRuleID(violations))
	return forbidden("cosigner policy rejected request: " + reason)
}

func firstPolicyRuleID(violations []policy.LintViolation) string {
	if len(violations) == 0 {
		return ""
	}
	return violations[0].RuleID
}

// logCosignerRejections records a refused cosigner request for every target;
// reason carries its own prefix (auditCosignerPolicyRejected,
// auditSignerInvariant).
func (s *Service) logCosignerRejections(plan *ComponentSignPlan, reason, policyRuleID string) {
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
			limited.LogCosignerComponentRejected(plan.ComponentKey, sender, reason, policyRuleID)
			continue
		}
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditRejectPolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignRejectedWithPolicyRule(plan.ComponentKey, sender, reason, policyRuleID)
				continue
			}
		}
		rejectLogger.LogSignRejected(plan.ComponentKey, sender, reason)
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
	// The cosigner signs each target's TxID, as decoded, in a frozen group;
	// it signs no dummies. Each record names its own transaction from the
	// target, the ID the component message was built from, and takes only
	// the group's ID and transaction IDs from the group.
	group := decodedSignedGroup(plan.Group, 0)
	for _, target := range plan.Targets {
		s.AuditLog.LogSignApproved(group.inGroup(SignedRecord{
			AuthAddress: componentKey,
			TxnSender:   target.Sender,
			Details:     fmt.Sprintf("cosigner component signature target %d signed", target.TargetIndex),
			TxID:        txIDString(target.TxID),
			Fee:         target.Fee,
		}))
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
