// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/policy"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"github.com/aplane-algo/aplane/internal/productmode"
)

func (s *Service) evaluateSentryComponentPolicy(plan *ComponentSignPlan) *ServiceError {
	if plan == nil {
		return internal("component sign plan is nil")
	}
	cfg := sentryPolicyConfig(s.SentryPolicy, plan.ComponentKey)
	if cfg == nil {
		return s.rejectSentryComponentPolicy(plan, []policy.LintViolation{{
			RuleID:   policy.SentryPolicyMissingRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  "sentry policy is not configured",
		}})
	}
	if cfg.TransferPolicy == nil || !cfg.TransferPolicy.Enabled {
		return s.rejectSentryComponentPolicy(plan, []policy.LintViolation{{
			RuleID:   policy.SentryTransferPolicyRequiredRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  "sentry.transfer_policy.enabled:true is required",
		}})
	}
	if violations := sentryTransferPolicyConfigLints(cfg.TransferPolicy); len(violations) > 0 {
		return s.rejectSentryComponentPolicy(plan, violations)
	}

	var violations []policy.LintViolation
	for _, target := range plan.Targets {
		txn := plan.Group.Entries[target.TargetIndex].Txn
		violations = append(violations, sentryTargetPolicyLints(txn, target.TargetIndex, cfg)...)
	}
	if len(violations) > 0 {
		return s.rejectSentryComponentPolicy(plan, violations)
	}
	return nil
}

func sentryPolicyConfig(cfg *policy.Config, componentKey string) *policy.Config {
	if cfg == nil {
		return nil
	}
	return cfg.ForKey(componentKey)
}

func sentryTransferPolicyConfigLints(tp *policy.TransferPolicy) []policy.LintViolation {
	if tp == nil {
		return nil
	}
	checks := []struct {
		field string
		value policy.TransferOnNoRoute
	}{
		{field: "on_no_route", value: tp.OnNoRoute},
		{field: "close_on_no_route", value: tp.CloseOnNoRoute},
		{field: "clawback_on_no_route", value: tp.ClawbackOnNoRoute},
	}
	var violations []policy.LintViolation
	for _, check := range checks {
		if check.value == policy.TransferOnNoRouteReject {
			continue
		}
		violations = append(violations, policy.LintViolation{
			RuleID:   policy.SentryDeterministicRoutingRuleID,
			Scope:    "group",
			TxnIndex: -1,
			Message:  fmt.Sprintf("sentry transfer_policy.%s must be reject, got %q", check.field, check.value),
		})
	}
	return violations
}

func sentryTargetPolicyLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
	var violations []policy.LintViolation
	isRekey := !txn.RekeyTo.IsZero()
	if !isRekey && len(policy.ExtractTransferMovements(txn)) == 0 {
		violations = append(violations, policy.LintViolation{
			RuleID:   policy.SentryNonTransferRuleID,
			Scope:    "txn",
			TxnIndex: targetIndex,
			Message:  fmt.Sprintf("sentry policy only supports direct pay and axfer targets, got %s", txn.Type),
		})
	}
	commonLintCfg := cfg.Clone()
	commonLintCfg.RejectForeignRekey = false
	commonLintCfg.RejectRekey = false
	violations = append(violations, withTargetIndex(
		policy.CheckTxnPolicyLintsWithKnownAddresses(txn, txn.Sender.String(), commonLintCfg, nil),
		targetIndex,
	)...)
	if isRekey {
		if cfg.RejectRekey {
			violations = append(violations, policy.LintViolation{
				RuleID:   policy.SentryRekeyRuleID,
				Scope:    "txn",
				TxnIndex: targetIndex,
				Message:  "rekey transactions are rejected by sentry policy",
			})
			return violations
		}
		violations = append(violations, sentryRekeyPolicyLints(txn, targetIndex, cfg)...)
		return violations
	}
	violations = append(violations, withTargetIndex(
		policy.CheckTxnTransferRoutingPolicyLints(txn, cfg, false),
		targetIndex,
	)...)
	violations = append(violations, withTargetIndex(
		policy.CheckTxnTransferRoutingReviewPolicyLints(txn, cfg, false),
		targetIndex,
	)...)
	return violations
}

func sentryRekeyPolicyLints(txn types.Transaction, targetIndex int, cfg *policy.Config) []policy.LintViolation {
	if txn.Type != types.PaymentTx {
		return []policy.LintViolation{sentryRekeyViolation(targetIndex, "rekey transactions must be payment transactions")}
	}
	if txn.Amount != 0 {
		return []policy.LintViolation{sentryRekeyViolation(targetIndex, "rekey transactions must transfer 0 microalgos")}
	}
	if txn.Receiver != txn.Sender {
		return []policy.LintViolation{sentryRekeyViolation(targetIndex, "rekey transactions must be self-payments")}
	}
	if !txn.CloseRemainderTo.IsZero() {
		return []policy.LintViolation{sentryRekeyViolation(targetIndex, "rekey transactions must not close remainder")}
	}
	if cfg == nil || cfg.RekeyPolicy == nil || !cfg.RekeyPolicy.Allows(txn.Sender, txn.RekeyTo) {
		return []policy.LintViolation{sentryRekeyViolation(
			targetIndex,
			fmt.Sprintf("rekey from %s to %s is not allowed by sentry rekey_policy", txn.Sender, txn.RekeyTo),
		)}
	}
	return nil
}

func sentryRekeyViolation(targetIndex int, message string) policy.LintViolation {
	return policy.LintViolation{
		RuleID:   policy.SentryRekeyRuleID,
		Scope:    "txn",
		TxnIndex: targetIndex,
		Message:  message,
	}
}

func withTargetIndex(violations []policy.LintViolation, targetIndex int) []policy.LintViolation {
	for i := range violations {
		violations[i].TxnIndex = targetIndex
	}
	return violations
}

func (s *Service) rejectSentryComponentPolicy(plan *ComponentSignPlan, violations []policy.LintViolation) *ServiceError {
	reason := policy.JoinLintViolations(violations)
	if reason == "" {
		reason = "sentry policy rejected request"
	}
	s.logSentryPolicyRejections(plan, reason, firstPolicyRuleID(violations))
	return forbidden("sentry policy rejected request: " + reason)
}

func firstPolicyRuleID(violations []policy.LintViolation) string {
	if len(violations) == 0 {
		return ""
	}
	return violations[0].RuleID
}

func (s *Service) logSentryPolicyRejections(plan *ComponentSignPlan, reason, policyRuleID string) {
	rejectLogger, ok := s.AuditLog.(policyAuditLogger)
	if !ok || rejectLogger == nil || plan == nil {
		return
	}
	for _, target := range plan.Targets {
		sender := target.Sender
		if sender == "" && plan.Group != nil && target.TargetIndex >= 0 && target.TargetIndex < len(plan.Group.Entries) {
			sender = plan.Group.Entries[target.TargetIndex].Txn.Sender.String()
		}
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditRejectPolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignRejectedWithPolicyRule(productmode.IdentityID, plan.ComponentKey, sender, "sentry_policy_rejected: "+reason, policyRuleID)
				continue
			}
		}
		rejectLogger.LogSignRejected(productmode.IdentityID, plan.ComponentKey, sender, "sentry_policy_rejected: "+reason)
	}
}

func (s *Service) logSentryComponentApproved(plan *ComponentSignPlan, result *ComponentSignResult) {
	if s.AuditLog == nil || plan == nil || result == nil {
		return
	}
	componentKey := result.ComponentKey
	if componentKey == "" {
		componentKey = plan.ComponentKey
	}
	for _, target := range plan.Targets {
		s.AuditLog.LogSignApproved(productmode.IdentityID, componentKey,
			target.Sender,
			fmt.Sprintf("sentry component signature target %d signed", target.TargetIndex),
		)
	}
}
