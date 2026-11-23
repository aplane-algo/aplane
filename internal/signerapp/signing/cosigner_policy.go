// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"encoding/hex"
	"fmt"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeval"
	"github.com/aplane-algo/aplane/internal/txnreview"
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
// cosigner node, is treated as a rejection. Last come the document's external
// checks, which run only for a request the policy would sign and can only
// refuse it.
func (s *Service) runCosignerGates(ctx context.Context, plan *ComponentSignPlan) *ServiceError {
	if plan == nil {
		return internal("component sign plan is nil")
	}
	// prepareComponentSigning made the plan's key canonical; every step
	// below, the external checks and the audit record included, uses it as
	// it stands.
	componentKey, err := witness.NormalizeID(plan.ComponentKey)
	if err != nil {
		return badRequest(err.Error())
	}
	if componentKey != plan.ComponentKey {
		return internal("component sign plan carries a non-canonical Witness Key ID")
	}
	if s.HoldsCosignerKey == nil || !s.HoldsCosignerKey(componentKey) {
		return badRequest(fmt.Sprintf("Witness Key ID %q not found", componentKey))
	}
	group := makeTxnSlice(plan.Group)
	targets := componentTargetPositions(plan)
	// A group the network could never accept gets no witness signature. This
	// route reaches neither the planner nor the frozen-component validation,
	// which make the same checks.
	if err := validateTransactionBounds(group); err != nil {
		return err
	}
	if len(group) > 1 {
		if err := validateNetworkParams(group, consoleOf(s.Console)); err != nil {
			return err
		}
	}
	// A cosigner holds only witness keys. Their 52-character IDs never equal
	// a 58-character RekeyTo address, but an Ed25519 witness key's public key
	// is an address, and the key records that it is not a valid rekey target:
	// the valid-target invariant refuses a rekey to it, at any position, as a
	// signer refuses one to its own keys. A set it can't build refuses the
	// request rather than passing it.
	var invalidTargets map[string]txnreview.InvalidRekeyTarget
	if groupRekeys(group) {
		if s.Planner == nil || s.Planner.Snapshot == nil {
			return internal("planner not configured")
		}
		var addressErr error
		if invalidTargets, addressErr = cosignerKeyAddresses(s.Planner.Snapshot()); addressErr != nil {
			return internal(addressErr.Error())
		}
	}
	if err := s.rejectSignerInvariants(group, targets, invalidTargets); err != nil {
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
	return s.runExternalChecks(ctx, plan, cfg, group, targets)
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
		if limited, ok := s.AuditLog.(AuditCosignerRejectLogger); ok && limited != nil {
			limited.LogCosignerComponentRejected(plan.ComponentKey, target.Sender, reason, policyRuleID)
			continue
		}
		if policyRuleID != "" {
			if ruleLogger, ok := s.AuditLog.(AuditRejectPolicyRuleLogger); ok && ruleLogger != nil {
				ruleLogger.LogSignRejectedWithPolicyRule(plan.ComponentKey, target.Sender, reason, policyRuleID)
				continue
			}
		}
		rejectLogger.LogSignRejected(plan.ComponentKey, target.Sender, reason)
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
			Details:     fmt.Sprintf("cosigner component signature target %d signed", target.TargetIndex) + externalChecksNote(plan.ExternalChecks),
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

// cosignerKeyAddresses is the address of each witness key this cosigner holds
// whose public key is also one (an Ed25519 key's), with its key type. Those
// keys sign only their component message, so an account rekeyed to one could
// never be spent again. A key whose public key can't be read is an error.
func cosignerKeyAddresses(snapshot PlannerRuntimeSnapshot) (map[string]txnreview.InvalidRekeyTarget, error) {
	var addresses map[string]txnreview.InvalidRekeyTarget
	for id, keyType := range snapshot.KeyTypes {
		if !witness.IsKeyType(keyType) {
			continue
		}
		publicKey, err := hex.DecodeString(snapshot.KeyMetadata[id].PublicKeyHex)
		if err != nil {
			return nil, fmt.Errorf("cosigner key %s: unreadable public key: %w", id, err)
		}
		address, hasAddress, err := witness.AccountAddress(keyType, publicKey)
		if err != nil {
			return nil, fmt.Errorf("cosigner key %s: %w", id, err)
		}
		if !hasAddress {
			continue
		}
		if addresses == nil {
			addresses = make(map[string]txnreview.InvalidRekeyTarget)
		}
		addresses[types.Address(address).String()] = txnreview.InvalidRekeyTarget{KeyType: keyType}
	}
	return addresses, nil
}
