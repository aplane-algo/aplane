// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package policyeval computes the signer's policy verdict for a group: which
// tier decides (Always Deny, Always Review, Always Approve, or none, leaving
// the Operator Default) and by which rule. It is pure: it reads only its
// input, so the daemon and offline tools that call it get the same answer.
//
// What happens after the verdict (User Auto-Approve, the operator prompt,
// reviewability, audit and console output) and refusals made before policy
// (an unknown network, a rekey to a rotating account) stay with the caller.
package policyeval

import (
	"errors"

	"github.com/algorand/go-algorand-sdk/v2/types"

	apconfig "github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/signerapp/approvalpolicy"
	signingutil "github.com/aplane-algo/aplane/internal/signing"
)

// Role selects the verdict surface.
type Role int

const (
	// RoleClient is client signing: Always Deny, Always Review, Always
	// Approve, else the Operator Default.
	RoleClient Role = iota
	// RoleCosigner is a cosigner's authorization: Approve or Reject, with no
	// operator and so no review.
	RoleCosigner
)

// SlotClass is what a judged position is to this signer.
type SlotClass int

const (
	// SlotSigner is a position this signer signs; its policy judges it.
	SlotSigner SlotClass = iota
	// SlotPassthrough carries a signature the caller supplied.
	SlotPassthrough
	// SlotForeign is signed by someone else.
	SlotForeign
)

// Slot is one position the evaluator judges. Index is its position in
// Input.Group, so violations keep their group index. Positions with no slot,
// such as signer-added dummies, are context only and are never judged.
type Slot struct {
	Index int
	Class SlotClass
	// Policy governs a signer slot; nil means no policy is loaded for it.
	// Passthrough and foreign slots have none.
	Policy *policy.Config
}

// Input is everything a verdict depends on.
type Input struct {
	Role Role
	// Group is the finalized group as it will be signed: fees after pooling,
	// signer-added dummies at the tail.
	Group []types.Transaction
	// Slots are the judged positions, in index order.
	Slots []Slot
	// KnownAddresses are the accounts this node holds keys for. Only rekeys
	// read it: the rekeys setting's reject_foreign_rekey and the rekey warning.
	KnownAddresses map[string]bool
	// ProtocolRekeyTargets are rekeys the signer issued itself (a rotation's
	// next stage); they are not warnings.
	ProtocolRekeyTargets map[string]bool
	// ForcedReviewRuleID is a signer-owned review requirement (a bounded
	// admin operation). It replaces the review rule when set.
	ForcedReviewRuleID string
	// Plan is the planner's report for Always Approve. Nil means the surface
	// has no Always Approve. The cosigner role does not read it.
	Plan *PlanFacts
	// Networks maps genesis hashes to networks for the cosigner role's
	// known-network check; the zero value knows the built-in networks.
	// Client routing reads the mapping compiled into each policy instead.
	Networks apconfig.GenesisHashNetworkResolver
}

// PlanFacts are what the planner reports about how it built Group. The
// approval rule checks them against Group itself rather than trusting them.
type PlanFacts struct {
	// RequestCount is the number of caller requests.
	RequestCount int
	// AuthAddressPresent reports that the first request named its auth address.
	AuthAddressPresent bool
	HasPassthrough     bool
	HasForeign         bool
	IsPreGrouped       bool
	// DummiesNeeded is the number of dummies the planner computed it needed;
	// DummyCount is the number it appended.
	DummiesNeeded int
	DummyCount    int
	// LsigIndices are the positions signed by a LogicSig, and LSigCount the
	// fee plan's LogicSig count.
	LsigIndices []int
	LSigCount   int
	// TotalFees is the signer's fee adjustment.
	TotalFees               uint64
	ProgramFeeContribution  uint64
	NativePQFeeContribution uint64
}

// Outcome is the tier that decided.
type Outcome int

const (
	// Default means no policy rule decided: the Operator Default applies.
	Default Outcome = iota
	// Reject is Always Deny.
	Reject
	// Review is Always Review.
	Review
	// Approve is Always Approve.
	Approve
)

// String is the outcome's word: "default", "reject", "review" or "approve".
func (o Outcome) String() string {
	switch o {
	case Reject:
		return "reject"
	case Review:
		return "review"
	case Approve:
		return "approve"
	default:
		return "default"
	}
}

// ParseOutcome is the outcome a word names.
func ParseOutcome(word string) (Outcome, bool) {
	for _, o := range []Outcome{Default, Reject, Review, Approve} {
		if o.String() == word {
			return o, true
		}
	}
	return Default, false
}

// Verdict is the evaluator's answer. A cosigner verdict is Approve or Reject. Reject carries every violation in the
// order the daemon reports them, each with its group index. Review carries
// the deciding rule ID, empty when review is required without one; Approve
// carries the approval rule ID.
type Verdict struct {
	Outcome    Outcome
	RuleID     string
	Violations []policy.LintViolation
}

// ErrPolicyNotLoaded is returned, with no verdict, when a judged signer slot
// has no policy. It is a server fault, not a policy rejection.
var ErrPolicyNotLoaded = errors.New("policy is not loaded")

// Evaluate computes the verdict for in.Role. For client signing that is
// Always Deny, then Always Review, then Always Approve when nothing asked for
// review, else the Operator Default. For a cosigner it is Approve or Reject.
func Evaluate(in Input) (Verdict, error) {
	if in.Role == RoleCosigner {
		return cosignerVerdict(in)
	}
	violations, err := Deny(in)
	if err != nil {
		return Verdict{}, err
	}
	if len(violations) > 0 {
		return Verdict{Outcome: Reject, Violations: violations}, nil
	}
	if ruleID, review := ReviewRule(in); review {
		return Verdict{Outcome: Review, RuleID: ruleID}, nil
	}
	if ruleID, approved := ApprovalRule(in); approved {
		return Verdict{Outcome: Approve, RuleID: ruleID}, nil
	}
	return Verdict{Outcome: Default}, nil
}

// Deny returns the Always Deny violations of every signer slot, in slot
// order and each with its group index: a slot's transaction rules, then its
// transfer routing. A signer slot with no policy ends the evaluation with
// ErrPolicyNotLoaded.
func Deny(in Input) ([]policy.LintViolation, error) {
	var violations []policy.LintViolation
	for _, slot := range in.Slots {
		if slot.Class != SlotSigner {
			continue
		}
		if slot.Policy == nil {
			return nil, ErrPolicyNotLoaded
		}
		txn := in.Group[slot.Index]
		found := policy.CheckTxnPolicyLintsIn(txn, slot.Policy, policy.LintContext{
			KnownAddresses: in.KnownAddresses, ProtocolRekeyTargets: in.ProtocolRekeyTargets,
		})
		found = append(found, policy.CheckTxnTransferRoutingPolicyLints(txn, slot.Policy)...)
		for i := range found {
			found[i].TxnIndex = slot.Index
		}
		violations = append(violations, found...)
	}
	return violations, nil
}

// ReviewRule reports whether Always Review applies and the deciding rule:
// the first hit in slot order. A signer slot asks for review by its
// transaction rules, then its transfer routing, then its warnings when
// always_review_warnings is on; a passthrough or foreign slot by any
// warning. A forced review replaces the rule. A signer slot with no policy
// asks for review with no rule.
func ReviewRule(in Input) (ruleID string, review bool) {
	ruleID, review = reviewRule(in)
	if in.ForcedReviewRuleID != "" {
		return in.ForcedReviewRuleID, true
	}
	return ruleID, review
}

func reviewRule(in Input) (string, bool) {
	warnCtx := approvalpolicy.Context{KnownAddresses: in.KnownAddresses, ProtocolRekeyTargets: in.ProtocolRekeyTargets}
	for _, slot := range in.Slots {
		txn := in.Group[slot.Index]
		if slot.Class != SlotSigner {
			// The signer contributes no signature here, but a group it
			// co-signs that rekeys, closes, clawbacks, or otherwise carries a
			// dangerous field via another leg requires review even when
			// always_review_warnings is off (it governs the signer's own legs).
			if len(approvalpolicy.CheckDecodedTxnWarningsIn(txn, warnCtx)) > 0 {
				return policy.AlwaysReviewWarningsRuleID, true
			}
			continue
		}
		cfg := slot.Policy
		if cfg == nil {
			return "", true
		}
		if violations := policy.CheckTxnReviewPolicyLints(txn, cfg); len(violations) > 0 {
			return violations[0].RuleID, true
		}
		if violations := policy.CheckTxnTransferRoutingReviewPolicyLints(txn, cfg); len(violations) > 0 {
			return violations[0].RuleID, true
		}
		if cfg.AlwaysReviewWarnings && len(approvalpolicy.CheckDecodedTxnWarningsIn(txn, warnCtx)) > 0 {
			return policy.AlwaysReviewWarningsRuleID, true
		}
	}
	return "", false
}

// ApprovalRule reports whether Always Approve applies. Its one rule,
// auto_approve_self_noop_transfer, approves a single signer request that is
// a self no-op transfer, built with at most the signer's own LogicSig-budget
// dummies, under a policy that turns the rule on.
func ApprovalRule(in Input) (ruleID string, approved bool) {
	plan := in.Plan
	if plan == nil || len(in.Group) == 0 || plan.RequestCount != 1 {
		return "", false
	}
	if plan.HasPassthrough || plan.HasForeign || plan.IsPreGrouped || !plan.AuthAddressPresent {
		return "", false
	}
	var first *Slot
	for i := range in.Slots {
		if in.Slots[i].Index == 0 {
			first = &in.Slots[i]
		}
	}
	if first == nil || first.Class != SlotSigner {
		return "", false
	}
	if first.Policy == nil || !first.Policy.AutoApproveSelfNoOpTransfer {
		return "", false
	}
	if !MatchesSelfNoOpPlan(in.Group, *plan) {
		return "", false
	}
	return policy.AutoApproveSelfNoOpTransferRuleID, true
}

// MatchesSelfNoOpPlan reports whether group, as the planner reports building
// it, is a self no-op transfer with at most the signer's own dummies: no
// priced program bytes or post-quantum fee, a dummy count that agrees with
// both what the planner needed and the group's length, and with dummies, a
// LogicSig at position zero alone whose fee increase covers exactly the
// dummies, each of them in the signer's dummy shape.
func MatchesSelfNoOpPlan(group []types.Transaction, plan PlanFacts) bool {
	if plan.ProgramFeeContribution != 0 || plan.NativePQFeeContribution != 0 {
		return false
	}
	dummyCount := plan.DummyCount
	if plan.DummiesNeeded != dummyCount || len(group) != 1+dummyCount {
		return false
	}
	if dummyCount == 0 {
		return plan.TotalFees == 0 && policy.MatchesSelfNoOpTransferAutoApproval(group[0])
	}

	if len(plan.LsigIndices) != 1 || plan.LsigIndices[0] != 0 || plan.LSigCount != 1 {
		return false
	}
	maxDummyFees := uint64(dummyCount) * policy.SelfNoOpTransferMaxFeeMicroAlgos
	if plan.TotalFees == 0 || plan.TotalFees > maxDummyFees {
		return false
	}

	normalized := group[0]
	if uint64(normalized.Fee) < plan.TotalFees {
		return false
	}
	normalized.Fee = types.MicroAlgos(uint64(normalized.Fee) - plan.TotalFees)
	normalized.Group = types.Digest{}
	if !policy.MatchesSelfNoOpTransferAutoApproval(normalized) {
		return false
	}

	for i, dummy := range group[1:] {
		if !signingutil.IsSignerAddedDummy(dummy, group[0], i) {
			return false
		}
	}
	return true
}
