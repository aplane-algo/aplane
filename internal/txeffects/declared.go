// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects

import (
	"fmt"
	"slices"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

// Path is the authorization path a declaration admits a transaction on.
type Path string

// The admitted paths use the names argument path masks and resource profiles use.
const (
	PathSpend         Path = boundedmeta.PathSpend
	PathSpendingRekey Path = boundedmeta.PathSpendingRekey
	PathListedRekey   Path = boundedmeta.PathListedRekey
	PathRefused       Path = "refused"
)

// Rule names the rule that decided a transaction. Every decision comes from a
// named rule, so a test can prove that no effect reaches a default branch.
type Rule string

const (
	RuleFeeCeiling       Rule = "fee_ceiling"
	RuleSpendAllowed     Rule = "spend_allowed"
	RuleSpendNotDeclared Rule = "spend_not_declared"
	// RuleOpenSpend sends a plain host's transaction that doesn't rekey to the
	// spend path: a plain host has no host rules, and its cosigner's policy
	// restricts what gets signed.
	RuleOpenSpend Rule = "open_spend"
	// RuleRekeyAllowed sends a pure rekey to the spending-key path, with the
	// cosigner on a cosigned account. Under plus cosigned the signer moves a
	// listed target to the listed path instead: membership is checked against
	// the stored list, which a declaration doesn't carry.
	RuleRekeyAllowed Rule = "rekey_allowed"
	// RuleRekeyListed sends a pure rekey under only these to the listed path.
	// Whether the target is on the list is the signer's to check against the
	// stored list; a declaration carries only the list's root.
	RuleRekeyListed  Rule = "rekey_listed"
	RuleRekeyRefused Rule = "rekey_refused"
	RuleHybridRekey  Rule = "hybrid_rekey"
	RuleDeniedEffect Rule = "denied_effect"
	RuleDeniedType   Rule = "denied_type"
)

// Decision is what a path declaration makes of one transaction. Reason is set
// whenever Path is PathRefused.
type Decision struct {
	Classification
	Path   Path
	Rule   Rule
	Reason string
}

// ClassifyFor decides which path, if any, a declaration admits a transaction on.
// It checks the fee ceiling first, then the transaction's shape against what the
// declaration allows. A bounded host refuses closes, clawback, hybrid rekeys and
// every transaction type outside its spend effects. A plain host takes every
// transaction that doesn't rekey as a spend, and refuses only a rekey that isn't
// pure. An invalid declaration is an error, not a refusal, so a corrupt
// declaration can't be mistaken for a policy decision.
func ClassifyFor(txn types.Transaction, declaration boundedmeta.PathDeclaration) (Decision, error) {
	if err := boundedmeta.ValidateRekeySetting(declaration.Rekey); err != nil {
		return Decision{}, err
	}
	contract := declaration.Contract
	switch contract {
	case boundedmeta.Contract:
	case boundedmeta.PlainContract:
		if declaration.MaxFee != nil || len(declaration.SpendEffects) != 0 {
			return Decision{}, fmt.Errorf("%s declares no fee ceiling or spend effects", contract)
		}
	default:
		return Decision{}, fmt.Errorf("unsupported bounded authorization contract %q", contract)
	}
	refuse := func(decision Decision, rule Rule, reason string) (Decision, error) {
		decision.Path, decision.Rule, decision.Reason = PathRefused, rule, reason
		return decision, nil
	}

	decision := Decision{Classification: Classify(txn)}
	if declaration.MaxFee != nil && uint64(txn.Fee) > *declaration.MaxFee {
		return refuse(decision, RuleFeeCeiling, fmt.Sprintf("%s fee %d exceeds account maximum %d", contract, txn.Fee, *declaration.MaxFee))
	}
	if contract == boundedmeta.PlainContract && !decision.Facts.Has(EffectRekey) {
		return classifyOpenSpend(txn, decision, refuse)
	}
	switch decision.Shape {
	case ShapePureSpend:
		if !declaration.AllowsSpendEffect(string(decision.SpendEffect)) {
			return refuse(decision, RuleSpendNotDeclared, fmt.Sprintf("%s account does not allow spend effect %q", contract, decision.SpendEffect))
		}
		decision.Path, decision.Rule = PathSpend, RuleSpendAllowed
		return decision, nil
	case ShapePureRekey:
		if declaration.Rekey == boundedmeta.RekeyRefused && declaration.RekeyList {
			decision.Path, decision.Rule = PathListedRekey, RuleRekeyListed
			return decision, nil
		}
		if declaration.Rekey == boundedmeta.RekeyRefused {
			return refuse(decision, RuleRekeyRefused, fmt.Sprintf("%s account permanently disables rekey", contract))
		}
		decision.Path, decision.Rule = PathSpendingRekey, RuleRekeyAllowed
		return decision, nil
	case ShapeHybrid:
		return refuse(decision, RuleHybridRekey, fmt.Sprintf("%s rejects hybrid transaction effects: %s", contract, effectNames(decision.Facts)))
	case ShapeDeniedEffect:
		return refuse(decision, RuleDeniedEffect, fmt.Sprintf("%s rejects transaction effects: %s", contract, effectNames(decision.Facts)))
	case ShapeDeniedType:
		return refuse(decision, RuleDeniedType, fmt.Sprintf("%s rejects transaction type %q", contract, txn.Type))
	default:
		return Decision{}, fmt.Errorf("unknown transaction shape %q", decision.Shape)
	}
}

// classifyOpenSpend decides a plain host's transaction that doesn't rekey. The
// manifest lists every type and effect a spend may carry, so a type or effect
// it doesn't name is refused by rule rather than passed by default.
func classifyOpenSpend(txn types.Transaction, decision Decision, refuse func(Decision, Rule, string) (Decision, error)) (Decision, error) {
	contract := plainManifest.Contract
	if !slices.Contains(plainManifest.SpendTypes, txn.Type) {
		return refuse(decision, RuleDeniedType, fmt.Sprintf("%s does not classify transaction type %q", contract, txn.Type))
	}
	for _, effect := range decision.Facts.Effects() {
		if !slices.Contains(plainManifest.SpendEffects, effect) {
			return refuse(decision, RuleDeniedEffect, fmt.Sprintf("%s does not classify transaction effect %s", contract, effect))
		}
	}
	decision.Path, decision.Rule = PathSpend, RuleOpenSpend
	return decision, nil
}

func effectNames(facts Facts) string {
	effects := facts.Effects()
	if len(effects) == 0 {
		return "none"
	}
	names := make([]string, len(effects))
	for i, effect := range effects {
		names[i] = string(effect)
	}
	return strings.Join(names, ", ")
}
