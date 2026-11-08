// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package txeffects

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/boundedmeta"
)

// Path is the authorization path a declaration admits a transaction on.
type Path string

const (
	PathSpend         Path = "spend"
	PathSpendingRekey Path = "spending_rekey"
	PathRefused       Path = "refused"
)

// Rule names the rule that decided a transaction. Every decision comes from a
// named rule, so a test can prove that no effect reaches a default branch.
type Rule string

const (
	RuleFeeCeiling       Rule = "fee_ceiling"
	RuleSpendAllowed     Rule = "spend_allowed"
	RuleSpendNotDeclared Rule = "spend_not_declared"
	RuleRekeyAllowed     Rule = "rekey_allowed"
	RuleRekeyRefused     Rule = "rekey_refused"
	RuleHybridRekey      Rule = "hybrid_rekey"
	RuleDeniedEffect     Rule = "denied_effect"
	RuleDeniedType       Rule = "denied_type"
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
// declaration allows. Closes, clawback, hybrid rekeys and every other transaction
// type are refused for every declaration. An invalid declaration is an error, not
// a refusal, so a corrupt declaration can't be mistaken for a policy decision.
func ClassifyFor(txn types.Transaction, declaration boundedmeta.PathDeclaration) (Decision, error) {
	switch declaration.Rekey {
	case boundedmeta.RekeyRefused, boundedmeta.RekeySpendingKey:
	default:
		return Decision{}, fmt.Errorf("unsupported rekey setting %q", declaration.Rekey)
	}
	contract := declaration.Contract
	refuse := func(decision Decision, rule Rule, reason string) (Decision, error) {
		decision.Path, decision.Rule, decision.Reason = PathRefused, rule, reason
		return decision, nil
	}

	decision := Decision{Classification: Classify(txn)}
	if declaration.MaxFee != nil && uint64(txn.Fee) > *declaration.MaxFee {
		return refuse(decision, RuleFeeCeiling, fmt.Sprintf("%s fee %d exceeds account maximum %d", contract, txn.Fee, *declaration.MaxFee))
	}
	switch decision.Shape {
	case ShapePureSpend:
		if !declaration.AllowsSpendEffect(string(decision.SpendEffect)) {
			return refuse(decision, RuleSpendNotDeclared, fmt.Sprintf("%s account does not allow spend effect %q", contract, decision.SpendEffect))
		}
		decision.Path, decision.Rule = PathSpend, RuleSpendAllowed
		return decision, nil
	case ShapePureRekey:
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
