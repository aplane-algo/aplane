// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// RekeyPolicy is the compiled effective cosigner rekey policy.
type RekeyPolicy struct {
	Allowed []CompiledRekeyRule
}

// CompiledRekeyRule is one allowed edge. Its terms are the route address
// terms: a wildcard matches every address, and Self, a target-only term,
// matches the sender's own address (a rekey back to the account's own key).
// Rekey edges aren't network-scoped, so a set is resolved to its addresses at
// compile time and Sets is always empty.
type CompiledRekeyRule struct {
	Sender  compiledAddressTerms
	Targets compiledAddressTerms
}

func (p *RekeyPolicy) Clone() *RekeyPolicy {
	if p == nil {
		return nil
	}
	cp := &RekeyPolicy{Allowed: make([]CompiledRekeyRule, len(p.Allowed))}
	for i, rule := range p.Allowed {
		cp.Allowed[i] = CompiledRekeyRule{
			Sender:  cloneRekeyAddressTerms(rule.Sender),
			Targets: cloneRekeyAddressTerms(rule.Targets),
		}
	}
	return cp
}

// Allows reports whether some rule covers a rekey of sender to target. Both
// sides go through the route term matcher, with the sender as "self".
func (p *RekeyPolicy) Allows(sender, target types.Address) bool {
	if p == nil {
		return false
	}
	for _, rule := range p.Allowed {
		if addressTermsMatch(rule.Sender, nil, "", sender, sender) &&
			addressTermsMatch(rule.Targets, nil, "", target, sender) {
			return true
		}
	}
	return false
}

// compileRekeyAddressTerms compiles one side of a rekey rule with the route
// term compiler. allowSelf is true for targets only: a sender is always
// itself, so "self" there would be "*" under another name.
func compileRekeyAddressTerms(label string, raw []string, addressSets map[string]compiledAddressSet, allowSelf bool) (compiledAddressTerms, error) {
	if len(raw) == 0 {
		return compiledAddressTerms{}, fmt.Errorf("rekey_policy.%s is required", label)
	}
	if !allowSelf {
		for _, term := range raw {
			if term == "self" {
				return compiledAddressTerms{}, fmt.Errorf(`rekey_policy.%s: self is meaningless as a sender; use "*"`, label)
			}
		}
	}
	out, err := compileAddressTerms("rekey_policy."+label, raw, addressSets, allowSelf)
	if err != nil {
		return compiledAddressTerms{}, err
	}
	for _, name := range out.Sets {
		set := addressSets[name]
		if len(set.ByNetwork) > 0 {
			return compiledAddressTerms{}, fmt.Errorf("rekey_policy.%s references network-specific address set %q", label, name)
		}
		out.Direct = append(out.Direct, set.Flat...)
	}
	out.Sets = nil
	if !out.Wildcard && !out.Self && len(out.Direct) == 0 {
		return compiledAddressTerms{}, fmt.Errorf("rekey_policy.%s must resolve to at least one address", label)
	}
	return out, nil
}

func cloneRekeyAddressTerms(in compiledAddressTerms) compiledAddressTerms {
	return compiledAddressTerms{Wildcard: in.Wildcard, Self: in.Self, Direct: append([]types.Address(nil), in.Direct...)}
}
