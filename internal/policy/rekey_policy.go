// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// RekeyPolicy is the compiled effective cosigner rekey policy.
type RekeyPolicy struct {
	Allowed []CompiledRekeyRule
}

type CompiledRekeyRule struct {
	Sender  compiledRekeyAddressTerms
	Targets compiledRekeyAddressTerms
}

type compiledRekeyAddressTerms struct {
	Direct []types.Address
}

func (p *RekeyPolicy) Clone() *RekeyPolicy {
	if p == nil {
		return nil
	}
	cp := &RekeyPolicy{Allowed: make([]CompiledRekeyRule, len(p.Allowed))}
	for i, rule := range p.Allowed {
		cp.Allowed[i] = CompiledRekeyRule{
			Sender:  cloneCompiledRekeyAddressTerms(rule.Sender),
			Targets: cloneCompiledRekeyAddressTerms(rule.Targets),
		}
	}
	return cp
}

func (p *RekeyPolicy) Allows(sender, target types.Address) bool {
	if p == nil {
		return false
	}
	for _, rule := range p.Allowed {
		if !rekeyAddressTermsContain(rule.Sender, sender) {
			continue
		}
		if rekeyAddressTermsContain(rule.Targets, target) {
			return true
		}
	}
	return false
}

func compileRekeyAddressTerms(label string, raw []string, addressSets map[string]compiledAddressSet) (compiledRekeyAddressTerms, error) {
	if len(raw) == 0 {
		return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s is required", label)
	}
	var out compiledRekeyAddressTerms
	for _, term := range raw {
		term = strings.TrimSpace(term)
		switch {
		case term == "":
			return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s contains an empty address term", label)
		case term == "*":
			return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s does not support wildcard addresses", label)
		case term == "self":
			return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s does not support self", label)
		case strings.HasPrefix(term, "@"):
			name := strings.TrimPrefix(term, "@")
			set, ok := addressSets[name]
			if !ok {
				return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s references unresolved address set %q", label, name)
			}
			if len(set.ByNetwork) > 0 {
				return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s references network-specific address set %q", label, name)
			}
			out.Direct = append(out.Direct, set.Flat...)
		default:
			addr, err := types.DecodeAddress(term)
			if err != nil {
				return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s invalid address %q: %w", label, term, err)
			}
			out.Direct = append(out.Direct, addr)
		}
	}
	if len(out.Direct) == 0 {
		return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s must resolve to at least one address", label)
	}
	return out, nil
}

func rekeyAddressTermsContain(terms compiledRekeyAddressTerms, candidate types.Address) bool {
	for _, addr := range terms.Direct {
		if addr == candidate {
			return true
		}
	}
	return false
}

func cloneCompiledRekeyAddressTerms(in compiledRekeyAddressTerms) compiledRekeyAddressTerms {
	return compiledRekeyAddressTerms{Direct: append([]types.Address(nil), in.Direct...)}
}
