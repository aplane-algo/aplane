// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"fmt"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/types"
	"gopkg.in/yaml.v3"
)

// StoredRekeyPolicy is the YAML representation of sentry rekey authorization.
// It is intentionally narrow: every allowed edge names a sender address or
// flat address set and a list of allowed rekey target addresses or flat sets.
type StoredRekeyPolicy struct {
	Allowed []StoredRekeyRule `yaml:"allowed,omitempty"`
}

type StoredRekeyRule struct {
	Sender  string   `yaml:"sender"`
	Targets []string `yaml:"targets"`
}

func (p *StoredRekeyPolicy) Clone() *StoredRekeyPolicy {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Allowed = make([]StoredRekeyRule, len(p.Allowed))
	for i, rule := range p.Allowed {
		cp.Allowed[i] = rule.Clone()
	}
	return &cp
}

func (r StoredRekeyRule) Clone() StoredRekeyRule {
	return StoredRekeyRule{
		Sender:  r.Sender,
		Targets: append([]string(nil), r.Targets...),
	}
}

func (p *StoredRekeyPolicy) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("rekey_policy must be a mapping")
	}
	allowed := map[string]struct{}{"allowed": {}}
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown rekey_policy field %q", key)
		}
	}
	type rawPolicy StoredRekeyPolicy
	var raw rawPolicy
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*p = StoredRekeyPolicy(raw)
	return nil
}

func (r *StoredRekeyRule) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("rekey_policy.allowed entry must be a mapping")
	}
	allowed := map[string]struct{}{"sender": {}, "targets": {}}
	for i := 0; i < len(value.Content); i += 2 {
		key := value.Content[i].Value
		if _, ok := allowed[key]; !ok {
			return fmt.Errorf("unknown rekey_policy.allowed field %q", key)
		}
	}
	type rawRule StoredRekeyRule
	var raw rawRule
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*r = StoredRekeyRule(raw)
	return nil
}

// RekeyPolicy is the compiled effective sentry rekey policy.
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

func (p *StoredRekeyPolicy) Apply(base *RekeyPolicy, addressSets map[string]compiledAddressSet) (*RekeyPolicy, error) {
	if p == nil {
		if base == nil {
			return nil, nil
		}
		return base.Clone(), nil
	}
	out := &RekeyPolicy{Allowed: make([]CompiledRekeyRule, 0, len(p.Allowed))}
	for i, rule := range p.Allowed {
		sender, err := compileRekeyAddressTerm(fmt.Sprintf("allowed[%d].sender", i), rule.Sender, addressSets)
		if err != nil {
			return nil, err
		}
		targets, err := compileRekeyAddressTerms(fmt.Sprintf("allowed[%d].targets", i), rule.Targets, addressSets)
		if err != nil {
			return nil, err
		}
		out.Allowed = append(out.Allowed, CompiledRekeyRule{Sender: sender, Targets: targets})
	}
	return out, nil
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

func compileRekeyAddressTerm(label, raw string, addressSets map[string]compiledAddressSet) (compiledRekeyAddressTerms, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return compiledRekeyAddressTerms{}, fmt.Errorf("rekey_policy.%s is required", label)
	}
	return compileRekeyAddressTerms(label, []string{raw}, addressSets)
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
