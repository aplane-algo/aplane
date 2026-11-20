// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package externalcheck runs a cosigner document's external checks: REST
// lookups whose JSON answers must satisfy the document's rules before the
// cosigner signs. The checks only refuse. They are run for a request the
// policy would sign, and anything that goes wrong with a lookup refuses it.
//
// The work is three steps. Plan lists the lookups a request needs and what
// each must be judged against; it is pure. The fetcher makes the lookups.
// Judge applies a check's rules to an answer; it is pure, and it is what an
// offline tool runs on a canned answer.
package externalcheck

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/policy"
)

// MaxLookups is the most lookups one component request may need, after
// identical ones are merged.
const MaxLookups = 32

// Request is the component request the checks judge: the group as it will go
// on chain and the positions this cosigner signs.
type Request struct {
	WitnessKey string
	Group      []types.Transaction
	Targets    []int
	// NetworkOf names the network of a transaction; "" when it is unknown.
	NetworkOf func(types.Transaction) string
}

// Facts are a unit's facts by name. A fact a unit does not have is absent
// from the map.
type Facts map[string]string

// Lookup is one GET a request needs.
type Lookup struct {
	SourceName string
	Source     policy.ExternalSourceV1
	URL        string
	// Path is the request path and query, for the audit record.
	Path string
}

// Judgment is one check applied to one unit, against the answer of a lookup.
type Judgment struct {
	Check  policy.ExternalCheckV1
	Unit   string
	Facts  Facts
	Lookup int // index into Plan.Lookups
}

// Plan is what a request needs: its lookups, identical ones merged, and the
// judgments to make on their answers, in document order.
type Plan struct {
	Lookups   []Lookup
	Judgments []Judgment
}

// Refusal says which check refused which unit, and why.
type Refusal struct {
	CheckID string
	// Outcome is "" when a rule did not hold, or one of the policy package's
	// ExternalCheck*Outcome values when the check could not be judged.
	Outcome string
	Unit    string
	Source  string
	Path    string
	// Detail is what failed, for the audit record. It may quote the answer.
	Detail string
}

// RuleID is the refusal's policy rule ID.
func (r *Refusal) RuleID() string { return policy.ExternalCheckRuleID(r.CheckID, r.Outcome) }

// Message is what the requester is told: the check and the unit, and nothing
// of the answer, which belongs to the cosigner's operator and the source.
func (r *Refusal) Message() string {
	return fmt.Sprintf("external check %s refused %s (%s)", r.CheckID, r.Unit, r.RuleID())
}

// AuditReason is the refusal in full, for the cosigner's own audit record.
func (r *Refusal) AuditReason() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: external check %s refused %s", r.RuleID(), r.CheckID, r.Unit)
	if r.Source != "" {
		fmt.Fprintf(&b, "; source %s", r.Source)
	}
	if r.Path != "" {
		fmt.Fprintf(&b, ", GET %s", r.Path)
	}
	if r.Detail != "" {
		fmt.Fprintf(&b, ": %s", r.Detail)
	}
	return b.String()
}

// unit is one thing a check runs on.
type unit struct {
	label   string
	network string
	facts   Facts
	kind    policy.TransferMovementKind // set for a movement
}

// BuildPlan lists the lookups and judgments req needs under checks. A unit
// that lacks a fact its check uses, a check whose source is missing, and a
// request that needs more than MaxLookups lookups are refusals.
func BuildPlan(checks []policy.ExternalCheckV1, sources map[string]policy.ExternalSourceV1, req Request) (*Plan, *Refusal) {
	plan := &Plan{}
	merged := make(map[string]int)
	requestUnits, transactionUnits, movementUnits := requestUnitsOf(req)
	for _, check := range checks {
		source, ok := sources[check.Source]
		if !ok {
			return nil, &Refusal{CheckID: check.ID, Outcome: policy.ExternalCheckUnavailableOutcome, Unit: "the request",
				Source: check.Source, Detail: "the document defines no such source"}
		}
		var units []unit
		switch check.Scope {
		case policy.ExternalScopeRequest:
			units = requestUnits
		case policy.ExternalScopeTransaction:
			units = transactionUnits
		case policy.ExternalScopeMovement:
			units = movementUnits
		}
		for _, u := range units {
			if !check.CoversNetwork(u.network) {
				continue
			}
			if check.Scope == policy.ExternalScopeMovement && !check.CoversMovementKind(u.kind) {
				continue
			}
			for _, name := range check.UsedFacts() {
				if _, has := u.facts[name]; !has {
					return nil, &Refusal{CheckID: check.ID, Outcome: policy.ExternalCheckMissingFactOutcome, Unit: u.label,
						Source: check.Source, Detail: fmt.Sprintf("it has no %s", name)}
				}
			}
			lookup, err := renderLookup(check, source, u.facts)
			if err != nil {
				return nil, &Refusal{CheckID: check.ID, Outcome: policy.ExternalCheckUnavailableOutcome, Unit: u.label,
					Source: check.Source, Detail: err.Error()}
			}
			key := check.Source + "\x00" + lookup.URL
			index, seen := merged[key]
			if !seen {
				if len(plan.Lookups) == MaxLookups {
					return nil, &Refusal{CheckID: check.ID, Outcome: policy.ExternalCheckTooManyLookupsOutcome, Unit: u.label,
						Source: check.Source, Detail: fmt.Sprintf("the request needs more than %d lookups", MaxLookups)}
				}
				index = len(plan.Lookups)
				merged[key] = index
				plan.Lookups = append(plan.Lookups, lookup)
			}
			plan.Judgments = append(plan.Judgments, Judgment{Check: check, Unit: u.label, Facts: u.facts, Lookup: index})
		}
	}
	return plan, nil
}

// requestUnitsOf lists a request's units at each scope: the request itself,
// each transaction the cosigner signs, and each transfer movement of those.
func requestUnitsOf(req Request) (request, transactions, movements []unit) {
	networkOf := req.NetworkOf
	if networkOf == nil {
		networkOf = func(types.Transaction) string { return "" }
	}
	for _, target := range req.Targets {
		if target < 0 || target >= len(req.Group) {
			continue
		}
		txn := req.Group[target]
		network := networkOf(txn)
		base := Facts{"network": network, "witness_key": req.WitnessKey}
		if request == nil {
			request = []unit{{label: "the request", network: network, facts: base}}
		}
		txFacts := cloneFacts(base)
		txFacts["sender"] = txn.Sender.String()
		txFacts["txid"] = crypto.GetTxID(txn)
		txFacts["type"] = string(txn.Type)
		txFacts["fee"] = strconv.FormatUint(uint64(txn.Fee), 10)
		if !txn.RekeyTo.IsZero() {
			txFacts["rekey_to"] = txn.RekeyTo.String()
		}
		transactions = append(transactions, unit{label: fmt.Sprintf("transaction %d", target), network: network, facts: txFacts})
		for _, m := range policy.ExtractTransferMovements(txn) {
			facts := cloneFacts(txFacts)
			facts["kind"] = string(m.Kind)
			facts["source"] = m.Source.String()
			facts["destination"] = m.Destination.String()
			if m.Kind == policy.TransferMovementClawback {
				facts["asset_source"] = m.AssetSource.String()
			}
			if m.Asset.Algo {
				facts["asset"], facts["asset_id"] = "algo", "0"
			} else {
				id := strconv.FormatUint(m.Asset.ASAID, 10)
				facts["asset"], facts["asset_id"] = "asa:"+id, id
			}
			if m.AmountKnown {
				facts["amount"] = strconv.FormatUint(m.Amount, 10)
			}
			movements = append(movements, unit{
				label:   fmt.Sprintf("the %s movement of transaction %d", m.Kind, target),
				network: network, facts: facts, kind: m.Kind,
			})
		}
	}
	return request, transactions, movements
}

func cloneFacts(in Facts) Facts {
	out := make(Facts, len(in)+8)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// renderLookup builds a check's GET for one unit: the source's base path with
// trailing "/" removed, then the check's path with each fact escaped as one
// path segment, then the query in name order with each whole value escaped.
// The result must still be at the source's scheme, host and port.
func renderLookup(check policy.ExternalCheckV1, source policy.ExternalSourceV1, facts Facts) (Lookup, error) {
	base, err := url.Parse(source.BaseURL)
	if err != nil {
		return Lookup{}, fmt.Errorf("source base_url does not parse")
	}
	var path strings.Builder
	path.WriteString(strings.TrimRight(base.EscapedPath(), "/"))
	for _, part := range check.Path.Parts {
		if part.Fact != "" {
			path.WriteString(url.PathEscape(facts[part.Fact]))
			continue
		}
		path.WriteString(part.Literal)
	}
	pathAndQuery := path.String()
	for i, param := range check.Query {
		var value strings.Builder
		for _, part := range param.Value.Parts {
			if part.Fact != "" {
				value.WriteString(facts[part.Fact])
				continue
			}
			value.WriteString(part.Literal)
		}
		sep := "&"
		if i == 0 {
			sep = "?"
		}
		pathAndQuery += sep + url.QueryEscape(param.Name) + "=" + url.QueryEscape(value.String())
	}
	full := base.Scheme + "://" + base.Host + pathAndQuery
	parsed, err := url.Parse(full)
	if err != nil || parsed.Scheme != base.Scheme || parsed.Host != base.Host || parsed.User != nil || parsed.Fragment != "" {
		return Lookup{}, fmt.Errorf("the rendered request leaves the source's origin")
	}
	return Lookup{SourceName: check.Source, Source: source, URL: full, Path: pathAndQuery}, nil
}
