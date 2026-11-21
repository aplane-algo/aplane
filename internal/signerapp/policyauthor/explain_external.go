// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyauthor

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/policy"
)

// externalChecks says a cosigner document's sources and checks in words.
func (e *explainer) externalChecks() {
	d := e.doc
	e.line("External checks: asked only when this document would sign; a check can only refuse")
	e.line("Sources:")
	for _, name := range d.ExternalSourceNames() {
		e.line("  %s: %s", name, externalSourceWords(d.ExternalSources[name]))
	}
	e.line("Checks:")
	for _, c := range d.ExternalChecks {
		e.line("  %s: %s, %s", c.ID, externalScopeWords(c), externalNetworkWords(c))
		if c.Description != "" {
			e.line("    %s", c.Description)
		}
		e.line("    asks %s: GET %s", c.Source, externalRequestWords(d.ExternalSources[c.Source], c))
		var holds []string
		if c.EchoPointer != nil {
			holds = append(holds, externalPointerWords(*c.EchoPointer)+" is the request ID the cosigner sent")
		}
		for _, r := range c.Require {
			holds = append(holds, externalRuleWords(r))
		}
		if len(holds) == 1 {
			e.line("    refuses unless %s", holds[0])
			continue
		}
		e.line("    refuses unless all of these hold:")
		for _, h := range holds {
			e.line("      %s", h)
		}
	}
}

func externalSourceWords(s policy.ExternalSourceV1) string {
	parts := []string{s.BaseURL, "no token"}
	if s.Token != nil {
		parts[1] = "with a token"
	}
	switch len(s.TLSPins) {
	case 0:
	case 1:
		parts = append(parts, "pinned to 1 server key")
	default:
		parts = append(parts, fmt.Sprintf("pinned to %d server keys", len(s.TLSPins)))
	}
	return strings.Join(parts, ", ")
}

func externalScopeWords(c policy.ExternalCheckV1) string {
	switch c.Scope {
	case policy.ExternalScopeRequest:
		return "once per request"
	case policy.ExternalScopeTransaction:
		return "for each transaction this cosigner signs"
	}
	if c.MovementKinds == nil {
		return "for each movement of a payment or asset transfer this cosigner signs"
	}
	kinds := make([]string, len(c.MovementKinds))
	for i, k := range c.MovementKinds {
		kinds[i] = string(k)
	}
	return "for each " + joinOr(kinds) + " movement"
}

func externalNetworkWords(c policy.ExternalCheckV1) string {
	if c.NetworkWildcard {
		return "on any network"
	}
	return "on " + joinOr(c.Networks)
}

// externalRequestWords is the path and query a check asks for: the
// source's base path joined with the check's path template, as the cosigner
// joins them, with the placeholders as written.
func externalRequestWords(s policy.ExternalSourceV1, c policy.ExternalCheckV1) string {
	base := ""
	if u, err := url.Parse(s.BaseURL); err == nil {
		base = strings.TrimSuffix(u.EscapedPath(), "/")
	}
	out := base + c.Path.Text
	if len(c.Query) > 0 {
		params := make([]string, len(c.Query))
		for i, q := range c.Query {
			params[i] = q.Name + "=" + q.Value.Text
		}
		out += "?" + strings.Join(params, "&")
	}
	return out
}

var externalOpWords = map[policy.ExternalOp]string{
	policy.ExternalOpEq:    "is",
	policy.ExternalOpNe:    "is not",
	policy.ExternalOpLt:    "is less than",
	policy.ExternalOpLe:    "is at most",
	policy.ExternalOpGt:    "is more than",
	policy.ExternalOpGe:    "is at least",
	policy.ExternalOpIn:    "is one of",
	policy.ExternalOpNotIn: "is not one of",
}

// externalRuleWords says a rule, e.g. "/risk/score is at most 30".
func externalRuleWords(r policy.ExternalRuleV1) string {
	subject := externalPointerWords(r.Pointer)
	switch r.Op {
	case policy.ExternalOpPresent:
		return subject + " is present"
	case policy.ExternalOpAbsent:
		return subject + " is absent"
	}
	verb, ok := externalOpWords[r.Op]
	if !ok {
		verb = string(r.Op)
	}
	var operand string
	switch {
	case r.Number != nil:
		operand = *r.Number
	case r.String != nil:
		operand = strconv.Quote(*r.String)
	case r.Bool != nil:
		operand = strconv.FormatBool(*r.Bool)
	case r.Numbers != nil:
		operand = strings.Join(r.Numbers, ", ")
	case r.Strings != nil:
		quoted := make([]string, len(r.Strings))
		for i, s := range r.Strings {
			quoted[i] = strconv.Quote(s)
		}
		operand = strings.Join(quoted, ", ")
	case r.Fact != "":
		operand = externalFactWords(r.Fact)
	}
	return subject + " " + verb + " " + operand
}

func externalPointerWords(pointer string) string {
	if pointer == "" {
		return "the whole answer"
	}
	return pointer
}

var externalFactPhrases = map[string]string{
	"network":      "the request's network",
	"witness_key":  "the requested witness key",
	"sender":       "the transaction's sender",
	"txid":         "the transaction ID",
	"type":         "the transaction's type",
	"fee":          "the transaction's fee",
	"rekey_to":     "the transaction's rekey target",
	"kind":         "the movement's kind",
	"source":       "the movement's source",
	"asset_source": "the account the asset is clawed back from",
	"destination":  "the movement's destination",
	"asset":        "the movement's asset",
	"asset_id":     "the movement's asset ID",
	"amount":       "the movement's amount",
}

func externalFactWords(name string) string {
	if phrase, ok := externalFactPhrases[name]; ok {
		return phrase
	}
	return name
}

// joinOr joins words as "a", "a or b", or "a, b or c".
func joinOr(words []string) string {
	return joinLast(words, " or ")
}

// joinAnd joins words as "a", "a and b", or "a, b and c".
func joinAnd(words []string) string {
	return joinLast(words, " and ")
}

func joinLast(words []string, last string) string {
	if len(words) <= 1 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + last + words[len(words)-1]
}
