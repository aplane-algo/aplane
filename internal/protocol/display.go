// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/termsafe"
)

// ValidityWindowLine is the line an approval client shows for a request's
// first_valid and last_valid: the rounds it can be submitted in, for a group
// the rounds every transaction in it is valid. A window that ends before it
// begins is said to be empty. The line is empty when the signer sent no
// window (either round is 0).
func ValidityWindowLine(firstValid, lastValid uint64) string {
	switch {
	case firstValid == 0 || lastValid == 0:
		return ""
	case lastValid < firstValid:
		return fmt.Sprintf("Valid Rounds: %d - %d (empty: no round is valid)", firstValid, lastValid)
	default:
		return fmt.Sprintf("Valid Rounds: %d - %d (window: %d blocks)", firstValid, lastValid, lastValid-firstValid)
	}
}

// TerminalSafe returns the request with every string an approval client shows
// escaped for a terminal. The signer escapes them before it sends the request;
// a client escapes them again where it receives it, so text from the
// transaction or the requesting client never drives the operator's terminal
// even if a path on the signer missed one. Escaping is idempotent.
func (m SignRequestMessage) TerminalSafe() SignRequestMessage {
	m.Address = termsafe.Line(m.Address)
	m.TxnSender = termsafe.Line(m.TxnSender)
	m.Description = termsafe.Lines(m.Description)
	if len(m.Violations) > 0 {
		m.Violations = safeViolations(m.Violations)
	}
	m.Review = m.Review.terminalSafe()
	return m
}

func safeViolations(in []PolicyViolation) []PolicyViolation {
	if in == nil {
		return nil
	}
	out := make([]PolicyViolation, len(in))
	for i, v := range in {
		v.Field = termsafe.Line(v.Field)
		v.Value = termsafe.Line(v.Value)
		v.Severity = termsafe.Line(v.Severity)
		v.Message = termsafe.Lines(v.Message)
		out[i] = v
	}
	return out
}

func safeLines(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = termsafe.Line(s)
	}
	return out
}

func safeFields(in []ReviewField) []ReviewField {
	if in == nil {
		return nil
	}
	out := make([]ReviewField, len(in))
	for i, f := range in {
		f.Label, f.Value, f.Party = termsafe.Line(f.Label), termsafe.Line(f.Value), termsafe.Line(f.Party)
		out[i] = f
	}
	return out
}

// terminalSafe is a copy of the review with every string escaped for a
// terminal. A transaction's title keeps its newlines, as the description does.
func (r *Review) terminalSafe() *Review {
	if r == nil {
		return nil
	}
	safe := *r
	safe.Version = termsafe.Line(r.Version)
	safe.Banners = safeLines(r.Banners)
	safe.Changes.Heading, safe.Changes.Lines = termsafe.Line(r.Changes.Heading), safeLines(r.Changes.Lines)
	if r.Items != nil {
		safe.Items = make([]ReviewItem, len(r.Items))
	}
	for i, item := range r.Items {
		item.Position, item.Label = termsafe.Line(item.Position), termsafe.Line(item.Label)
		item.Notes, item.Claims = safeFields(item.Notes), safeLines(item.Claims)
		item.Title, item.Sender = termsafe.Lines(item.Title), termsafe.Line(item.Sender)
		item.Fields, item.Findings = safeFields(item.Fields), safeViolations(item.Findings)
		if item.Effects != nil {
			effects := make([]ReviewEffect, len(item.Effects))
			for j, e := range item.Effects {
				e.Kind, e.From, e.To = termsafe.Line(e.Kind), termsafe.Line(e.From), termsafe.Line(e.To)
				e.Authority, e.Text, e.Severity = termsafe.Line(e.Authority), termsafe.Line(e.Text), termsafe.Line(e.Severity)
				effects[j] = e
			}
			item.Effects = effects
		}
		safe.Items[i] = item
	}
	if r.Parties != nil {
		safe.Parties = make([]ReviewParty, len(r.Parties))
	}
	for i, p := range r.Parties {
		p.Address, p.KeyType = termsafe.Line(p.Address), termsafe.Line(p.KeyType)
		if p.Chain != nil {
			chain := *p.Chain
			chain.Authorizer, chain.OtherSigner = termsafe.Line(chain.Authorizer), termsafe.Line(chain.OtherSigner)
			p.Chain = &chain
		}
		safe.Parties[i] = p
	}
	safe.Findings = safeViolations(r.Findings)
	if r.Chain != nil {
		chain := *r.Chain
		chain.Unavailable = termsafe.Line(chain.Unavailable)
		safe.Chain = &chain
	}
	return &safe
}
