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
		violations := make([]PolicyViolation, len(m.Violations))
		for i, v := range m.Violations {
			v.Field = termsafe.Line(v.Field)
			v.Value = termsafe.Line(v.Value)
			v.Severity = termsafe.Line(v.Severity)
			v.Message = termsafe.Lines(v.Message)
			violations[i] = v
		}
		m.Violations = violations
	}
	return m
}
