// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import "github.com/aplane-algo/aplane/internal/termsafe"

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
