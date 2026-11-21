// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// A cosigner's source tokens decide whether its external checks can run, so
// they take the authorization of a policy apply, policy.update, for reading
// as for changing, and a change is audited like one: see mutation_audit.go.
// None of them is open to an auth_only session. The token travels only in
// source_token_set, as a sensitive value the handler zeroes whatever
// happens; no result, audit entry or error carries it.

// sourceTokenResource names a selector's tokens for authorization.
func sourceTokenResource(selector string) auth.Resource {
	return auth.Resource{Type: "source_tokens", ID: selector}
}

// HandleSetSourceToken sets one source's token, and zeroes the token in msg
// whether or not the change runs.
func (s *Session) HandleSetSourceToken(msg *protocol.SourceTokenSetMessage) {
	defer msg.Token.Zero()
	s.changeSourceToken(msg.ID, protocol.MsgTypeSourceTokenSetResult, "set", msg.Selector, msg.Source,
		func() adminproto.SourceTokenChangeResult {
			return s.keyServices.SetSourceToken(adminproto.SetSourceTokenRequest{
				Selector: msg.Selector, Source: msg.Source, Token: msg.Token,
			})
		})
}

// HandleRemoveSourceToken removes one source's token.
func (s *Session) HandleRemoveSourceToken(msg *protocol.SourceTokenRemoveMessage) {
	s.changeSourceToken(msg.ID, protocol.MsgTypeSourceTokenRemoveResult, "remove", msg.Selector, msg.Source,
		func() adminproto.SourceTokenChangeResult {
			return s.keyServices.RemoveSourceToken(adminproto.RemoveSourceTokenRequest{
				Selector: msg.Selector, Source: msg.Source,
			})
		})
}

// changeSourceToken authorizes a token change, records its intent durably,
// runs it, records its outcome and answers with resultType.
func (s *Session) changeSourceToken(id, resultType, action, selector, source string, change func() adminproto.SourceTokenChangeResult) {
	if !s.authorize(id, auth.ActionPolicyUpdate, sourceTokenResource(selector)) {
		return
	}
	audit, _ := s.audit.(sourceTokenAudit)
	var record func() error
	if audit != nil {
		record = func() error {
			return audit.LogSourceTokenChangeIntentDurableContext(s.SessionContext(), id, action, selector, source)
		}
	}
	if code, refusal := s.recordMutationIntent("source token change", record, false); code != "" {
		_ = s.WriteJSON(ProtocolSourceTokenChangeResultMessage(id, resultType, adminproto.SourceTokenChangeResult{
			Selector: selector, Source: source, Code: code, Error: refusal,
		}))
		return
	}
	result := change()
	audit.LogSourceTokenChangeResultContext(s.SessionContext(), id, action, selector, source, result)
	_ = s.WriteJSON(ProtocolSourceTokenChangeResultMessage(id, resultType, result))
}

// HandleListSourceTokens lists token names, set times and states.
func (s *Session) HandleListSourceTokens(msg *protocol.SourceTokenListMessage) {
	if !s.authorize(msg.ID, auth.ActionPolicyUpdate, sourceTokenResource(msg.Selector)) {
		return
	}
	result := s.keyServices.ListSourceTokens(adminproto.ListSourceTokensRequest{Selector: msg.Selector})
	_ = s.WriteJSON(ProtocolSourceTokenListResultMessage(msg.ID, result))
}

// ProtocolSourceTokenChangeResultMessage projects a token change's result
// onto the wire as resultType.
func ProtocolSourceTokenChangeResultMessage(id, resultType string, result adminproto.SourceTokenChangeResult) protocol.SourceTokenChangeResultMessage {
	return protocol.SourceTokenChangeResultMessage{
		BaseMessage: protocol.BaseMessage{Type: resultType, ID: id},
		Success:     result.Success,
		Selector:    result.Selector,
		Source:      result.Source,
		Tokens:      protocolSourceTokens(result.Tokens),
		Code:        result.Code,
		Error:       result.Error,
	}
}

// ProtocolSourceTokenListResultMessage projects a token listing onto the
// wire.
func ProtocolSourceTokenListResultMessage(id string, result adminproto.ListSourceTokensResult) protocol.SourceTokenListResultMessage {
	msg := protocol.SourceTokenListResultMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSourceTokenListResult, ID: id},
		Success:     result.Success,
		Selectors:   make([]protocol.SourceTokenSelector, 0, len(result.Selectors)),
		Omitted:     result.Omitted,
		Code:        result.Code,
		Error:       result.Error,
	}
	for _, listing := range result.Selectors {
		msg.Selectors = append(msg.Selectors, protocol.SourceTokenSelector{
			Selector: listing.Selector,
			Policy:   listing.Policy,
			Sources:  listing.Sources,
			Tokens:   protocolSourceTokens(listing.Tokens),
		})
	}
	return msg
}

func protocolSourceTokens(tokens []adminproto.SourceTokenInfo) []protocol.SourceTokenInfo {
	out := make([]protocol.SourceTokenInfo, 0, len(tokens))
	for _, token := range tokens {
		info := protocol.SourceTokenInfo{Source: token.Source, State: token.State}
		if !token.SetAt.IsZero() {
			info.SetAt = token.SetAt.UTC().Format(time.RFC3339)
		}
		out = append(out, info)
	}
	return out
}
