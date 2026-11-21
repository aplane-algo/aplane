// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

// Source token changes are audited as policy and ASA set changes are: a
// durable SOURCE_TOKEN_CHANGE_INTENT before the change runs, then one
// outcome, SOURCE_TOKEN_SET or SOURCE_TOKEN_REMOVED on success and
// SOURCE_TOKEN_CHANGE_FAILED otherwise. Entries name the policy selector and
// the source; no method here takes a token, so none can record one.

// LogSourceTokenChangeIntentDurableContext records a source_token_set or
// source_token_remove request before it runs. action is "set" or "remove".
func (a *AuditLogger) LogSourceTokenChangeIntentDurableContext(ctx adminserver.SessionContext, operationID, action, selector, source string) error {
	entry := sessionAuditFields(ctx)
	entry.Event = AuditSourceTokenChangeIntent
	entry.Outcome = "requested"
	entry.OperationID = operationID
	entry.SourceTokenAction, entry.PolicySelector, entry.ExternalSource = action, selector, source
	return a.logDurable(entry)
}

// LogSourceTokenChangeResultContext records what a source token change did.
func (a *AuditLogger) LogSourceTokenChangeResultContext(ctx adminserver.SessionContext, operationID, action, selector, source string, result adminproto.SourceTokenChangeResult) {
	entry := sessionAuditFields(ctx)
	entry.OperationID = operationID
	entry.SourceTokenAction, entry.PolicySelector, entry.ExternalSource = action, selector, source
	switch {
	case result.Success && action == "set":
		entry.Event, entry.Outcome = AuditSourceTokenSet, "succeeded"
	case result.Success:
		entry.Event, entry.Outcome = AuditSourceTokenRemoved, "succeeded"
	default:
		entry.Event, entry.Outcome = AuditSourceTokenChangeFailed, "failed"
		entry.ResultCode, entry.Reason = result.Code, boundText(result.Error, maxAuditReason)
	}
	a.Log(entry)
}
