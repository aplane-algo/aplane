// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"errors"
	"fmt"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
)

// Live policy and ASA set changes change what the node accepts, so each one
// needs an audit record before it runs. After authorization, the handler
// durably appends the request's intent; if the audit log is missing or the
// write fails, the change is refused and the service is never called. After
// the service returns, the handler appends exactly one outcome entry, best
// effort: a failure to write it is reported by the logger and never changes
// or repeats the change. Offline rescue and apstore are outside this: they
// run without the daemon and its audit log.

// ErrAuditUnavailable reports that the daemon has no audit log: it could not
// be opened at startup, and only a restart opens it again.
var ErrAuditUnavailable = errors.New("the daemon has no audit log")

type policyApplyAudit interface {
	LogPolicyApplyIntentDurableContext(SessionContext, string, adminproto.ApplyPolicyRequest) error
	LogPolicyApplyResultContext(SessionContext, string, adminproto.ApplyPolicyResult)
}

type asaSetAudit interface {
	LogASASetUpdateIntentDurableContext(SessionContext, string, string, string, string, uint64) error
	LogASASetAddResultContext(SessionContext, string, adminproto.AddASARequest, adminproto.AddASAResult)
	LogASASetRemoveResultContext(SessionContext, string, adminproto.RemoveASARequest, adminproto.RemoveASAResult)
}

// recordMutationIntent runs record, which durably appends a change's intent,
// and returns the code and message refusing the change when it cannot: no
// record (no audit log), ErrAuditUnavailable, or a failed write. what names
// the change; rescue adds the offline policy path to the advice.
func (s *Session) recordMutationIntent(what string, record func() error, rescue bool) (string, string) {
	var err error
	if record == nil {
		err = ErrAuditUnavailable
	} else {
		err = record()
	}
	if err == nil {
		return "", ""
	}
	alternative := ""
	if rescue {
		alternative = " To change policy without the daemon, stop it and use apadmin policy rescue, which needs free space for a new generation too."
	}
	if errors.Is(err, ErrAuditUnavailable) {
		return protocol.ResultCodeAuditUnavailable, fmt.Sprintf(
			"%s refused: the daemon has no audit log, because it could not be opened at startup (see the daemon log). Repair the audit log's storage or permissions, then restart the daemon; retrying the request alone cannot help.%s",
			what, alternative)
	}
	return protocol.ResultCodeAuditWriteFailed, fmt.Sprintf(
		"%s refused: the audit log could not record the request: %v. Repair the cause, such as a full disk or wrong permissions, and retry.%s",
		what, err, alternative)
}
