// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	signersigning "github.com/aplane-algo/aplane/internal/signerapp/signing"
)

const auditTransportHTTP = "http"

type signingAuditLogger struct {
	log         *AuditLogger
	attribution auditAttribution
}

var _ signingAudit = (*signingAuditLogger)(nil)
var _ signersigning.AuditCosignerRejectLogger = (*signingAuditLogger)(nil)
var _ signersigning.AuditRotatingReleaseLogger = (*signingAuditLogger)(nil)
var _ signersigning.AuditRotatingRecoveryLogger = (*signingAuditLogger)(nil)
var _ signersigning.AuditWithheldLogger = (*signingAuditLogger)(nil)

// signingRequestID is the ID that ties together what one signing or
// planning request does: the request_id it carried or, for a request sent
// without one, an ID the signer mints for it, req- and the time in
// nanoseconds. Each handler settles it once, before anything is logged, and
// sets it on the request, so the audit operation_id, the approval prompt,
// /sign/cancel and a response that returns an ID all carry the same value.
func signingRequestID(supplied string) string {
	if supplied != "" {
		return supplied
	}
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}

// signingAuditAttributionFromRequest attributes a signing request's entries
// to the connection that sent it, and ties them together by the request's
// ID (signingRequestID).
func signingAuditAttributionFromRequest(r *http.Request, requestID string) auditAttribution {
	attr := auditAttribution{
		Transport:  auditTransportHTTP,
		RemoteAddr: r.RemoteAddr,
		RequestID:  requestID,
	}
	ident := auth.IdentityFromContext(r.Context())
	if ident == nil {
		return attr
	}
	attr.RequesterPrincipal = ident.ID
	return attr
}

func (fs *Signer) signingAuditLogger(r *http.Request, requestID string) signingAudit {
	if fs.auditLog == nil {
		return nil
	}
	return &signingAuditLogger{
		log:         fs.auditLog,
		attribution: signingAuditAttributionFromRequest(r, requestID),
	}
}

// LogRequest records one slot of a request as it arrived: a SIGN_REQUEST,
// or a PLAN_REQUEST for /plan.
func (l *signingAuditLogger) LogRequest(kind signersigning.RequestKind, authAddress, txnSender, txnType, details string) {
	if l == nil || l.log == nil {
		return
	}
	if kind == signersigning.RequestToPlan {
		l.log.LogPlanRequestAttributed(l.attribution, authAddress, txnSender, txnType, details)
		return
	}
	l.log.LogSignRequestAttributed(l.attribution, authAddress, txnSender, txnType, details)
}

func (l *signingAuditLogger) LogSignApproved(record signersigning.SignedRecord) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignApprovedAttributed(l.attribution, signeraudit.SignApproval{
		TxnAuth:      record.AuthAddress,
		TxnSender:    record.TxnSender,
		TxnDetails:   record.Details,
		PolicyRuleID: record.PolicyRuleID,
		TxID:         record.TxID,
		Fee:          record.Fee,
		GroupID:      record.GroupID,
		GroupTxIDs:   record.GroupTxIDs,
		DummyCount:   record.DummyCount,
	})
}

func (l *signingAuditLogger) LogSignRejected(authAddress, txnSender, reason string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignRejectedAttributed(l.attribution, authAddress, txnSender, reason)
}

func (l *signingAuditLogger) LogSignRejectedWithPolicyRule(authAddress, txnSender, reason, policyRuleID string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignRejectedAttributedWithPolicyRule(l.attribution, authAddress, txnSender, reason, policyRuleID)
}

func (l *signingAuditLogger) LogCosignerComponentRejected(witnessKeyID, txnSender, reason, policyRuleID string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogCosignerComponentRejectedAttributed(l.attribution, witnessKeyID, txnSender, reason, policyRuleID)
}

func (l *signingAuditLogger) LogSignFailed(authAddress, txnSender, reason string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignFailedAttributed(l.attribution, authAddress, txnSender, reason)
}

// LogSignWithheld records a signature already recorded as signed that never
// left the signer, under its SIGN_APPROVED's txid and group_id.
func (l *signingAuditLogger) LogSignWithheld(record signersigning.SignedRecord, reason string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignWithheldAttributed(l.attribution, record.AuthAddress, record.TxnSender, record.TxID, record.GroupID, reason)
}

// LogRotatingRelease records a rotating release durably before the
// signature leaves the signer.
func (l *signingAuditLogger) LogRotatingRelease(account, txid string, stage, lastValid, tree uint64, index uint32) error {
	if l == nil || l.log == nil {
		return nil
	}
	return l.log.LogRotatingReleaseAttributed(l.attribution, account, txid, stage, lastValid, tree, index)
}

// LogRotatingRecovery records an operator's recovery request.
func (l *signingAuditLogger) LogRotatingRecovery(_ context.Context, account, action string, grantID uint64, detail string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogRotatingRecoveryAttributed(l.attribution, account, action, grantID, detail)
}

func (l *signingAuditLogger) RecordApprovalResponse(response signerapproval.SignResponse) {
	if l == nil || response.ApproverPrincipal == "" {
		return
	}
	l.attribution.ApproverPrincipal = response.ApproverPrincipal
}
