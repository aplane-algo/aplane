// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
	signeraudit "github.com/aplane-algo/aplane/internal/signerapp/audit"
	signerrest "github.com/aplane-algo/aplane/internal/signerapp/rest"
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

// signingRequest settles the ID a signing or planning request is handled
// under (signersigning.RequestID of the request_id it sent) and returns it
// with the REST service for the request: its audit entries are attributed to
// the connection that sent it and carry that ID as operation_id. The handler
// sets the ID on its request before calling the service, so the entries, the
// approval prompt, /sign/cancel and a response that returns an ID all carry
// the same value. It is the only way a handler gets a service whose entries
// name a request.
func (fs *Signer) signingRequest(r *http.Request, supplied string) (string, signerrest.Service) {
	requestID := signersigning.RequestID(supplied)
	attr := signingAuditAttributionFromRequest(r)
	attr.RequestID = requestID
	return requestID, fs.restServiceWithSigningAudit(fs.signingAuditLogger(attr))
}

// connectionService is the REST service for a call that is not a signing
// request (rotating prepare and recovery): its entries are attributed to the
// connection that sent it and name no request.
func (fs *Signer) connectionService(r *http.Request) signerrest.Service {
	return fs.restServiceWithSigningAudit(fs.signingAuditLogger(signingAuditAttributionFromRequest(r)))
}

// signingAuditAttributionFromRequest attributes entries to the connection
// that sent r.
func signingAuditAttributionFromRequest(r *http.Request) auditAttribution {
	attr := auditAttribution{
		Transport:  auditTransportHTTP,
		RemoteAddr: r.RemoteAddr,
	}
	ident := auth.IdentityFromContext(r.Context())
	if ident == nil {
		return attr
	}
	attr.RequesterPrincipal = ident.ID
	return attr
}

// signingAuditLogger writes signing entries attributed as attr, or is nil
// when the daemon has no audit log.
func (fs *Signer) signingAuditLogger(attr auditAttribution) signingAudit {
	if fs.auditLog == nil {
		return nil
	}
	return &signingAuditLogger{log: fs.auditLog, attribution: attr}
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
