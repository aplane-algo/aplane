// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"net/http"

	"github.com/aplane-algo/aplane/internal/auth"
	signerapproval "github.com/aplane-algo/aplane/internal/signerapp/approval"
)

const auditTransportHTTP = "http"

type signingAuditLogger struct {
	log         *AuditLogger
	attribution auditAttribution
}

var _ signingAudit = (*signingAuditLogger)(nil)

func signingAuditAttributionFromRequest(r *http.Request) auditAttribution {
	attr := auditAttribution{
		Transport:  auditTransportHTTP,
		RemoteAddr: r.RemoteAddr,
	}
	ident := auth.IdentityFromContext(r.Context())
	if ident == nil {
		return attr
	}
	attr.TargetIdentityID = ident.ID
	attr.RequesterPrincipal = ident.ID
	return attr
}

func (fs *Signer) signingAuditLogger(r *http.Request) signingAudit {
	if fs.auditLog == nil {
		return nil
	}
	return &signingAuditLogger{
		log:         fs.auditLog,
		attribution: signingAuditAttributionFromRequest(r),
	}
}

func (l *signingAuditLogger) LogSignRequest(identityID, authAddress, txnSender, txnType, details string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignRequestAttributed(l.attribution, identityID, authAddress, txnSender, txnType, details)
}

func (l *signingAuditLogger) LogSignApproved(identityID, authAddress, txnSender, details string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignApprovedAttributed(l.attribution, identityID, authAddress, txnSender, details)
}

func (l *signingAuditLogger) LogSignApprovedWithPolicyRule(identityID, authAddress, txnSender, details, policyRuleID string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignApprovedAttributedWithPolicyRule(l.attribution, identityID, authAddress, txnSender, details, policyRuleID)
}

func (l *signingAuditLogger) LogSignRejected(identityID, authAddress, txnSender, reason string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignRejectedAttributed(l.attribution, identityID, authAddress, txnSender, reason)
}

func (l *signingAuditLogger) LogSignRejectedWithPolicyRule(identityID, authAddress, txnSender, reason, policyRuleID string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignRejectedAttributedWithPolicyRule(l.attribution, identityID, authAddress, txnSender, reason, policyRuleID)
}

func (l *signingAuditLogger) LogSignFailed(identityID, authAddress, txnSender, reason string) {
	if l == nil || l.log == nil {
		return
	}
	l.log.LogSignFailedAttributed(l.attribution, identityID, authAddress, txnSender, reason)
}

func (l *signingAuditLogger) RecordApprovalResponse(response signerapproval.SignResponse) {
	if l == nil || response.ApproverPrincipal == "" {
		return
	}
	l.attribution.ApproverPrincipal = response.ApproverPrincipal
}
