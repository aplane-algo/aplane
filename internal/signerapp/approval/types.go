// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import (
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/txnreview"
)

// Cancellation reasons are wire values owned by internal/protocol; the
// aliases keep this package's API stable for coordinator callers.
const (
	SignRequestCancelReasonClientCanceled = protocol.SignRequestCancelReasonClientCanceled
	SignRequestCancelReasonTimeout        = protocol.SignRequestCancelReasonTimeout
	SignRequestCancelReasonSessionEnded   = protocol.SignRequestCancelReasonSessionEnded

	SignRequestCancelReasonApproverDisconnected = protocol.SignRequestCancelReasonApproverDisconnected
	SignRequestCancelReasonApproverDisplaced    = protocol.SignRequestCancelReasonApproverDisplaced
)

// SignRequestCancelState describes the result of a sign-request cancellation.
type SignRequestCancelState string

const (
	SignRequestCancelStateCanceled SignRequestCancelState = "canceled"
	SignRequestCancelStateNotFound SignRequestCancelState = "not_found"
)

// SignRequestCancelResult is returned by the sign-request lifecycle manager.
type SignRequestCancelResult struct {
	State SignRequestCancelState
}

// ViolationSeverity is the approval-warning severity shown to operators.
type ViolationSeverity string

const (
	ViolationSeverityWarning  ViolationSeverity = "warning"
	ViolationSeverityCritical ViolationSeverity = "critical"
	// ViolationSeverityNotice is a finding shown without alarm: a rekey to an
	// account this signer holds a valid aplane key for. Anything that counts
	// warnings counts it; only the display differs.
	ViolationSeverityNotice ViolationSeverity = "notice"
)

// Violation describes a warning or critical condition shown during approval.
type Violation struct {
	Field    string
	Value    string
	Severity ViolationSeverity
	Message  string
}

// ViolationFor is a review finding as a prompt's warning.
func ViolationFor(finding txnreview.Finding) Violation {
	return Violation{Field: finding.Field, Value: finding.Value, Severity: ViolationSeverity(finding.Level()), Message: finding.Message}
}

// SignRequest is the domain-level approval request for transaction signing.
type SignRequest struct {
	ID          string
	Address     string
	TxnSender   string
	Description string
	Timestamp   int64
	FirstValid  uint64
	LastValid   uint64
	Violations  []Violation
	// Review is the request as data, or nil when the caller built only text.
	Review *txnreview.Review
}

// Prompt is what a caller asks the operator to approve.
type Prompt struct {
	RequestID   string
	Address     string
	TxnSender   string
	Description string
	FirstValid  uint64
	LastValid   uint64
	Violations  []Violation
	// Review is the request as data, or nil when the caller built only text.
	Review *txnreview.Review
}

// SignRequestCanceled reports that a previously delivered signing request is no
// longer actionable.
type SignRequestCanceled struct {
	ID     string
	Reason string
}

// SignResponse is the domain-level approval response for transaction signing.
type SignResponse struct {
	ID                string
	Approved          bool
	Reason            string
	ApproverPrincipal string
	// withdrawn marks a response the coordinator sent to end the request
	// (a cancellation), as opposed to an operator's answer; only this
	// package can set it.
	withdrawn bool
}

// ClientEnrollmentRequest tells the operator that a client's enrollment
// request is waiting in the queue.
type ClientEnrollmentRequest struct {
	ID             string
	SSHFingerprint string
	Label          string
	RemoteAddr     string
	Timestamp      int64
}
