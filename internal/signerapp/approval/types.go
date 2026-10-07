// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package approval

import "github.com/aplane-algo/aplane/internal/protocol"

// Cancellation reasons are wire values owned by internal/protocol; the
// aliases keep this package's API stable for coordinator callers.
const (
	SignRequestCancelReasonClientCanceled = protocol.SignRequestCancelReasonClientCanceled
	SignRequestCancelReasonTimeout        = protocol.SignRequestCancelReasonTimeout
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
)

// Violation describes a warning or critical condition shown during approval.
type Violation struct {
	Field    string
	Value    string
	Severity ViolationSeverity
	Message  string
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
}

// ClientEnrollmentRequest is the domain-level approval request for enrolling
// a client key.
type ClientEnrollmentRequest struct {
	ID             string
	SSHFingerprint string
	Label          string
	RemoteAddr     string
	Timestamp      int64
}

// ClientEnrollmentCanceled withdraws a delivered client enrollment request
// from the approval client.
type ClientEnrollmentCanceled struct {
	ID     string
	Reason string
}

// ClientEnrollmentCancelReasonPreempted means a signing request took the
// approval turn from the client enrollment request.
const ClientEnrollmentCancelReasonPreempted = protocol.ClientEnrollmentCancelReasonPreempted

// ClientEnrollmentResponse is the domain-level approval response for client enrollment.
type ClientEnrollmentResponse struct {
	ID       string
	Approved bool
	Reason   string
}
