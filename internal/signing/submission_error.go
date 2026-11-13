// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"errors"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"
)

// SubmissionState is how far a signed group got with algod when its
// submission, or the wait for its confirmation, failed.
type SubmissionState string

const (
	// SubmissionRejected: algod answered the submit call with HTTP 400. That
	// says the node answered, not that the network lacks the group: a group
	// already in the ledger is answered this way too, so the reason decides.
	SubmissionRejected SubmissionState = "rejected"
	// SubmissionNotSent: the context had ended before the submit call was
	// made, so nothing was sent.
	SubmissionNotSent SubmissionState = "not_sent"
	// SubmissionSubmitted: algod accepted the group, and the wait for its
	// confirmation then failed, so whether it confirmed was not seen.
	SubmissionSubmitted SubmissionState = "submitted"
	// SubmissionUnknown: the submit call ended without a 400 answer from
	// algod (no answer, a lost connection, another status, or the context
	// ending during the call), so whether algod has the group is not known.
	SubmissionUnknown SubmissionState = "unknown"
)

// SubmissionError reports a signed group whose submission or confirmation
// wait failed: the IDs of its signed transactions, in group order, and how
// far it got. Its text is Err's, so wrapping it changes no message. Callers
// above SubmitTransactionsWithContext wrap it with %w, and errors.As finds it
// in what any submitting command returns. It follows the SDK's
// SubmissionError, whose Submitted is State == SubmissionSubmitted.
type SubmissionError struct {
	TxIDs []string
	State SubmissionState
	Err   error
}

func (e *SubmissionError) Error() string {
	return e.Err.Error()
}

func (e *SubmissionError) Unwrap() error {
	return e.Err
}

// Submitted reports that algod accepted the group: the failure came after.
func (e *SubmissionError) Submitted() bool {
	return e.State == SubmissionSubmitted
}

func submissionFailure(txIDs []string, state SubmissionState, err error) error {
	return &SubmissionError{TxIDs: append([]string(nil), txIDs...), State: state, Err: err}
}

// submitCallState reads the submit call's error without interpreting algod's
// reason: a 400 is algod's answer; any other failure leaves it open whether
// algod has the group.
func submitCallState(err error) SubmissionState {
	var answered common.BadRequest
	if errors.As(err, &answered) {
		return SubmissionRejected
	}
	return SubmissionUnknown
}
