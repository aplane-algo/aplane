// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"errors"
	"net/http"

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
	// confirmation then ended with an error.
	SubmissionSubmitted SubmissionState = "submitted"
	// SubmissionUnknown: the submit call ended without a 400 answer from
	// algod: with no HTTP answer (a lost connection, a timeout, the context
	// ending during the call) or with another HTTP status (Answer). Whether
	// algod has the group is not known.
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
	// Answer is algod's HTTP answer to the submit call, its status and its
	// message as algod gave them, when the call got one. It is nil when the
	// call got no HTTP answer, and when the failure came before the call or
	// after algod accepted the group.
	Answer *common.HTTPError
	// Err is the failure. For SubmissionSubmitted it is "confirmation
	// failed: " wrapping the confirmation wait's own error.
	Err error
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

func submissionFailure(txIDs []string, state SubmissionState, answer *common.HTTPError, err error) error {
	return &SubmissionError{TxIDs: append([]string(nil), txIDs...), State: state, Answer: answer, Err: err}
}

// algodAnswer returns the HTTP answer algod gave a call that failed, nil when
// err holds none: the call got no HTTP answer.
func algodAnswer(err error) *common.HTTPError {
	var (
		badRequest   common.BadRequest
		invalidToken common.InvalidToken
		notFound     common.NotFound
		internal     common.InternalError
		other        common.HTTPError
	)
	switch {
	case errors.As(err, &badRequest):
		return &badRequest.HTTPError
	case errors.As(err, &invalidToken):
		return &invalidToken.HTTPError
	case errors.As(err, &notFound):
		return &notFound.HTTPError
	case errors.As(err, &internal):
		return &internal.HTTPError
	case errors.As(err, &other):
		return &other
	}
	return nil
}

// submitCallState reads the submit call's answer without interpreting
// algod's reason: a 400 is algod's answer; anything else leaves it open
// whether algod has the group.
func submitCallState(answer *common.HTTPError) SubmissionState {
	if answer != nil && answer.StatusCode == http.StatusBadRequest {
		return SubmissionRejected
	}
	return SubmissionUnknown
}
