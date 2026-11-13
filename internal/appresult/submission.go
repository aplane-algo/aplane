// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appresult

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/signing"
)

// Submission is the machine projection of a failed submission, read from the
// *signing.SubmissionError an error carries: how far the signed group got
// with algod, the IDs of its transactions, the failure's own text, and a
// sentence saying what happened. It names transaction IDs only, never what
// the transactions hold.
type Submission struct {
	// State is "submitted" (algod accepted them; the wait for their
	// confirmation then ended with an error), "unknown" (the submit call got
	// no answer, or an answer other than HTTP 400, so whether algod has them
	// is not known), "rejected" (algod answered the submit call with HTTP 400,
	// which a transaction already in the ledger also gets: the reason
	// decides) or "not_sent" (the context ended before the submit call).
	State string `json:"state"`
	// Submitted is true for "submitted" only, as the SDK's is: false does not
	// say the network lacks them unless State is "not_sent".
	Submitted bool     `json:"submitted"`
	TxIDs     []string `json:"txids"`
	Error     string   `json:"error"`
	Message   string   `json:"message"`
}

// SubmissionFailures is an error that reports submission failures without
// wrapping them: a command's failure as a whole, whose items failed each in
// their own way. errors.Is and errors.As reach nothing through it, so an
// item's sentinel or submission output does not describe the whole.
type SubmissionFailures interface {
	error
	SubmissionFailures() []*signing.SubmissionError
}

// SubmissionsFromError returns, in order, the outcome of every submission err
// carries through its wrapping, including the errors it joins and those a
// SubmissionFailures reports: one for a command's own submission, one for
// each failed item of a sweep. None means that no transaction of err's
// reached algod's submit call.
func SubmissionsFromError(err error) []Submission {
	var out []Submission
	collectSubmissions(err, &out)
	return out
}

// SubmissionFromError returns the outcome of the submission one item's error
// carries, nil when it carries none.
func SubmissionFromError(err error) *Submission {
	var failure *signing.SubmissionError
	if !errors.As(err, &failure) {
		return nil
	}
	submission := submissionOf(failure)
	return &submission
}

func collectSubmissions(err error, out *[]Submission) {
	switch e := err.(type) {
	case nil:
	case *signing.SubmissionError:
		*out = append(*out, submissionOf(e))
	case SubmissionFailures:
		for _, failure := range e.SubmissionFailures() {
			*out = append(*out, submissionOf(failure))
		}
	case interface{ Unwrap() []error }:
		for _, inner := range e.Unwrap() {
			collectSubmissions(inner, out)
		}
	case interface{ Unwrap() error }:
		collectSubmissions(e.Unwrap(), out)
	}
}

func submissionOf(failure *signing.SubmissionError) Submission {
	ids := strings.Join(failure.TxIDs, ", ")
	var message string
	switch failure.State {
	case signing.SubmissionSubmitted:
		waitErr := failure.Err
		if inner := errors.Unwrap(waitErr); inner != nil {
			waitErr = inner
		}
		message = fmt.Sprintf("Submitted: algod accepted transaction(s) %s, and waiting for their confirmation ended with: %s. Check these IDs on the network before retrying.",
			ids, strings.TrimSpace(waitErr.Error()))
	case signing.SubmissionRejected:
		message = fmt.Sprintf("algod answered the submit request for transaction(s) %s with an error. Read the reason before retrying: a transaction already in the ledger is answered this way too.", ids)
	case signing.SubmissionNotSent:
		message = fmt.Sprintf("Not sent: the context had ended before the submit call for transaction(s) %s was made, so nothing was sent.", ids)
	default:
		if answer := failure.Answer; answer != nil {
			message = fmt.Sprintf("Submission outcome unknown: algod answered the submit request for transaction(s) %s with HTTP %d: %s. Check these IDs on the network before retrying.",
				ids, answer.StatusCode, strings.TrimSpace(answer.Message))
		} else {
			message = fmt.Sprintf("Submission outcome unknown: the submit request for transaction(s) %s got no answer from algod, so they may have been accepted. Check these IDs on the network before retrying.", ids)
		}
	}
	return Submission{
		State:     string(failure.State),
		Submitted: failure.Submitted(),
		TxIDs:     append([]string{}, failure.TxIDs...),
		Error:     failure.Err.Error(),
		Message:   message,
	}
}
