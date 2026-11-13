// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appresult

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/signing"
)

// Submission is the machine projection of a failed submission, read from the
// *signing.SubmissionError an error carries: how far the signed group got
// with algod, the IDs of its transactions, the failure's own text, and a
// sentence saying what that means for the caller. It names transaction IDs
// only, never what the transactions hold.
type Submission struct {
	// State is "submitted" (algod accepted them; confirmation was not seen),
	// "unknown" (the submit call got no answer, so they may have been
	// accepted), "rejected" (algod answered the submit call with HTTP 400,
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

// SubmissionsFromError returns, in order, the outcome of every submission err
// carries through its wrapping, including the errors it joins: one for a
// command's own submission, one for each failed item of a sweep. None means
// that no transaction of err's reached algod's submit call.
func SubmissionsFromError(err error) []Submission {
	var out []Submission
	collectSubmissions(err, &out)
	return out
}

// SubmissionFromError returns the outcome err carries, nil when it carries
// none. It is for one item's error.
func SubmissionFromError(err error) *Submission {
	submissions := SubmissionsFromError(err)
	if len(submissions) == 0 {
		return nil
	}
	return &submissions[0]
}

func collectSubmissions(err error, out *[]Submission) {
	switch e := err.(type) {
	case nil:
	case *signing.SubmissionError:
		*out = append(*out, submissionOf(e))
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
		message = fmt.Sprintf("Submitted: algod accepted transaction(s) %s, and their confirmation was not seen. Check these IDs on the network before retrying.", ids)
	case signing.SubmissionRejected:
		message = fmt.Sprintf("algod answered the submit request for transaction(s) %s with an error. Read the reason before retrying: a transaction already in the ledger is answered this way too.", ids)
	case signing.SubmissionNotSent:
		message = fmt.Sprintf("Not sent: the context had ended before the submit call for transaction(s) %s was made, so nothing was sent.", ids)
	default:
		message = fmt.Sprintf("Submission outcome unknown: the submit request for transaction(s) %s got no answer from algod, so they may have been accepted. Check these IDs on the network before retrying.", ids)
	}
	return Submission{
		State:     string(failure.State),
		Submitted: failure.Submitted(),
		TxIDs:     append([]string{}, failure.TxIDs...),
		Error:     failure.Err.Error(),
		Message:   message,
	}
}
