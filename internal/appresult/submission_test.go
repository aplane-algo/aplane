// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appresult

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common"

	"github.com/aplane-algo/aplane/internal/signing"
)

// failures reports submission failures without wrapping them, as a sweep's
// error does.
type failures struct{ list []*signing.SubmissionError }

func (f failures) Error() string                                  { return "all 2 transaction(s) failed" }
func (f failures) SubmissionFailures() []*signing.SubmissionError { return f.list }

// The outcomes come from every submission an error carries, through %w,
// through errors it joins and from a SubmissionFailures it wraps, in order;
// an error with none has none.
func TestSubmissionsFromError(t *testing.T) {
	first := &signing.SubmissionError{TxIDs: []string{"A"}, State: signing.SubmissionSubmitted, Err: fmt.Errorf("confirmation failed: %w", errors.New("wait for transaction id A timed out"))}
	second := &signing.SubmissionError{TxIDs: []string{"B", "C"}, State: signing.SubmissionUnknown, Err: errors.New("failed to submit transaction group: EOF")}
	third := &signing.SubmissionError{TxIDs: []string{"D"}, State: signing.SubmissionNotSent, Err: errors.New("failed to submit transaction: context canceled")}
	joined := fmt.Errorf("sweep() error: %w", errors.Join(fmt.Errorf("item 1: %w", first), errors.New("refused before signing"), second,
		fmt.Errorf("%w (reasons)", failures{list: []*signing.SubmissionError{third}})))

	got := SubmissionsFromError(joined)
	want := []Submission{
		{State: "submitted", Submitted: true, TxIDs: []string{"A"}, Error: "confirmation failed: wait for transaction id A timed out",
			Message: "Submitted: algod accepted transaction(s) A, and waiting for their confirmation ended with: wait for transaction id A timed out. Check these IDs on the network before retrying."},
		{State: "unknown", TxIDs: []string{"B", "C"}, Error: "failed to submit transaction group: EOF",
			Message: "Submission outcome unknown: the submit request for transaction(s) B, C got no answer from algod, so they may have been accepted. Check these IDs on the network before retrying."},
		{State: "not_sent", TxIDs: []string{"D"}, Error: "failed to submit transaction: context canceled",
			Message: "Not sent: the context had ended before the submit call for transaction(s) D was made, so nothing was sent."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SubmissionsFromError() = %+v, want %+v", got, want)
	}
	if one := SubmissionFromError(fmt.Errorf("wrapped: %w", second)); one == nil || !reflect.DeepEqual(*one, want[1]) {
		t.Fatalf("SubmissionFromError() = %+v", one)
	}
	for _, err := range []error{nil, errors.New("signer refused"), failures{}} {
		if got := SubmissionsFromError(err); got != nil || SubmissionFromError(err) != nil {
			t.Fatalf("SubmissionsFromError(%v) = %+v, want none", err, got)
		}
	}
}

// Each sentence says what happened and hands over what algod answered as it
// was given: an answer to the submit call other than 400 is named with its
// status, a pool error that ended the confirmation wait is quoted, and
// neither is read for what it means.
func TestSubmissionMessages(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure *signing.SubmissionError
		want    string
	}{
		{"answered with another status", &signing.SubmissionError{TxIDs: []string{"D"}, State: signing.SubmissionUnknown,
			Answer: &common.HTTPError{StatusCode: 503, Message: "{\"message\":\"node is catching up\"}\n"},
			Err:    errors.New("failed to submit transaction: HTTP 503: {\"message\":\"node is catching up\"}\n")},
			"Submission outcome unknown: algod answered the submit request for transaction(s) D with HTTP 503: {\"message\":\"node is catching up\"}. Check these IDs on the network before retrying."},
		{"a pool error ended the wait", &signing.SubmissionError{TxIDs: []string{"D", "E"}, State: signing.SubmissionSubmitted,
			Err: fmt.Errorf("confirmation failed: %w", errors.New("transaction rejected: overspend"))},
			"Submitted: algod accepted transaction(s) D, E, and waiting for their confirmation ended with: transaction rejected: overspend. Check these IDs on the network before retrying."},
		{"rejected", &signing.SubmissionError{TxIDs: []string{"D"}, State: signing.SubmissionRejected,
			Answer: &common.HTTPError{StatusCode: 400, Message: "overspend"}, Err: errors.New("x")},
			"algod answered the submit request for transaction(s) D with an error. Read the reason before retrying: a transaction already in the ledger is answered this way too."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SubmissionFromError(tc.failure)
			if got == nil || got.Message != tc.want || got.State != string(tc.failure.State) || got.Submitted != tc.failure.Submitted() {
				t.Fatalf("SubmissionFromError() = %+v, want message %q", got, tc.want)
			}
		})
	}
}
