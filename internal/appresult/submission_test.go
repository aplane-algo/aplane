// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package appresult

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/aplane-algo/aplane/internal/signing"
)

// The outcomes come from every submission an error carries, through %w and
// through errors it joins, in order; an error with none has none.
func TestSubmissionsFromError(t *testing.T) {
	first := &signing.SubmissionError{TxIDs: []string{"A"}, State: signing.SubmissionSubmitted, Err: errors.New("confirmation failed: x")}
	second := &signing.SubmissionError{TxIDs: []string{"B", "C"}, State: signing.SubmissionUnknown, Err: errors.New("failed to submit transaction group: EOF")}
	joined := fmt.Errorf("sweep() error: %w", errors.Join(fmt.Errorf("item 1: %w", first), errors.New("refused before signing"), second))

	got := SubmissionsFromError(joined)
	want := []Submission{
		{State: "submitted", Submitted: true, TxIDs: []string{"A"}, Error: "confirmation failed: x",
			Message: "Submitted: algod accepted transaction(s) A, and their confirmation was not seen. Check these IDs on the network before retrying."},
		{State: "unknown", TxIDs: []string{"B", "C"}, Error: "failed to submit transaction group: EOF",
			Message: "Submission outcome unknown: the submit request for transaction(s) B, C got no answer from algod, so they may have been accepted. Check these IDs on the network before retrying."},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SubmissionsFromError() = %+v, want %+v", got, want)
	}
	if one := SubmissionFromError(fmt.Errorf("wrapped: %w", second)); one == nil || !reflect.DeepEqual(*one, want[1]) {
		t.Fatalf("SubmissionFromError() = %+v", one)
	}
	for state, want := range map[signing.SubmissionState]string{
		signing.SubmissionRejected: "algod answered the submit request for transaction(s) D with an error. Read the reason before retrying: a transaction already in the ledger is answered this way too.",
		signing.SubmissionNotSent:  "Not sent: the context had ended before the submit call for transaction(s) D was made, so nothing was sent.",
	} {
		one := SubmissionFromError(&signing.SubmissionError{TxIDs: []string{"D"}, State: state, Err: errors.New("x")})
		if one == nil || one.State != string(state) || one.Submitted || one.Message != want {
			t.Fatalf("SubmissionFromError(%s) = %+v, want message %q", state, one, want)
		}
	}
	for _, err := range []error{nil, errors.New("signer refused")} {
		if got := SubmissionsFromError(err); got != nil || SubmissionFromError(err) != nil {
			t.Fatalf("SubmissionsFromError(%v) = %+v, want none", err, got)
		}
	}
}
