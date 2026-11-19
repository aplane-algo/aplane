// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/partkeyparse"
	"github.com/aplane-algo/aplane/internal/signing"
)

// A pasted registration that algod accepted, and whose confirmation wait
// then failed, may still confirm: the result names its transaction, and the
// error is a submitted SubmissionError for it, not the wait's error alone.
func TestKeyRegFromPartKeyKeepsTheRegistrationWhoseWaitFailed(t *testing.T) {
	f := newArgsFixture(t)
	f.signsFor = map[string]bool{argsNative: true} // the node accepts; its pending lookups fail

	result, err := f.app.KeyRegFromPartKey(context.Background(), &partkeyparse.ParsedInfo{
		ParentAddress: argsNative,
		VoteKey:       "tAtM0mBYE1p5k5KaHOvFYho09qEUEGWzaZs1dmBFWVQ=",
		SelectionKey:  "1+bzBrUVQDWDqcv4Iuv9uRYLp4DPViih4x2MGmKcYus=",
		StateProofKey: "eS1o+ZVYZDkHBgFqhHAdF8Slyb190C+9aopj85xyUDB7342Pn02Fz2sUP+zGYC697vAWnZFT5SKExOG/PB+asQ==",
		VoteFirst:     1, VoteLast: 2000, KeyDilution: 1733,
	}, false)

	if f.submitted.Load() != 1 {
		t.Fatalf("node accepted %d transaction(s), want the registration", f.submitted.Load())
	}
	var failure *signing.SubmissionError
	if !errors.As(err, &failure) || !failure.Submitted() {
		t.Fatalf("error = %v, want a submitted SubmissionError", err)
	}
	if result == nil || result.TxID == "" || result.Confirmed {
		t.Fatalf("result = %+v, want the unconfirmed registration with its transaction ID", result)
	}
	if !slices.Equal(failure.TxIDs, []string{result.TxID}) {
		t.Fatalf("error names %v, want the registration %s", failure.TxIDs, result.TxID)
	}
	if !strings.Contains(result.Output, result.TxID) || !strings.Contains(result.Output, "Waiting for confirmation") {
		t.Fatalf("output %q, want the submission and the wait", result.Output)
	}
	if !strings.HasPrefix(err.Error(), "key registration failed: confirmation failed: ") {
		t.Fatalf("error text = %q", err)
	}
}
