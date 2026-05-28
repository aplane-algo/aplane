// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

import (
	"errors"
	"testing"
)

type testSubmissionOutputCarrier interface {
	SubmissionOutput() string
}

func TestErrorWithSubmissionOutputWrapsAndPreservesErrorSemantics(t *testing.T) {
	sentinel := errors.New("submit failed")

	err := errorWithSubmissionOutput(sentinel, "simulation diagnostics\n")
	if err == nil {
		t.Fatal("expected wrapped error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("errors.Is(wrapped, sentinel) = false")
	}

	var wrapper *submissionOutputError
	if !errors.As(err, &wrapper) {
		t.Fatalf("errors.As(wrapped, *submissionOutputError) = false")
	}
	if got := wrapper.SubmissionOutput(); got != "simulation diagnostics\n" {
		t.Fatalf("SubmissionOutput() = %q, want diagnostics", got)
	}

	var carrier testSubmissionOutputCarrier
	if !errors.As(err, &carrier) {
		t.Fatalf("errors.As(wrapped, submission output carrier) = false")
	}
	if got := carrier.SubmissionOutput(); got != "simulation diagnostics\n" {
		t.Fatalf("carrier SubmissionOutput() = %q, want diagnostics", got)
	}
}

func TestErrorWithSubmissionOutputNoopsForNilOrEmptyOutput(t *testing.T) {
	if got := errorWithSubmissionOutput(nil, "diagnostics"); got != nil {
		t.Fatalf("nil error wrapped as %v", got)
	}

	sentinel := errors.New("submit failed")
	if got := errorWithSubmissionOutput(sentinel, ""); got != sentinel {
		t.Fatalf("empty output returned %v, want original sentinel", got)
	}
}
