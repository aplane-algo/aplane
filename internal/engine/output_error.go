// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package engine

type submissionOutputError struct {
	err    error
	output string
}

func (e *submissionOutputError) Error() string {
	return e.err.Error()
}

func (e *submissionOutputError) Unwrap() error {
	return e.err
}

func (e *submissionOutputError) SubmissionOutput() string {
	return e.output
}

func errorWithSubmissionOutput(err error, output string) error {
	if err == nil || output == "" {
		return err
	}
	return &submissionOutputError{err: err, output: output}
}
