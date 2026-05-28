// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"errors"

	"github.com/aplane-algo/aplane/internal/apshellapp"
)

type submissionOutputCarrier interface {
	SubmissionOutput() string
}

func (r *REPLState) renderWarnings(warnings []apshellapp.Warning) {
	for _, warning := range warnings {
		r.printf("⚠️  Warning: %s\n", warning.Message)
	}
}

func (r *REPLState) renderSubmissionOutput(output string) {
	if output != "" {
		r.print(output)
	}
}

func (r *REPLState) renderErrorSubmissionOutput(err error) {
	var carrier submissionOutputCarrier
	if errors.As(err, &carrier) {
		r.renderSubmissionOutput(carrier.SubmissionOutput())
	}
}
