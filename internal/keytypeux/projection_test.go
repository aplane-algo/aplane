// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypeux

import (
	"testing"

	"github.com/aplane-algo/aplane/internal/keys"
)

func TestAvailabilityForCreation(t *testing.T) {
	if got := AvailabilityForCreation(true); got != AvailableToCreate {
		t.Fatalf("AvailabilityForCreation(true) = %q, want %q", got, AvailableToCreate)
	}
	if got := AvailabilityForCreation(false); got != NotAvailableToCreate {
		t.Fatalf("AvailabilityForCreation(false) = %q, want %q", got, NotAvailableToCreate)
	}
}

func TestTemplateProvenanceLabel(t *testing.T) {
	tests := []struct {
		status string
		want   string
	}{
		{status: keys.TemplateProvenanceStatusConflict, want: TemplateMismatch},
		{status: keys.TemplateProvenanceStatusUnavailable, want: TemplateMismatch},
		{status: "", want: ""},
		{status: "ok", want: ""},
	}

	for _, tt := range tests {
		if got := TemplateProvenanceLabel(tt.status); got != tt.want {
			t.Fatalf("TemplateProvenanceLabel(%q) = %q, want %q", tt.status, got, tt.want)
		}
	}
}
