// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatepolicy

import "testing"

func TestRegistrationOutcomeZeroValue(t *testing.T) {
	var outcome RegistrationOutcome

	if outcome.ActivatedKeyTypes != nil {
		t.Fatalf("ActivatedKeyTypes = %#v, want nil", outcome.ActivatedKeyTypes)
	}
	if outcome.IdempotentKeyTypes != nil {
		t.Fatalf("IdempotentKeyTypes = %#v, want nil", outcome.IdempotentKeyTypes)
	}
	if outcome.ConflictingKeyTypes != nil {
		t.Fatalf("ConflictingKeyTypes = %#v, want nil", outcome.ConflictingKeyTypes)
	}
	if outcome.InvalidKeyTypes != nil {
		t.Fatalf("InvalidKeyTypes = %#v, want nil", outcome.InvalidKeyTypes)
	}
}

func TestRegistrationOutcomeCarriesIndependentCategories(t *testing.T) {
	outcome := RegistrationOutcome{
		ActivatedKeyTypes:   []string{"generic-v1"},
		IdempotentKeyTypes:  []string{"generic-v0"},
		ConflictingKeyTypes: []string{"generic-conflict"},
		InvalidKeyTypes:     []string{"generic-invalid"},
	}

	if got := outcome.ActivatedKeyTypes[0]; got != "generic-v1" {
		t.Fatalf("ActivatedKeyTypes[0] = %q", got)
	}
	if got := outcome.IdempotentKeyTypes[0]; got != "generic-v0" {
		t.Fatalf("IdempotentKeyTypes[0] = %q", got)
	}
	if got := outcome.ConflictingKeyTypes[0]; got != "generic-conflict" {
		t.Fatalf("ConflictingKeyTypes[0] = %q", got)
	}
	if got := outcome.InvalidKeyTypes[0]; got != "generic-invalid" {
		t.Fatalf("InvalidKeyTypes[0] = %q", got)
	}
}
