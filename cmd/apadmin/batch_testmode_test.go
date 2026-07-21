//go:build testmode

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "testing"

func TestFormatBatchKeyTypeProjectsTemplateProvenanceNote(t *testing.T) {
	got := formatBatchKeyType("test.timed-policy.v1", "unavailable")
	want := "test.timed-policy.v1 [template provenance]"
	if got != want {
		t.Fatalf("formatBatchKeyType() = %q, want %q", got, want)
	}
}
