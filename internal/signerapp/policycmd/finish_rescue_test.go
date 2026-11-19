// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"errors"
	"testing"
)

// A rescue that committed, or may have, normalizes the store's ownership
// even when its command then fails, so a root-run rescue never leaves files
// the service user cannot read; one that committed nothing does not.
func TestFinishRescueNormalizesAfterACommitThatFailedLater(t *testing.T) {
	uncertain := errors.New("policy may have committed")
	for _, tc := range []struct {
		name       string
		runErr     error
		committed  bool
		normalized bool
	}{
		{"committed", nil, true, true},
		{"uncertain commit", uncertain, true, true},
		{"nothing committed", uncertain, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized := false
			err := finishRescue(tc.runErr, tc.committed, func() error { normalized = true; return nil })
			if normalized != tc.normalized || !errors.Is(err, tc.runErr) && tc.runErr != nil || (tc.runErr == nil && err != nil) {
				t.Fatalf("normalized=%v err=%v; want normalized=%v and the command's error", normalized, err, tc.normalized)
			}
		})
	}
}
