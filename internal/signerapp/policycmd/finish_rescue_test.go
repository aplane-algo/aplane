// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"errors"
	"strings"
	"testing"
)

// A rescue normalizes the store's ownership on every outcome, so a root-run
// rescue never leaves files the service user cannot read: not after a
// commit, and not after a mint that failed once it had published its
// successor or sealed the current generation.
func TestFinishRescueNormalizesOnEveryOutcome(t *testing.T) {
	failed := errors.New("policy apply failed before commit")
	for _, tc := range []struct {
		name   string
		runErr error
	}{
		{"committed", nil},
		{"failed", failed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized := false
			err := finishRescue(tc.runErr, func() error { normalized = true; return nil })
			if !normalized || !errors.Is(err, tc.runErr) {
				t.Fatalf("normalized=%v err=%v; want normalized and the command's error", normalized, err)
			}
		})
	}
	err := finishRescue(failed, func() error { return errors.New("chown failed") })
	if !errors.Is(err, failed) || !strings.Contains(err.Error(), "managed store ownership normalization also failed: chown failed") {
		t.Fatalf("finishRescue() with both failing = %v, want both reported", err)
	}
}
