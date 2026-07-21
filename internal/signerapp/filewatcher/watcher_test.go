// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package filewatcher

import "testing"

func TestIsReloadCandidate(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"account.key", true},
		{"sentry.sen", true},
		{"policy.template", true},
		{"external.wit", false},
		{"external.wit.json", false},
		{"notes.json", false},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			if got := isReloadCandidate(test.path); got != test.want {
				t.Fatalf("isReloadCandidate(%q) = %v, want %v", test.path, got, test.want)
			}
		})
	}
}
