// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "testing"

func TestCommandRawArgs(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		raw     string
		wantRaw string
	}{
		{
			name:    "js preserves brace payload",
			cmd:     "js",
			raw:     `js { print("hi there") }`,
			wantRaw: `{ print("hi there") }`,
		},
		{
			name:    "jssave preserves quoted code payload",
			cmd:     "jssave",
			raw:     `jssave rebalance.js let msg = "hi there"`,
			wantRaw: `rebalance.js let msg = "hi there"`,
		},
		{
			name:    "missing args returns empty",
			cmd:     "jssave",
			raw:     `jssave`,
			wantRaw: ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := commandRawArgs(tt.cmd, tt.raw); got != tt.wantRaw {
				t.Fatalf("commandRawArgs(%q, %q) = %q, want %q", tt.cmd, tt.raw, got, tt.wantRaw)
			}
		})
	}
}
