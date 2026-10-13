// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"
	"testing"
)

func TestCmdRotateRejectsBadUsage(t *testing.T) {
	r := &REPLState{}
	for _, args := range [][]string{
		{},
		{"vault", "later"},
		{"vault", "nowait", "extra"},
		{"status", "vault", "extra"},
		{"exit", "vault", "to", "bob"},
	} {
		if _, err := r.cmdRotate(args, nil); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("args %v: err = %v, want usage error", args, err)
		}
	}
}
