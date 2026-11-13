// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"
	"testing"
)

// A word after the file other than nowait is refused before the file is read.
// The zero REPLState has no app, so reaching the workflow would panic.
func TestSignRefusesWordsItWouldIgnore(t *testing.T) {
	for _, word := range []string{"arg:preimage=text:open", "fee=2000", "note=hi", "wait", "NOWAIT"} {
		t.Run(word, func(t *testing.T) {
			for _, args := range [][]string{
				{"txn.json", word},
				{"txn.json", "nowait", word},
				{"txn.json", word, "nowait"},
			} {
				_, err := (&REPLState{}).runSign(args)
				if err == nil {
					t.Fatalf("runSign(%q) accepted %q", args, word)
				}
				if !strings.Contains(err.Error(), word) || !strings.Contains(err.Error(), "nowait") {
					t.Fatalf("runSign(%q) error = %q, want it to name %q and nowait", args, err, word)
				}
			}
		})
	}
}
