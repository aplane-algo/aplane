// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestKeyRegPasteModeUsesContextInteractiveLineReader(t *testing.T) {
	reads := 0
	state := &REPLState{
		Out: &bytes.Buffer{},
		LineReaderContext: func(context.Context) (string, error) {
			reads++
			return "", nil
		},
	}

	err := state.keyRegPasteMode()
	if err == nil || !strings.Contains(err.Error(), "no input provided") {
		t.Fatalf("keyRegPasteMode() error = %v, want no input", err)
	}
	if reads != 2 {
		t.Fatalf("context reader calls = %d, want 2", reads)
	}
}
