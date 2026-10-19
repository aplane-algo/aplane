// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/chzyer/readline"
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

func TestIncentiveEligibilityUsesEmbeddedPromptAndPropagatesCancellation(t *testing.T) {
	for _, promptErr := range []error{context.Canceled, readline.ErrInterrupt, io.EOF} {
		t.Run(promptErr.Error(), func(t *testing.T) {
			var out bytes.Buffer
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := &REPLState{Out: &out, currentCommandCtx: ctx}
			session := &Session{state: state}
			prompted := false
			session.SetInteractiveLinePromptContext(func(gotCtx context.Context, prompt string) (string, error) {
				prompted = true
				if gotCtx != ctx {
					t.Fatal("prompt did not receive the command context")
				}
				if prompt != "Enable consensus incentive eligibility? (2 ALGO fee) [y/N]: " {
					t.Fatalf("unexpected prompt: %q", prompt)
				}
				return "", promptErr
			})

			// Cancellation must return before querying eligibility or submitting
			// a transaction; deliberately supply no application for either step.
			chargeFee, err := checkIncentiveEligibility(state, "ACCOUNT", false, true)
			if !prompted || !errors.Is(err, promptErr) || chargeFee {
				t.Fatalf("prompted=%v, chargeFee=%v, err=%v", prompted, chargeFee, err)
			}
			if out.Len() != 0 {
				t.Fatalf("prompt written to captured output instead of host UI: %q", out.String())
			}
		})
	}
}
