// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"testing"
)

func TestReadPromptResponseUsesInteractiveLineReader(t *testing.T) {
	var out bytes.Buffer
	var prompts []string
	state := &REPLState{
		Out: &out,
		SetPrompt: func(p string) {
			prompts = append(prompts, p)
		},
		LineReader: func() (string, error) {
			return " Y ", nil
		},
	}

	got, err := state.readPromptResponse("Delete key ADDR? [y/N]: ")
	if err != nil {
		t.Fatalf("readPromptResponse() error = %v", err)
	}
	if got != "y" {
		t.Fatalf("readPromptResponse() = %q, want y", got)
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, prompt should be routed through SetPrompt", out.String())
	}
	if len(prompts) != 2 {
		t.Fatalf("prompts = %#v, want temporary prompt and restore", prompts)
	}
	if prompts[0] != "Delete key ADDR? [y/N]: " {
		t.Fatalf("first prompt = %q, want delete prompt", prompts[0])
	}
	if prompts[1] != "" {
		t.Fatalf("restored prompt = %q, want empty prompt for test fixture", prompts[1])
	}
}
