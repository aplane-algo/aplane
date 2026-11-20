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

	"github.com/aplane-algo/aplane/internal/plugin/jsonrpc"
)

func TestConfirmUsesInteractiveLineReader(t *testing.T) {
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

	got, err := state.confirm("Delete key ADDR? [y/N]: ")
	if err != nil {
		t.Fatalf("confirm() error = %v", err)
	}
	if !got {
		t.Fatal("confirm() = false, want true for Y")
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

func TestConfirmUsesContextInteractiveLineReader(t *testing.T) {
	var out bytes.Buffer
	var prompts []string
	state := &REPLState{
		Out: &out,
		SetPrompt: func(p string) {
			prompts = append(prompts, p)
		},
		LineReaderContext: func(context.Context) (string, error) {
			return " yes ", nil
		},
	}

	got, err := state.confirm("Proceed? [y/N]: ")
	if err != nil {
		t.Fatalf("confirm() error = %v", err)
	}
	if !got {
		t.Fatal("confirm() = false, want true for yes")
	}
	if out.Len() != 0 {
		t.Fatalf("output = %q, context prompt should be routed through SetPrompt", out.String())
	}
	if len(prompts) != 2 || prompts[0] != "Proceed? [y/N]: " || prompts[1] != "" {
		t.Fatalf("prompts = %#v, want temporary prompt and restore", prompts)
	}
}

// yesNoSites are the [y/N] prompts of the shell, each reporting whether the
// user agreed.
func yesNoSites(t *testing.T) []struct {
	name string
	ask  func(r *REPLState) (bool, error)
} {
	reviewed := func(result *jsonrpc.ExecuteResult) func(r *REPLState) (bool, error) {
		return func(r *REPLState) (bool, error) {
			_, cancelled, err := reviewPluginTransactions(r, result, nil)
			return !cancelled, err
		}
	}
	return []struct {
		name string
		ask  func(r *REPLState) (bool, error)
	}{
		{"send lookalikes", func(r *REPLState) (bool, error) { return r.confirmLookalikes(nil) }},
		{"incentive eligibility", askIncentiveEligibility},
		{"host key", func(r *REPLState) (bool, error) { return buildHostKeyApproval(r)("host", "SHA256:x") }},
		{"plugin default draft", reviewed(&jsonrpc.ExecuteResult{
			RequiresApproval: true, Transactions: rawIntents(approvalTestPayment(1, 2, 1))})},
		{"plugin pregrouped signed", reviewed(pregroupedSignedResult(t))},
	}
}

// TestYesNoPromptsAcceptOnlyYOrYes pins the answer rule every [y/N] prompt
// shares: y or yes, in any case and with space around it. Anything else, an
// empty answer included, is no.
func TestYesNoPromptsAcceptOnlyYOrYes(t *testing.T) {
	answers := map[string]bool{
		"y": true, "Y": true, " yes ": true, "YES": true, "Yes\t": true,
		"": false, "n": false, "no": false, "ye": false, "yess": false, "y es": false, "ok": false,
	}
	for _, site := range yesNoSites(t) {
		for answer, want := range answers {
			t.Run(site.name+"/"+answer, func(t *testing.T) {
				var out bytes.Buffer
				state := &REPLState{Out: &out, LineReader: func() (string, error) { return answer, nil }}
				got, err := site.ask(state)
				if err != nil || got != want {
					t.Fatalf("answer %q: agreed = %v, %v; want %v", answer, got, err, want)
				}
			})
		}
	}
}

// TestYesNoPromptsReturnReadErrors pins that a failed read is an error, not
// an answer.
func TestYesNoPromptsReturnReadErrors(t *testing.T) {
	for _, site := range yesNoSites(t) {
		t.Run(site.name, func(t *testing.T) {
			var out bytes.Buffer
			state := &REPLState{Out: &out, LineReader: func() (string, error) { return "", io.ErrUnexpectedEOF }}
			if _, err := site.ask(state); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error = %v, want the read error", err)
			}
		})
	}
}

// TestPluginReviewDeclineSaysCancelled pins the line a declined plugin review
// prints.
func TestPluginReviewDeclineSaysCancelled(t *testing.T) {
	var out bytes.Buffer
	state := &REPLState{Out: &out, LineReader: func() (string, error) { return "n", nil }}
	_, cancelled, err := reviewPluginTransactions(state, pregroupedSignedResult(t), nil)
	if err != nil || !cancelled {
		t.Fatalf("review = %v, %v; want cancelled", cancelled, err)
	}
	if !strings.HasSuffix(out.String(), "\nTransaction cancelled by user\n") {
		t.Fatalf("output = %q, want it to end with the cancellation line", out.String())
	}
}

// TestSetupValuePrompts pins the two setup value readers: both trim, one
// refuses an empty answer, the other takes its default for one. Without an
// interactive reader the prompt is printed on a new line.
func TestSetupValuePrompts(t *testing.T) {
	read := func(answer string, interactive bool, ask func(r *REPLState) (string, error)) (string, string, []string, error) {
		var out bytes.Buffer
		var prompts []string
		state := &REPLState{Out: &out, SetPrompt: func(p string) { prompts = append(prompts, p) }}
		if interactive {
			state.LineReader = func() (string, error) { return answer, nil }
		} else {
			withStdin(t, answer+"\n")
		}
		got, err := ask(state)
		return got, out.String(), prompts, err
	}
	required := func(r *REPLState) (string, error) { return r.readRequiredSetupValue("URL: ") }
	withDefault := func(r *REPLState) (string, error) { return r.readSetupValueWithDefault("Name", "home") }

	if got, out, prompts, err := read(" ssh://h ", true, required); err != nil || got != "ssh://h" || out != "" ||
		len(prompts) != 2 || prompts[0] != "URL: " || prompts[1] != "" {
		t.Fatalf("required = %q, %q, %q, %v", got, out, prompts, err)
	}
	if _, _, _, err := read("  ", true, required); err == nil || err.Error() != "value is required" {
		t.Fatalf("required empty error = %v", err)
	}
	if got, out, prompts, err := read(" work ", true, withDefault); err != nil || got != "work" || out != "" ||
		len(prompts) != 2 || prompts[0] != "Name [home]: " {
		t.Fatalf("with default = %q, %q, %q, %v", got, out, prompts, err)
	}
	if got, _, _, err := read(" ", true, withDefault); err != nil || got != "home" {
		t.Fatalf("with default empty = %q, %v", got, err)
	}
	if got, out, _, err := read("x", false, required); err != nil || got != "x" || out != "\nURL: " {
		t.Fatalf("required from stdin = %q, %q, %v", got, out, err)
	}
	if got, out, _, err := read("", false, withDefault); err != nil || got != "home" || out != "\nName [home]: " {
		t.Fatalf("with default from stdin = %q, %q, %v", got, out, err)
	}
}
