// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// A non-atomic send in which every item failed fails as a command: the REPL
// draws each item and then returns the send's error, so a script stops, and
// MCP answers with an error result that lists each item's outcome. One send
// is no different from several.
func TestSendWhoseItemsAllFailedFailsTheCommand(t *testing.T) {
	for _, tc := range []struct {
		name  string
		to    func(f *submitFixture) string
		count int
	}{
		{"one", func(f *submitFixture) string { return f.b.Address.String() }, 1},
		{"two", func(f *submitFixture) string { return fmt.Sprintf("[%s %s]", f.b.Address, f.c.Address) }, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := fmt.Sprintf("all %d transaction(s) failed", tc.count)
			line := func(f *submitFixture) Command {
				cmd, err := parseShellCommand(fmt.Sprintf("send 0.001 algo from %s to %s", f.a.Address, tc.to(f)))
				if err != nil {
					t.Fatal(err)
				}
				return cmd
			}

			f := newSubmitFixture(t, nodeRefusesSubmit)
			var out bytes.Buffer
			f.state.SetOutput(&out)
			err := f.state.executeCommand(line(f))
			if err == nil || err.Error() != want {
				t.Fatalf("executeCommand() error = %v, want %q", err, want)
			}
			if got := strings.Count(out.String(), "✗ Failed:"); got != tc.count {
				t.Fatalf("the REPL drew %d failed item(s), want %d:\n%s", got, tc.count, out.String())
			}

			f = newSubmitFixture(t, nodeRefusesSubmit)
			text, structured := mcpErrorParts(t, mcpExecuteCommand(f.state, line(f)))
			if structured.Error != want || len(structured.Submissions) != tc.count {
				t.Fatalf("MCP error %q with %d submission(s), want %q with %d (text %q)", structured.Error, len(structured.Submissions), want, tc.count, text)
			}
		})
	}
}

// A send that went through is unchanged: no error, and MCP's result is the
// send's own.
func TestSendThatWentThroughSucceeds(t *testing.T) {
	f := newSubmitFixture(t, nodeConfirms)
	cmd, err := parseShellCommand(fmt.Sprintf("send 0.001 algo from %s to %s", f.a.Address, f.b.Address))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.state.executeCommand(cmd); err != nil {
		t.Fatalf("executeCommand() error = %v", err)
	}
	if result := mcpExecuteCommand(f.state, cmd); result.IsError {
		t.Fatalf("MCP result is an error: %q", mcpResultText(t, result))
	}
}

// A one-shot simulate draws its result as simulated. The mode it set is
// restored before the result is drawn, so the drawing must not ask for it.
func TestOneShotSimulateSendSaysItWasSimulated(t *testing.T) {
	f := newSubmitFixture(t, nodeConfirms)
	result, err := executeSimulate(f.state, []string{"send", "0.001", "algo", "from", f.a.Address.String(), "to", f.b.Address.String()})
	if err != nil {
		t.Fatalf("executeSimulate() error = %v", err)
	}
	if f.state.app().IsSimulateEnabled() {
		t.Fatal("one-shot simulate left simulate mode on")
	}
	var out bytes.Buffer
	if err := result.RenderText(&out); err != nil {
		t.Fatalf("RenderText() error = %v", err)
	}
	f.mu.Lock()
	submits, simulations := f.submits, f.simulations
	f.mu.Unlock()
	if submits != 0 || simulations != 1 {
		t.Fatalf("the node saw %d submit(s) and %d simulation(s), want 0 and 1", submits, simulations)
	}
	if strings.Contains(out.String(), "Transaction submitted") {
		t.Fatalf("a simulated send was drawn as submitted:\n%s", out.String())
	}
}
