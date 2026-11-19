// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
)

// scriptShell is a shell with its plugin runtime, as a script runs in,
// writing to out.
func scriptShell(t *testing.T, out *bytes.Buffer) *REPLState {
	t.Helper()
	session, err := NewSession("testnet", config.DefaultConfig(), t.TempDir(), out)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(session.Shutdown)
	return session.state
}

func writeScript(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A script stops at a line that names no command, or that is a shell
// command, which runs only at the interactive prompt: a typo is not skipped
// with the run going on to report success. The REPL only says so and goes on.
func TestScriptStopsAtALineItCannotRun(t *testing.T) {
	for _, tc := range []struct {
		name, line, want string
	}{
		{"unknown command", "sned 5 algo from alice to bob", "Error on line 2: unknown command: sned"},
		{"shell command", "!echo from the shell", "Error on line 2: shell commands (!) run only at the interactive prompt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			r := scriptShell(t, &out)

			err := r.runScript([]string{writeScript(t, "simulate", tc.line, "simulate on")})
			if err == nil || err.Error() != "script execution stopped at line 2" {
				t.Fatalf("runScript() error = %v, want it stopped at line 2\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("output %q does not say %q", out.String(), tc.want)
			}
			if slices.Contains(strings.Split(out.String(), "\n"), "from the shell") {
				t.Fatalf("the shell command ran:\n%s", out.String())
			}
			if r.app().IsSimulateEnabled() {
				t.Fatal("the line after the one that stopped the script ran")
			}
		})
	}

	var out bytes.Buffer
	if err := scriptShell(t, &out).executeCommand(Command{Name: "sned"}); err != nil || !strings.Contains(out.String(), "Unknown command: sned") {
		t.Fatalf("at the prompt an unknown command returned %v and said %q, want it said and no error", err, out.String())
	}
}

func TestScriptRunsEveryLine(t *testing.T) {
	var out bytes.Buffer
	r := scriptShell(t, &out)

	if err := r.runScript([]string{writeScript(t, "# a comment", "simulate", "", "simulate on")}); err != nil {
		t.Fatalf("runScript() error = %v\n%s", err, out.String())
	}
	if !r.app().IsSimulateEnabled() || !strings.Contains(out.String(), "Script completed successfully (2 commands executed)") {
		t.Fatalf("simulate = %v, output:\n%s", r.app().IsSimulateEnabled(), out.String())
	}
}
