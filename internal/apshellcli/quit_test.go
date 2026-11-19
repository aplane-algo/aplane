// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"testing"
)

// Only quit ends the shell. A plugin that fails with the message "exit"
// fails, in a session and in a script, like any other failure: its text is
// not quit's.
func TestOnlyQuitEndsTheShell(t *testing.T) {
	failsWithExit := map[string]any{"success": false, "message": "exit"}

	state, _ := scriptedPluginShell(t, failsWithExit)
	state.CommandRegistry = state.initCommandRegistry()
	session := &Session{state: state}
	_, exit, err := session.ExecuteLineCaptured("wf go")
	if exit || err == nil || err.Error() != "exit" {
		t.Fatalf("a plugin failing with %q: exit = %v, error = %v; want the plugin's failure and the session going on", "exit", exit, err)
	}
	if _, exit, err := session.ExecuteLineCaptured("quit"); !exit || err != nil {
		t.Fatalf("quit: exit = %v, error = %v; want the session ended", exit, err)
	}

	state, scripted := scriptedPluginShell(t, failsWithExit)
	state.CommandRegistry = state.initCommandRegistry()
	err = state.runScript([]string{writeScript(t, "wf go", "wf again")})
	if err == nil || err.Error() != "script execution stopped at line 1" {
		t.Fatalf("runScript() error = %v, want the script failed at line 1, not ended as by quit", err)
	}
	if calls := len(scripted.calls); calls != 1 {
		t.Fatalf("plugin called %d times, want the script stopped after the first", calls)
	}
	if err := state.runScript([]string{writeScript(t, "quit", "wf again")}); err != errQuit {
		t.Fatalf("runScript() of quit = %v, want errQuit", err)
	}
}
