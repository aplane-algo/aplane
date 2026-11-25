// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

var nextPluginStep = map[string]any{"command": "wf", "args": []string{"_next"}}

// emptySteps is n steps that have no transactions and ask for another.
func emptySteps(n int) []map[string]any {
	steps := make([]map[string]any, n)
	for i := range steps {
		steps[i] = map[string]any{"success": true, "message": fmt.Sprintf("empty %d", i), "continuation": nextPluginStep}
	}
	return steps
}

// submittingSteps is n steps that each submit a group and ask for another.
func submittingSteps(t *testing.T, n int) []map[string]any {
	t.Helper()
	steps := make([]map[string]any, n)
	for i := range steps {
		steps[i], _ = pregroupedStep(t, fmt.Sprintf("step %d", i), nextPluginStep)
	}
	return steps
}

var lastPluginStep = []map[string]any{{"success": true, "message": "done"}}

func joinSteps(groups ...[]map[string]any) []map[string]any {
	var steps []map[string]any
	for _, group := range groups {
		steps = append(steps, group...)
	}
	return steps
}

// A plugin that keeps asking for another step is stopped: soon when its steps
// have no transactions, and only far above any real workflow when they do, since
// the steps before are already submitted.
func TestPluginContinuationsAreBounded(t *testing.T) {
	const (
		tooManyEmpty = "plugin run stopped: more than 8 steps in a row had no transactions and asked for another"
		tooManySteps = "plugin run stopped: it asked for more than 64 continuation steps"
	)
	if maxEmptyPluginSteps != 8 || maxPluginContinuations != 64 {
		t.Fatalf("caps = %d, %d; update this test's counts", maxEmptyPluginSteps, maxPluginContinuations)
	}
	tests := []struct {
		name     string
		steps    func(t *testing.T) []map[string]any
		refusal  string // empty: the run completes
		executed int
		sent     int32
	}{
		{"a run of empty steps", func(t *testing.T) []map[string]any {
			return emptySteps(30)
		}, tooManyEmpty, 9, 0},
		{"as many empty steps as allowed", func(t *testing.T) []map[string]any {
			return joinSteps(emptySteps(8), lastPluginStep)
		}, "", 9, 0},
		{"empty steps, started over by a submitting one", func(t *testing.T) []map[string]any {
			return joinSteps(emptySteps(8), submittingSteps(t, 1), emptySteps(8), lastPluginStep)
		}, "", 18, 1},
		{"a run of empty steps after a submitting one", func(t *testing.T) []map[string]any {
			return joinSteps(submittingSteps(t, 1), emptySteps(30))
		}, tooManyEmpty, 10, 1},
		{"as many submitting steps as allowed", func(t *testing.T) []map[string]any {
			return joinSteps(submittingSteps(t, 64), lastPluginStep)
		}, "", 65, 64},
		{"too many submitting steps", func(t *testing.T) []map[string]any {
			return submittingSteps(t, 70)
		}, tooManySteps, 65, 65},
		{"too many steps, every other one empty", func(t *testing.T) []map[string]any {
			var steps []map[string]any
			for range 40 {
				steps = joinSteps(steps, submittingSteps(t, 1), emptySteps(1))
			}
			return steps
		}, tooManySteps, 65, 33},
	}
	for _, tt := range tests {
		for _, entry := range []string{"REPL", "JS"} {
			t.Run(tt.name+"/"+entry, func(t *testing.T) {
				client, sent := confirmationFailingAlgod(t, 1000)
				state, scripted := boundedPluginShell(t, client, tt.steps(t))
				var failure string
				if entry == "JS" {
					if _, err := runScript(t, state, `JSON.stringify(plugin("wf", "start"))`); err != nil {
						failure = err.Error()
					}
				} else {
					result, ok := execPlugin(state, "wf", []string{"start"})
					if !ok {
						t.Fatal("execPlugin() did not run the plugin")
					}
					if !result.Success {
						failure = result.Message
					}
					if got := len(result.Steps); tt.refusal != "" && int32(got) != tt.sent {
						t.Fatalf("recorded %d submitted steps, want %d", got, tt.sent)
					}
				}
				if tt.refusal == "" && failure != "" || tt.refusal != "" && !strings.Contains(failure, tt.refusal) {
					t.Fatalf("failure = %q, want %q", failure, tt.refusal)
				}
				if got := len(scripted.executeCalls()); got != tt.executed {
					t.Fatalf("plugin executed %d steps, want %d", got, tt.executed)
				}
				if got := sent.Load(); got != tt.sent {
					t.Fatalf("groups sent = %d, want %d", got, tt.sent)
				}
			})
		}
	}
}

func boundedPluginShell(t *testing.T, client *algod.Client, steps []map[string]any) (*REPLState, *scriptedPlugin) {
	t.Helper()
	state, scripted := scriptedPluginShellWithAlgod(t, client, steps...)
	state.AutoConfirm, state.LineReader = false, func() (string, error) { return "y", nil }
	return state, scripted
}
