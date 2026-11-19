// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/command"

	"github.com/chzyer/readline"
)

type offersOne struct{}

func (offersOne) Do([]rune, int) ([][]rune, int) { return [][]rune{[]rune("ice")}, 2 }

// Tab at a prompt a command shows while it runs offers nothing and returns
// at once. The command holds the runtime lock the completer takes at the
// command prompt; waiting for it there would never end, since the command is
// itself waiting for the line.
func TestTabAtACommandsOwnPromptOffersNothing(t *testing.T) {
	r := testREPLForSimulate(t)
	completer := r.lockedCompleter(func() readline.AutoCompleter { return offersOne{} })

	if got, _ := completer.Do([]rune("al"), 2); len(got) != 1 {
		t.Fatalf("at the command prompt Tab offered %q, want the completer's one candidate", got)
	}

	offered := make(chan [][]rune, 1)
	if err := r.CommandRegistry.Register(&command.Command{
		Name: "asks", Category: command.CategoryInfo, Automation: command.StructuredAutomation,
		Handler: command.NewInternalHandler(func([]string, *command.Context) (command.Result, error) {
			got, _ := completer.Do([]rune("al"), 2) // Tab at the command's own prompt
			offered <- got
			return newTerminalCommandResult(nil), nil
		}),
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- r.executeCommandWithInterrupt(Command{Name: "asks"}, make(chan os.Signal)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the command failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Tab at the command's prompt never returned: the completer is waiting for the lock the command holds")
	}
	if got := <-offered; len(got) != 0 {
		t.Fatalf("Tab at the command's prompt offered %q, want nothing", got)
	}
	if got, _ := completer.Do([]rune("al"), 2); len(got) != 1 {
		t.Fatalf("after the command Tab offered %q, want completion back at the command prompt", got)
	}
}

// The completer readline is given at startup completes from the shell as it
// is at each Tab, so nothing replaces it later: readline reads it on its own
// goroutine, and a later write to its config would race with that read.
func TestTabCompletesFromTheShellAsItIsAtTheTab(t *testing.T) {
	r := testREPLForSimulate(t)
	completer := r.newReadlineConfig().AutoComplete
	completes := func(word string) bool {
		line := []rune("network ")
		candidates, _ := completer.Do(line, len(line))
		for _, candidate := range candidates {
			if strings.TrimSpace(string(candidate)) == word {
				return true
			}
		}
		return false
	}
	if completes("devnet7") {
		t.Fatal("Tab offered a network that is not configured")
	}
	r.app().Config.NetworksAllowed = append(r.app().Config.NetworksAllowed, "devnet7")
	if !completes("devnet7") {
		t.Fatal("Tab did not offer the network configured after the completer was installed")
	}
}

// One-shot simulate runs the command it names, so MCP applies that command's
// policy too: keyreg's paste mode, which would read MCP's own stdin, is
// refused as it is without simulate, and so is a command MCP blocks.
func TestMCPSimulateAppliesTheSimulatedCommandsPolicy(t *testing.T) {
	for _, tc := range []struct {
		line, want string
	}{
		{"keyreg", "keyreg paste mode not available via MCP"},
		{"simulate keyreg", "keyreg paste mode not available via MCP"},
		{"simulate script x.txt", "command 'script' not available via MCP"},
	} {
		cmd, err := parseShellCommand(tc.line)
		if err != nil {
			t.Fatal(err)
		}
		result := mcpExecuteCommand(testREPLForSimulate(t), cmd)
		if text := mcpResultText(t, result); !result.IsError || !strings.Contains(text, tc.want) {
			t.Fatalf("%q: MCP result %q (error %v), want a refusal containing %q", tc.line, text, result.IsError, tc.want)
		}
	}
	// With arguments keyreg passes its guard, simulated or not.
	cmd, err := parseShellCommand("simulate keyreg nosuchaccount offline")
	if err != nil {
		t.Fatal(err)
	}
	if text := mcpResultText(t, mcpExecuteCommand(testREPLForSimulate(t), cmd)); strings.Contains(text, "paste mode") {
		t.Fatalf("keyreg with arguments was refused as paste mode: %q", text)
	}
}
