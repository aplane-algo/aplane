// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chzyer/readline"

	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/docassets"
)

// linesThen is a line reader that returns lines in turn and then err.
func linesThen(err error, lines ...string) func() (string, error) {
	return func() (string, error) {
		if len(lines) == 0 {
			return "", err
		}
		line := lines[0]
		lines = lines[1:]
		return line, nil
	}
}

// watchPrompt records, in order, each clearing of the prompt and each line
// read. A prompt set to anything but empty fails the test.
func watchPrompt(t *testing.T, repl *REPLState) *[]string {
	t.Helper()
	var events []string
	repl.SetPrompt = func(prompt string) {
		if prompt != "" {
			t.Errorf("prompt set to %q, want cleared", prompt)
		}
		events = append(events, "prompt")
	}
	if read := repl.LineReader; read != nil {
		repl.LineReader = func() (string, error) {
			events = append(events, "read")
			return read()
		}
	}
	return &events
}

// checkPrompt requires the prompt to be cleared once, before the first read,
// when lines are read interactively, and left alone otherwise.
func checkPrompt(t *testing.T, events []string, interactive bool) {
	t.Helper()
	clears := 0
	for _, event := range events {
		if event == "prompt" {
			clears++
		}
	}
	if !interactive {
		if clears != 0 {
			t.Fatalf("prompt cleared %d times on piped input, want none", clears)
		}
		return
	}
	if clears != 1 || events[0] != "prompt" {
		t.Fatalf("events = %v, want the prompt cleared once, before the first read", events)
	}
}

// withStdin makes text the process's standard input for one test.
func withStdin(t *testing.T, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdin
	os.Stdin = file
	t.Cleanup(func() {
		os.Stdin = previous
		_ = file.Close()
	})
}

// The code each input mode hands to the runner, exactly.
func TestRunJSCodeForEachMode(t *testing.T) {
	raw := func(text string) *command.Context { return &command.Context{RawArgs: text} }
	tests := []struct {
		name  string
		args  []string
		ctx   *command.Context
		lines []string // interactive lines; nil reads standard input
		stdin string
		want  string
	}{
		{name: "inline keeps the raw text", args: []string{"1", "+", "2"}, ctx: raw("1 +  2"), want: "1 +  2"},
		{name: "inline without raw text joins the words", args: []string{"1", "+", "2"}, want: "1 + 2"},
		{name: "inline with empty raw text joins the words", args: []string{"40", "+", "2"}, ctx: raw(""), want: "40 + 2"},
		{name: "-help is code unless it comes first", args: []string{"1", "-help"}, ctx: raw("1 //-help"), want: "1 //-help"},

		{name: "lines until a blank one", lines: []string{"20 +", "22", "", "ignored"}, want: "20 +\n22"},
		{name: "a line of spaces is not blank", lines: []string{"20 +", "  ", "22", ""}, want: "20 +\n  \n22"},
		{name: "piped lines until a blank one", stdin: "20 +\n22\n\nignored\n", want: "20 +\n22"},
		{name: "piped lines until the input ends", stdin: "20 +\n22\n", want: "20 +\n22"},

		{name: "braces on one line", args: []string{"{", "6", "*", "7", "}"}, ctx: raw("{ 6 * 7 }"), want: "6 * 7"},
		{name: "braces keep inner quotes and spacing", args: []string{"{'a", "b'}"}, ctx: raw("{'a  b'}"), want: "'a  b'"},
		{name: "empty braces run empty code", args: []string{"{}"}, ctx: raw("{}"), want: ""},
		{name: "an open brace reads lines until a closing one", args: []string{"{", "var", "x", "=", "1;"}, ctx: raw("{ var x = 1;"),
			lines: []string{"x + 41", "  }  ", "ignored"}, want: "var x = 1;\nx + 41"},
		{name: "a bare open brace starts with an empty line", args: []string{"{"}, ctx: raw("{"),
			lines: []string{"40 + 2", "}"}, want: "\n40 + 2"},
		{name: "a brace inside a later line does not close", args: []string{"{"}, ctx: raw("{ var o ="),
			lines: []string{"{a: 1}", "}"}, want: "var o =\n{a: 1}"},
		{name: "an open brace reads piped lines", args: []string{"{", "var", "x", "=", "1;"}, ctx: raw("{ var x = 1;"),
			stdin: "x + 41\n}\nignored\n", want: "var x = 1;\nx + 41"},
		{name: "an open brace runs what it has when piped input ends", args: []string{"{", "1", "+"}, ctx: raw("{ 1 +"),
			stdin: "1\n", want: "1 +\n1"},
		{name: "an open brace runs what it has when piped input is empty", args: []string{"{", "1", "+", "1"}, ctx: raw("{ 1 + 1"),
			stdin: "", want: "1 + 1"},
		{name: "braces around spaces run empty code", args: []string{"{", "}"}, ctx: raw("{ }"), want: ""},
		{name: "a closing brace before the end of the line does not close", args: []string{"{", "'}'", "+", "'x'"}, ctx: raw("{ '}' + 'x'"),
			lines: []string{"}"}, want: "'}' + 'x'"},
		{name: "brace words without raw text are inline code", args: []string{"{", "}"}, want: "{ }"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repl := testREPLForJS(t)
			if tt.lines != nil {
				repl.LineReader = linesThen(errors.New("read past the end of the test's lines"), tt.lines...)
			} else {
				withStdin(t, tt.stdin)
			}
			events := watchPrompt(t, repl)
			if err := repl.runJS(tt.args, rawCommandArgs(tt.ctx)); err != nil {
				t.Fatalf("runJS() error = %v", err)
			}
			if repl.Scripts.Runner == nil {
				t.Fatal("no code was run")
			}
			if got := repl.Scripts.LastCode; got != tt.want {
				t.Fatalf("code run = %q, want %q", got, tt.want)
			}
			checkPrompt(t, *events, tt.lines != nil)
		})
	}
}

// Reading that ends without code runs nothing.
func TestRunJSRunsNothing(t *testing.T) {
	failed := errors.New("terminal went away")
	openBrace := []string{"{", "1", "+"}
	tooLong := strings.Repeat("x", bufio.MaxScanTokenSize+1)
	tests := []struct {
		name    string
		args    []string
		raw     string
		reader  func() (string, error)
		stdin   string
		wantErr error
		wantOut string
	}{
		{name: "no lines before the blank one", reader: linesThen(nil, ""),
			wantOut: "Enter JavaScript code (blank line to execute, Ctrl+C to cancel):\n"},
		{name: "piped input that is empty", stdin: "",
			wantOut: "Enter JavaScript code (blank line to execute, Ctrl+C to cancel):\n"},
		{name: "interrupted while entering lines", reader: linesThen(readline.ErrInterrupt, "20 +"),
			wantOut: "Enter JavaScript code (blank line to execute, Ctrl+C to cancel):\n\nCancelled.\n"},
		{name: "a read error while entering lines", reader: linesThen(failed, "20 +"), wantErr: failed,
			wantOut: "Enter JavaScript code (blank line to execute, Ctrl+C to cancel):\n"},
		{name: "interrupted inside braces", args: openBrace, raw: "{ 1 +", reader: linesThen(readline.ErrInterrupt, "1"),
			wantOut: "\nCancelled.\n"},
		{name: "a read error inside braces", args: openBrace, raw: "{ 1 +", reader: linesThen(failed, "1"), wantErr: failed},
		// A piped line too long to scan fails the read after a good line;
		// the good line is not run.
		{name: "a piped read error while entering lines", stdin: "20 +\n" + tooLong + "\n", wantErr: bufio.ErrTooLong,
			wantOut: "Enter JavaScript code (blank line to execute, Ctrl+C to cancel):\n"},
		{name: "a piped read error inside braces", args: openBrace, raw: "{ 1 +", stdin: "1\n" + tooLong + "\n", wantErr: bufio.ErrTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repl := testREPLForJS(t)
			if tt.reader != nil {
				repl.LineReader = tt.reader
			} else {
				withStdin(t, tt.stdin)
			}
			events := watchPrompt(t, repl)
			err := repl.runJS(tt.args, tt.raw)
			checkPrompt(t, *events, tt.reader != nil)
			if err != tt.wantErr {
				t.Fatalf("runJS() error = %v, want %v", err, tt.wantErr)
			}
			if repl.Scripts.Runner != nil {
				t.Fatalf("code was run: %q", repl.Scripts.LastCode)
			}
			if got := repl.Out.(*bytes.Buffer).String(); got != tt.wantOut {
				t.Fatalf("output = %q, want %q", got, tt.wantOut)
			}
		})
	}
}

func TestRunJSScriptFiles(t *testing.T) {
	t.Run("a bare name resolves to the scripts directory", func(t *testing.T) {
		repl := testREPLForJS(t)
		scripts := filepath.Join(repl.DataDir, "scripts")
		if err := os.MkdirAll(scripts, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(scripts, "answer.js"), []byte("40 + 2"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := repl.runJS([]string{"answer.js", "extra"}, "answer.js extra"); err != nil {
			t.Fatalf("runJS() error = %v", err)
		}
		if got := repl.Scripts.LastCode; got != "40 + 2" {
			t.Fatalf("code run = %q, want the file's contents", got)
		}
	})
	t.Run("a missing script is an error and runs nothing", func(t *testing.T) {
		repl := testREPLForJS(t)
		err := repl.runJS([]string{"missing.js"}, "missing.js")
		if err == nil || !strings.HasPrefix(err.Error(), "failed to read script: ") || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("runJS() error = %v, want a wrapped not-exist error", err)
		}
		if repl.Scripts.Runner != nil {
			t.Fatal("code was run")
		}
	})
	t.Run("braces win over a script name", func(t *testing.T) {
		repl := testREPLForJS(t)
		if err := repl.runJS([]string{"{'a.js'}"}, "{'a.js'}"); err != nil {
			t.Fatalf("runJS() error = %v", err)
		}
		if got := repl.Scripts.LastCode; got != "'a.js'" {
			t.Fatalf("code run = %q, want the braces' contents", got)
		}
	})
}

func TestRunJSPrintsItsResult(t *testing.T) {
	tests := []struct{ code, want string }{
		{"40 + 2", "42\n"},
		{"({a: 1})", "map[a:1]\n"},
		{"[1, 2]", "[1 2]\n"},
		{"undefined", ""},
		{"var x = 1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			repl := testREPLForJS(t)
			if err := repl.runJS(strings.Fields(tt.code), tt.code); err != nil {
				t.Fatalf("runJS() error = %v", err)
			}
			if got := repl.Out.(*bytes.Buffer).String(); got != tt.want {
				t.Fatalf("output = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunJSHelpPrintsTheReferenceAndRunsNothing(t *testing.T) {
	repl := testREPLForJS(t)
	if err := repl.runJS([]string{"-help", "{"}, "-help {"); err != nil {
		t.Fatalf("runJS() error = %v", err)
	}
	if repl.Scripts.Runner != nil {
		t.Fatal("code was run")
	}
	if got, want := repl.Out.(*bytes.Buffer).String(), strings.TrimRight(docassets.UserJSAPI, "\n")+"\n"; got != want {
		t.Fatalf("output is %d bytes, want the %d-byte API reference", len(got), len(want))
	}
}

// LastCode is the last code that ran without error; jssave -last saves it.
func TestRunJSKeepsLastCodeWhenARunFails(t *testing.T) {
	repl := testREPLForJS(t)
	if err := repl.runJS([]string{"40", "+", "2"}, "40 + 2"); err != nil {
		t.Fatalf("runJS() error = %v", err)
	}
	if err := repl.runJS([]string{"throw", "1"}, "throw 1"); err == nil {
		t.Fatal("runJS(throw 1) error = nil, want the script's error")
	}
	if got := repl.Scripts.LastCode; got != "40 + 2" {
		t.Fatalf("LastCode after a failed run = %q, want the earlier code", got)
	}
}
