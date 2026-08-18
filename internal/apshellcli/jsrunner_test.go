// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
)

func testREPLForJS(t *testing.T) *REPLState {
	t.Helper()

	eng, err := newIsolatedTestEngine(t, "testnet")
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	repl := &REPLState{
		App:     apshellapp.New(eng, config.DefaultConfig(), t.TempDir()),
		DataDir: t.TempDir(),
	}
	repl.SetOutput(&bytes.Buffer{})
	return repl
}

func TestCmdJSInlineAndFileModes(t *testing.T) {
	t.Run("inline", func(t *testing.T) {
		repl := testREPLForJS(t)
		out := repl.Out.(*bytes.Buffer)

		err := repl.runJS([]string{"1", "+", "2"}, &command.Context{RawArgs: "1 + 2"})
		if err != nil {
			t.Fatalf("cmdJS(inline) error = %v", err)
		}
		if got := out.String(); !strings.Contains(got, "3") {
			t.Fatalf("inline output = %q, want 3", got)
		}
		if repl.Scripts.Runner == nil {
			t.Fatal("inline state missing runner")
		}
	})

	t.Run("file", func(t *testing.T) {
		repl := testREPLForJS(t)
		out := repl.Out.(*bytes.Buffer)

		scriptPath := filepath.Join(t.TempDir(), "script.js")
		if err := os.WriteFile(scriptPath, []byte("40 + 2"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		err := repl.runJS([]string{scriptPath}, &command.Context{RawArgs: scriptPath})
		if err != nil {
			t.Fatalf("cmdJS(file) error = %v", err)
		}
		if got := out.String(); !strings.Contains(got, "42") {
			t.Fatalf("file output = %q, want 42", got)
		}
	})
}

func TestCmdJSBraceAndMultilineModes(t *testing.T) {
	t.Run("brace", func(t *testing.T) {
		repl := testREPLForJS(t)
		out := repl.Out.(*bytes.Buffer)

		err := repl.runJS([]string{"{"}, &command.Context{RawArgs: "{ 6 * 7 }"})
		if err != nil {
			t.Fatalf("cmdJS(brace) error = %v", err)
		}
		if got := out.String(); !strings.Contains(got, "42") {
			t.Fatalf("brace output = %q, want 42", got)
		}
	})

	t.Run("multiline", func(t *testing.T) {
		repl := testREPLForJS(t)
		out := repl.Out.(*bytes.Buffer)
		lines := []string{"20 +", "22", ""}
		repl.LineReader = func() (string, error) {
			line := lines[0]
			lines = lines[1:]
			return line, nil
		}

		err := repl.runJS(nil, nil)
		if err != nil {
			t.Fatalf("cmdJS(multiline) error = %v", err)
		}
		if got := out.String(); !strings.Contains(got, "42") {
			t.Fatalf("multiline output = %q, want 42", got)
		}
	})
}

func TestCmdJSHelpFlagPrintsAPIDocs(t *testing.T) {
	repl := testREPLForJS(t)
	out := repl.Out.(*bytes.Buffer)

	err := repl.runJS([]string{"-help"}, &command.Context{RawArgs: "-help"})
	if err != nil {
		t.Fatalf("cmdJS(-help) error = %v", err)
	}
	if !strings.Contains(out.String(), "JavaScript API Reference") {
		t.Fatalf("output missing expected header: %q", out.String())
	}
}

func TestCmdJSSaveAndJSListUseScriptsDirForBareFilename(t *testing.T) {
	repl := testREPLForJS(t)
	out := repl.Out.(*bytes.Buffer)
	scriptPath := filepath.Join(repl.DataDir, "scripts", "audit.js")

	err := repl.runJSSave(nil, &command.Context{RawArgs: `audit.js print("ok")`})
	if err != nil {
		t.Fatalf("cmdJSSave() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, scriptPath) {
		t.Fatalf("cmdJSSave() output = %q, want scripts-dir path %q", got, scriptPath)
	}

	out.Reset()
	err = repl.runJSList(nil, nil)
	if err != nil {
		t.Fatalf("cmdJSList() error = %v", err)
	}
	scriptsDir := filepath.Join(repl.DataDir, "scripts")
	got := out.String()
	if !strings.Contains(got, scriptsDir) {
		t.Fatalf("cmdJSList() output = %q, want scripts dir header %q", got, scriptsDir)
	}
	if !strings.Contains(got, "audit.js") {
		t.Fatalf("cmdJSList() output = %q, want filename %q", got, "audit.js")
	}
}

func TestCmdJSSaveAcceptsAbsolutePath(t *testing.T) {
	repl := testREPLForJS(t)
	out := repl.Out.(*bytes.Buffer)
	scriptPath := filepath.Join(t.TempDir(), "audit.js")

	err := repl.runJSSave(nil, &command.Context{RawArgs: scriptPath + ` print("ok")`})
	if err != nil {
		t.Fatalf("cmdJSSave() error = %v", err)
	}
	if got := out.String(); !strings.Contains(got, scriptPath) {
		t.Fatalf("cmdJSSave() output = %q, want absolute path %q", got, scriptPath)
	}
}

func TestCmdJSSaveRejectsRelativePathWithSlash(t *testing.T) {
	repl := testREPLForJS(t)

	err := repl.runJSSave(nil, &command.Context{RawArgs: `nested/audit.js print("ok")`})
	if err == nil {
		t.Fatal("cmdJSSave() expected error for relative path with slash")
	}
}
