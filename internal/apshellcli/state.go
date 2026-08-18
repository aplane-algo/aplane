// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/engine"
)

// REPLState holds the global state for the REPL.
// It keeps shell-only state locally while delegating command semantics to
// apshellapp and lower-level client mechanics to engine.
type REPLState struct {
	// Output writer for human command presentation. Defaults to os.Stdout.
	// MCP execute marshals machine results and does not capture this writer.
	Out io.Writer

	// Application facade for apshell command use-cases.
	App *apshellapp.App

	// Data directory (for config file location)
	DataDir string

	// Configuration (for network restrictions, connection defaults, etc.)
	Config config.Config

	// UI-specific state (not shared with Engine)
	CommandRegistry *command.Registry // Command registry for plugin-ready command system

	// Script session state for JS/AI commands.
	Scripts ScriptSession

	// LineReader for multi-line input in REPL (set by repl.go after readline init)
	LineReader func() (string, error)

	// SetPrompt changes the readline prompt (set by repl.go after readline init)
	SetPrompt func(string)

	// AutoConfirm skips interactive confirmation prompts (for MCP mode).
	AutoConfirm bool

	// HostKeyApproval overrides the default stdin-based TOFU prompt. Set by
	// TUI hosts that own stdin and need to route approval through their UI.
	HostKeyApproval func(host, fingerprint string) (bool, error)

	// ProgressLine, when non-nil, receives status lines emitted during
	// long-running commands (e.g. "Waiting for operator approval"). TUI hosts
	// set this to push live updates into their pane because the normal
	// captured-output path in ExecuteLineCaptured only flushes when the
	// command returns. When nil, callers fall back to println.
	ProgressLine func(string)

	// currentCommandCtx is set while an interruptible command is running.
	currentCommandCtx context.Context

	// runtimeMu serializes background signer-cache polling with command
	// execution and readline completion, because client caches are mutable maps.
	runtimeMu sync.Mutex
}

// NewREPLState creates a new REPLState with initialized runtime and app layers.
// Shared client mechanics live in Engine; shell command use-cases live in apshellapp.
func NewREPLState(network string, config *config.Config, dataDir string) (*REPLState, error) {
	eng, err := engine.NewInitializedEngine(network, config, dataDir)
	if err != nil {
		return nil, err
	}
	_ = eng.StartClientCacheWatcher()

	state := &REPLState{
		App:     apshellapp.New(eng, *config, dataDir),
		DataDir: dataDir,
		Config:  *config,
	}
	state.SetOutput(os.Stdout)

	return state, nil
}

// SetOutput updates shell output so capture/redirection stays in sync.
func (r *REPLState) SetOutput(w io.Writer) {
	r.Out = w
}

// printf writes formatted output to the configured writer.
func (r *REPLState) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(r.Out, format, args...)
}

// println writes a line to the configured writer.
func (r *REPLState) println(args ...any) {
	_, _ = fmt.Fprintln(r.Out, args...)
}

// print writes to the configured writer.
func (r *REPLState) print(args ...any) {
	_, _ = fmt.Fprint(r.Out, args...)
}

// progressPrintln emits a live status line that bypasses the captured-output
// buffer when a TUI host has installed ProgressLine, so users see progress
// during a blocking command. Falls back to println for non-TUI consumers.
func (r *REPLState) progressPrintln(line string) {
	if r.ProgressLine != nil {
		r.ProgressLine(line)
		return
	}
	r.println(line)
}

func (r *REPLState) commandContext() context.Context {
	if r.currentCommandCtx != nil {
		return r.currentCommandCtx
	}
	return context.Background()
}

func (r *REPLState) app() *apshellapp.App {
	return r.App
}

func (r *REPLState) applyClientCacheUpdates() {
	if r == nil || r.App == nil {
		return
	}
	_ = r.App.ApplyClientCacheUpdates()
}
