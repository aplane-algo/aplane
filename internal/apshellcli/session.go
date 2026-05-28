// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/config"
)

// Session is an embedded apshell command session for non-readline hosts.
type Session struct {
	state       *REPLState
	stopPolling context.CancelFunc

	execMu       sync.Mutex
	activeMu     sync.Mutex
	activeCancel context.CancelFunc
	activeID     uint64
}

// NewSession initializes apshell state without taking over terminal input or
// touching the network. Callers that want auto-connect (TUI hosts, REPL-like
// embeddings) must install any UI-routed handlers (e.g. SetHostKeyApproval)
// and then call StartupConnect.
func NewSession(network string, cfg config.Config, dataDir string, out io.Writer) (*Session, error) {
	state, err := NewREPLState(network, &cfg, dataDir)
	if err != nil {
		return nil, err
	}
	state.Config = cfg
	state.CommandRegistry = state.initCommandRegistry()
	if out != nil {
		state.SetOutput(out)
	}
	if err := initPluginRuntime(state); err != nil {
		return nil, err
	}
	return &Session{
		state:       state,
		stopPolling: state.startSignerStatusPolling(nil),
	}, nil
}

// StartupConnect runs the deferred signer connect that used to happen inside
// NewSession. Output emitted during the attempt is captured and returned so
// the caller (typically a TUI pane) can render it after the UI is up.
func (s *Session) StartupConnect() (string, error) {
	if s == nil || s.state == nil {
		return "", fmt.Errorf("apshell session is not initialized")
	}
	s.execMu.Lock()
	defer s.execMu.Unlock()

	var buf bytes.Buffer
	previous := s.state.Out
	s.state.SetOutput(&buf)
	defer s.state.SetOutput(previous)
	decision := s.state.app().StartupConnectDecision()
	if !decision.HasToken {
		s.state.println()
		s.state.println(missingAplaneTokenStartupMessage)
		s.state.println()
		return strings.TrimRight(buf.String(), "\n"), nil
	}
	err := attemptStartupConnection(s.state)
	if err != nil {
		s.state.printf("Warning: Signer verification failed: %v\n", err)
		s.state.println("Signer not available (run 'connect' to retry)")
	}
	return strings.TrimRight(buf.String(), "\n"), err
}

// ExecuteLine parses and executes one apshell input line.
func (s *Session) ExecuteLine(raw string) (exit bool, err error) {
	return s.ExecuteLineContext(context.Background(), raw)
}

// ExecuteLineContext parses and executes one apshell input line with a caller-owned context.
func (s *Session) ExecuteLineContext(ctx context.Context, raw string) (exit bool, err error) {
	if s == nil || s.state == nil {
		return false, fmt.Errorf("apshell session is not initialized")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.execMu.Lock()
	defer s.execMu.Unlock()
	return s.executeLineContext(ctx, raw)
}

func (s *Session) executeLineContext(ctx context.Context, raw string) (exit bool, err error) {
	cleanupSignerCtx := s.state.app().BindSignerClientContext(ctx)
	defer cleanupSignerCtx()
	priorCtx := s.state.currentCommandCtx
	s.state.currentCommandCtx = ctx
	defer func() {
		s.state.currentCommandCtx = priorCtx
	}()

	s.state.runtimeMu.Lock()
	defer s.state.runtimeMu.Unlock()

	if handled, err := s.state.handleShellInput(raw); handled {
		return false, err
	}
	cmd, err := s.state.parseInputCommand(raw)
	if err != nil {
		return false, err
	}
	if cmd.Name == "" {
		return false, nil
	}
	if err := s.state.executeCommand(cmd); err != nil {
		if err.Error() == "exit" {
			return true, nil
		}
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// ExecuteLineCaptured executes one line and returns text emitted by apshell.
func (s *Session) ExecuteLineCaptured(raw string) (output string, exit bool, err error) {
	if s == nil || s.state == nil {
		return "", false, fmt.Errorf("apshell session is not initialized")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.activeMu.Lock()
	s.activeID++
	activeID := s.activeID
	s.activeCancel = cancel
	s.activeMu.Unlock()
	defer func() {
		s.activeMu.Lock()
		if s.activeID == activeID {
			s.activeCancel = nil
		}
		s.activeMu.Unlock()
	}()

	previous := s.state.Out
	var buf bytes.Buffer
	s.execMu.Lock()
	s.state.SetOutput(&buf)
	defer func() {
		s.state.SetOutput(previous)
		s.execMu.Unlock()
	}()

	exit, err = s.executeLineContext(ctx, raw)
	return strings.TrimRight(buf.String(), "\n"), exit, err
}

// Complete returns tab-completion suggestions for line[:pos] using the same
// dynamic completer as the interactive REPL. The returned offset is the length
// of the partial word at pos-offset..pos; each candidate is the text to append
// after the partial to complete a word.
func (s *Session) Complete(line string, pos int) (int, []string) {
	if s == nil || s.state == nil {
		return 0, nil
	}
	s.state.runtimeMu.Lock()
	defer s.state.runtimeMu.Unlock()
	if pos < 0 {
		pos = 0
	}
	runes := []rune(line)
	if pos > len(runes) {
		pos = len(runes)
	}
	suggestions, offset := s.state.discoverCompleter().Do(runes, pos)
	out := make([]string, 0, len(suggestions))
	for _, sug := range suggestions {
		out = append(out, string(sug))
	}
	return offset, out
}

// Prompt returns the apshell prompt for the current session state, matching the
// ANSI-styled prompt used by the interactive REPL.
func (s *Session) Prompt() string {
	if s == nil || s.state == nil {
		return "> "
	}
	return s.state.promptString()
}

// History returns persisted apshell history entries in oldest-to-newest order.
func (s *Session) History() []string {
	return loadHistoryFile(historyFilePath(), historyLimit)
}

// RecordHistory persists one apshell command history entry.
func (s *Session) RecordHistory(line string) {
	appendHistoryFile(historyFilePath(), line)
}

// SetHostKeyApproval injects a custom SSH host key approval handler. TUI hosts
// call this after creating the bubbletea program so that unknown host prompts
// are routed through the UI instead of blocking on stdin.
func (s *Session) SetHostKeyApproval(fn func(host, fingerprint string) (bool, error)) {
	if s == nil || s.state == nil {
		return
	}
	s.state.HostKeyApproval = fn
}

// SetProgressLine installs a callback that receives live status lines emitted
// during blocking commands (e.g. "Waiting for operator approval"). TUI hosts
// use this to surface progress in a pane because the session's normal
// ExecuteLineCaptured output is only delivered when the command returns.
func (s *Session) SetProgressLine(fn func(string)) {
	if s == nil || s.state == nil {
		return
	}
	s.state.ProgressLine = fn
}

// SetInteractiveLinePrompt routes command-time line prompts through an embedding
// host. TUI hosts use this for approval prompts because they own stdin.
func (s *Session) SetInteractiveLinePrompt(fn func(prompt string) (string, error)) {
	if s == nil || s.state == nil || fn == nil {
		return
	}
	var mu sync.Mutex
	prompt := ""
	s.state.SetPrompt = func(p string) {
		mu.Lock()
		prompt = p
		mu.Unlock()
	}
	s.state.LineReader = func() (string, error) {
		mu.Lock()
		p := prompt
		mu.Unlock()
		return fn(p)
	}
}

// SetPluginStderr redirects plugin stderr (and the sandbox-startup banner) to
// w. Use io.Discard from TUI hosts where raw stderr would corrupt the display.
// No-op if the plugin runtime is not the concrete manager that supports it.
func (s *Session) SetPluginStderr(w io.Writer) {
	if s == nil || s.state == nil {
		return
	}
	app := s.state.app()
	if app == nil || app.Plugins == nil {
		return
	}
	if setter, ok := app.Plugins.(interface{ SetStderrWriter(io.Writer) }); ok {
		setter.SetStderrWriter(w)
	}
}

// Cancel interrupts the currently executing embedded command, if any.
func (s *Session) Cancel() bool {
	if s == nil {
		return false
	}
	s.activeMu.Lock()
	cancel := s.activeCancel
	s.activeMu.Unlock()
	if cancel == nil {
		return false
	}
	cancel()
	return true
}

// Shutdown releases apshell runtime resources owned by the session.
func (s *Session) Shutdown() {
	if s == nil || s.state == nil {
		return
	}
	s.Cancel()
	if s.stopPolling != nil {
		s.stopPolling()
		s.stopPolling = nil
	}
	shutdownRuntime(s.state)
	s.state = nil
}
