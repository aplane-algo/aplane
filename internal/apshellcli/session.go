// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/aplane-algo/aplane/internal/config"
)

var (
	errSessionNotInitialized = errors.New("apshell session is not initialized")
	errSessionShutDown       = errors.New("apshell session is shut down")
)

// Session is an embedded apshell command session for non-readline hosts.
// execMu is held while a line runs and while the session shuts down, so
// state, which Shutdown clears, is read under it.
type Session struct {
	state       *REPLState
	stopPolling context.CancelFunc

	execMu   sync.Mutex
	activeMu sync.Mutex
	// active holds the cancel of every operation begun and not yet ended:
	// the one running under execMu and any waiting for it. Cancel and
	// Shutdown reach them all.
	active   map[uint64]context.CancelFunc
	activeID uint64
	// closing is set, under activeMu, when Shutdown begins: nothing starts
	// after it, so no operation can slip past Shutdown's cancel.
	closing bool
}

// NewSession initializes apshell state without taking over terminal input or
// touching the network. Callers that want auto-connect (TUI hosts, REPL-like
// embeddings) must install any UI-routed handlers (e.g.
// SetHostKeyApprovalContext) and then call StartupConnect.
func NewSession(network string, cfg config.Config, dataDir string, out io.Writer) (*Session, error) {
	state, err := NewREPLState(network, &cfg, dataDir)
	if err != nil {
		return nil, err
	}
	state.CommandRegistry = state.initCommandRegistry()
	if out != nil {
		state.SetOutput(out)
	}
	if err := initPluginRuntime(state); err != nil {
		return nil, err
	}
	return &Session{
		state:       state,
		stopPolling: state.startSignerStatusPolling(),
	}, nil
}

// StartupConnect runs the deferred signer connect that used to happen inside
// NewSession. Output emitted during the attempt is captured and returned so
// the caller (typically a TUI pane) can render it after the UI is up.
//
// The attempt runs on its own context, which Cancel and Shutdown reach, as a
// line's does: a connect waiting on its SSH handshake or a host-key prompt
// ends with it.
func (s *Session) StartupConnect() (string, error) {
	if s == nil {
		return "", errSessionNotInitialized
	}
	ctx, end, err := s.beginActive(context.Background())
	if err != nil {
		return "", err
	}
	defer end()
	s.execMu.Lock()
	defer s.execMu.Unlock()
	if err := s.startable(ctx); err != nil {
		return "", err
	}
	defer s.state.bindCommandContext(ctx)()

	var buf bytes.Buffer
	previous := s.state.Out
	s.state.SetOutput(&buf)
	defer s.state.SetOutput(previous)
	err = attemptStartupConnection(s.state)
	if err != nil {
		s.state.printf("Warning: Signer verification failed: %v\n", err)
		s.state.println("Signer not available (run 'connect' to retry)")
	}
	return strings.TrimRight(buf.String(), "\n"), err
}

func (s *Session) executeLineContext(ctx context.Context, raw string) (exit bool, err error) {
	defer s.state.bindCommandContext(ctx)()

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
		if errors.Is(err, errQuit) {
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
	if s == nil {
		return "", false, errSessionNotInitialized
	}
	ctx, end, err := s.beginActive(context.Background())
	if err != nil {
		return "", false, err
	}
	defer end()

	s.execMu.Lock()
	defer s.execMu.Unlock()
	if err := s.startable(ctx); err != nil {
		return "", false, err
	}
	state := s.state
	previous := state.Out
	var buf bytes.Buffer
	state.SetOutput(&buf)
	defer state.SetOutput(previous)

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
	return loadHistoryFile(historyFilePath())
}

// RecordHistory persists one apshell command history entry.
func (s *Session) RecordHistory(line string) {
	appendHistoryFile(historyFilePath(), line)
}

// SetHostKeyApprovalContext routes unknown SSH host prompts through an
// embedding host's UI instead of stdin. TUI hosts call it after creating the
// bubbletea program. The prompt is dismissed when the active command context
// is canceled.
func (s *Session) SetHostKeyApprovalContext(fn func(context.Context, string, string) (bool, error)) {
	if s == nil || s.state == nil {
		return
	}
	s.state.HostKeyApprovalContext = fn
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

// SetInteractiveLinePromptContext routes command-time line prompts through an
// embedding host that owns terminal input. A pending prompt ends when the
// active command context is canceled.
func (s *Session) SetInteractiveLinePromptContext(fn func(context.Context, string) (string, error)) {
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
	s.state.LineReaderContext = func(ctx context.Context) (string, error) {
		mu.Lock()
		p := prompt
		mu.Unlock()
		return fn(ctx, p)
	}
}

// beginActive makes the context of the operation about to run, a line or the
// startup connect, from parent: Cancel and Shutdown cancel it until end is
// called, whether it runs or still waits for execMu. Once Shutdown has begun
// it refuses.
func (s *Session) beginActive(parent context.Context) (ctx context.Context, end func(), err error) {
	ctx, cancel := context.WithCancel(parent)
	s.activeMu.Lock()
	if s.closing {
		s.activeMu.Unlock()
		cancel()
		return nil, nil, errSessionShutDown
	}
	if s.active == nil {
		s.active = make(map[uint64]context.CancelFunc)
	}
	s.activeID++
	activeID := s.activeID
	s.active[activeID] = cancel
	s.activeMu.Unlock()
	return ctx, func() {
		s.activeMu.Lock()
		delete(s.active, activeID)
		s.activeMu.Unlock()
		cancel()
	}, nil
}

// activeCancels returns the cancel of every active operation; closing also
// marks the session closing in the same step, so none begins after.
func (s *Session) activeCancels(closing bool) []context.CancelFunc {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if closing {
		s.closing = true
	}
	cancels := make([]context.CancelFunc, 0, len(s.active))
	for _, cancel := range s.active {
		cancels = append(cancels, cancel)
	}
	return cancels
}

// startable reports, under execMu, why an operation on ctx must not run:
// Shutdown began or finished, or cancelled ctx while it waited for execMu.
func (s *Session) startable(ctx context.Context) error {
	if s.state == nil || s.isClosing() {
		return errSessionShutDown
	}
	return ctx.Err()
}

func (s *Session) isClosing() bool {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	return s.closing
}

// bindCommandContext runs what follows, until the returned restore, on ctx:
// the command context commands read and the signer client's requests.
func (r *REPLState) bindCommandContext(ctx context.Context) (restore func()) {
	cleanupSignerCtx := r.app().BindSignerClientContext(ctx)
	priorCtx := r.currentCommandCtx
	r.currentCommandCtx = ctx
	return func() {
		r.currentCommandCtx = priorCtx
		cleanupSignerCtx()
	}
}

// Cancel interrupts the executing embedded command, and any line waiting to
// run after it. It reports whether there was one.
func (s *Session) Cancel() bool {
	if s == nil {
		return false
	}
	cancels := s.activeCancels(false)
	for _, cancel := range cancels {
		cancel()
	}
	return len(cancels) > 0
}

// Shutdown releases apshell runtime resources owned by the session. It
// cancels every active operation, the running one and any waiting, and waits
// for the running one to return first: it still uses the runtime, and the
// state, while it unwinds.
func (s *Session) Shutdown() {
	if s == nil {
		return
	}
	for _, cancel := range s.activeCancels(true) {
		cancel()
	}
	s.execMu.Lock()
	defer s.execMu.Unlock()
	if s.state == nil {
		return
	}
	if s.stopPolling != nil {
		s.stopPolling()
		s.stopPolling = nil
	}
	shutdownRuntime(s.state)
	s.state = nil
}
