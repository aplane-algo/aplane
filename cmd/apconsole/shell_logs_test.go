// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/clientlog"
)

func queuedLogs(t *testing.T, lines ...string) *clientlog.Deferred {
	t.Helper()
	logs := clientlog.NewDeferred()
	for _, line := range lines {
		if err := logs.WriteRecord(clientlog.Record{Level: slog.LevelWarn, Line: line}); err != nil {
			t.Fatalf("WriteRecord() error = %v", err)
		}
	}
	return logs
}

func shellWithLogs(logs logSource) shellModel {
	m := newShellModel(&fakeShellExecutor{}, []string{"Ready."})
	m.logs = logs
	return m
}

func TestShellPaneStoresAndAcknowledgesLogBatches(t *testing.T) {
	logs := queuedLogs(t, "[cache] warning: first", "[cache] warning: second")
	m := shellWithLogs(logs)

	msg := pullShellLogs(logs)()
	updated, next := m.Update(msg)

	if !slices.Contains(updated.lines, "[cache] warning: first") || !slices.Contains(updated.lines, "[cache] warning: second") {
		t.Fatalf("lines = %q", updated.lines)
	}
	if next == nil {
		t.Fatal("the pane stopped pulling")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := logs.Flush(ctx); err != nil {
		t.Fatalf("Flush() error = %v; the batch wasn't acknowledged", err)
	}
}

func TestShellPaneShowsLossMarkers(t *testing.T) {
	logs := &fakeLogSource{}
	m := shellWithLogs(logs)

	updated, _ := m.Update(shellLogBatchMsg{batch: clientlog.Batch{ID: 7, Lost: 2, LostWarnings: 1}})

	for _, want := range []string{"[aplane] warning: 1 warnings dropped", "[aplane] 2 log lines dropped"} {
		if !slices.Contains(updated.lines, want) {
			t.Fatalf("lines = %q, want %q", updated.lines, want)
		}
	}
	if !slices.Equal(logs.acked, []uint64{7}) {
		t.Fatalf("acked = %v", logs.acked)
	}
}

type fakeLogSource struct {
	acked    []uint64
	flushed  int
	flushErr error
	onFlush  func()
}

func (s *fakeLogSource) Next(context.Context) (clientlog.Batch, bool) {
	return clientlog.Batch{}, false
}
func (s *fakeLogSource) Ack(id uint64) { s.acked = append(s.acked, id) }
func (s *fakeLogSource) Flush(context.Context) error {
	s.flushed++
	if s.onFlush != nil {
		s.onFlush()
	}
	return s.flushErr
}

func TestCommandsFlushLogsBeforeReturningTheirResult(t *testing.T) {
	failure := errors.New("plugin crashed")

	t.Run("shell line", func(t *testing.T) {
		logs := &fakeLogSource{}
		exec := &fakeShellExecutor{execErr: failure}
		msg, ok := executeShellLine(exec, logs, "mithras")().(shellExecMsg)
		if !ok || !errors.Is(msg.err, failure) {
			t.Fatalf("message = %#v", msg)
		}
		if logs.flushed != 1 {
			t.Fatalf("flushed %d times, want the barrier", logs.flushed)
		}
	})

	t.Run("startup connect", func(t *testing.T) {
		logs := &fakeLogSource{}
		msg, ok := startupConnectShell(&fakeShellExecutor{}, logs)().(shellStartupConnectMsg)
		if !ok {
			t.Fatalf("message = %#v", msg)
		}
		if logs.flushed != 1 {
			t.Fatalf("flushed %d times, want the barrier", logs.flushed)
		}
	})

	t.Run("a flush failure keeps the command's result", func(t *testing.T) {
		logs := &fakeLogSource{flushErr: context.DeadlineExceeded}
		msg := executeShellLine(&fakeShellExecutor{execErr: failure}, logs, "x")().(shellExecMsg)
		if !errors.Is(msg.err, failure) {
			t.Fatalf("err = %v, want the command's own error", msg.err)
		}
	})
}

func TestShellWithoutLogQueueStillWorks(t *testing.T) {
	if pullShellLogs(nil) != nil {
		t.Fatal("pullShellLogs(nil) should issue no command")
	}
	flushShellLogs(nil)
}

func TestDisabledShellLeavesLogsForTheExitFallback(t *testing.T) {
	logs := queuedLogs(t, "[transport] warning: dropped")
	m := newModelWithShell(testConnector{}, "", &fakeShellExecutor{}, nil, daemonModel{}, false, "")
	m.shell.logs = logs

	if cmd := m.Init(); cmd == nil {
		t.Fatal("Init() returned nil")
	}
	var out bytes.Buffer
	if err := logs.Close(&out); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !strings.Contains(out.String(), "[transport] warning: dropped") {
		t.Fatalf("out = %q, the record was consumed by a hidden pane", out.String())
	}
}

func TestLogBatchReachesTheShellThroughTheConsoleModel(t *testing.T) {
	logs := queuedLogs(t, "[ssh] warning: connection lost")
	m := newModelWithShell(testConnector{}, "", &fakeShellExecutor{}, nil, daemonModel{}, true, "")
	m.shell.logs = logs

	updated, _ := m.Update(pullShellLogs(logs)())

	if !slices.Contains(updated.(model).shell.lines, "[ssh] warning: connection lost") {
		t.Fatalf("lines = %q", updated.(model).shell.lines)
	}
}

var _ tea.Msg = shellLogBatchMsg{}
