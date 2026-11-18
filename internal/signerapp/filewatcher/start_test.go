// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package filewatcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// messages records what a watcher logs.
type messages struct {
	mu   sync.Mutex
	info []string
	warn []string
}

func (m *messages) options() Options {
	return Options{
		Infof: func(format string, args ...interface{}) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.info = append(m.info, fmt.Sprintf(format, args...))
		},
		Warnf: func(format string, args ...interface{}) {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.warn = append(m.warn, fmt.Sprintf(format, args...))
		},
	}
}

func (m *messages) snapshot() (info, warn []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.info...), append([]string(nil), m.warn...)
}

// eventually polls until check passes. It never fails for being early, only
// for a condition that does not come within five seconds.
func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// testLoop is a reload loop on a real, empty watcher. With an hour's delay a
// scheduled reload never fires during a test, so what handleEvent scheduled
// can be read from the timer without waiting on it.
func testLoop(t *testing.T, delay time.Duration, reloadFn func() error, opts Options) *reloadLoop {
	t.Helper()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	return &reloadLoop{watcher: watcher, pendingDirs: map[string]bool{}, reloadFn: reloadFn, opts: opts, delay: delay}
}

func noReload() error { return nil }

func TestHandleEventSchedulesOnlyForCandidateChanges(t *testing.T) {
	tests := []struct {
		name string
		file string
		op   fsnotify.Op
		want bool
	}{
		{"key created", "account.key", fsnotify.Create, true},
		{"key written", "account.key", fsnotify.Write, true},
		{"key removed", "account.key", fsnotify.Remove, true},
		{"key renamed", "account.key", fsnotify.Rename, true},
		{"key written and chmodded", "account.key", fsnotify.Write | fsnotify.Chmod, true},
		{"key chmodded only", "account.key", fsnotify.Chmod, false},
		{"cosigner credential written", "cosigner.cos", fsnotify.Write, true},
		{"template written", "policy.template", fsnotify.Write, true},
		{"store root replaced", storepaths.StoreRootName, fsnotify.Create, true},
		{"state record written", "state.json", fsnotify.Write, false},
		{"cosigner state record written", "cosigner.cos.json", fsnotify.Write, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loop := testLoop(t, time.Hour, noReload, Options{})
			loop.handleEvent(context.Background(), fsnotify.Event{Name: filepath.Join("keys", tt.file), Op: tt.op})
			scheduled := loop.debounceTimer != nil
			if scheduled {
				loop.debounceTimer.Stop()
			}
			if scheduled != tt.want {
				t.Fatalf("reload scheduled = %v, want %v", scheduled, tt.want)
			}
		})
	}
}

// A burst of changes leaves one pending reload: each event stops the timer
// before it and starts its own.
func TestHandleEventDebouncesABurst(t *testing.T) {
	loop := testLoop(t, time.Hour, noReload, Options{})
	event := fsnotify.Event{Name: "account.key", Op: fsnotify.Write}

	var previous *time.Timer
	for i := range 5 {
		loop.handleEvent(context.Background(), event)
		if loop.debounceTimer == nil || loop.debounceTimer == previous {
			t.Fatalf("event %d did not start a new timer", i)
		}
		if previous != nil && previous.Stop() {
			t.Fatalf("event %d left the timer before it pending", i)
		}
		previous = loop.debounceTimer
	}
	if !loop.debounceTimer.Stop() {
		t.Fatal("the last event's reload is not pending")
	}
}

func TestDebouncedReloadRunsAndWarnsOnFailure(t *testing.T) {
	var reloads atomic.Int32
	var log messages
	loop := testLoop(t, time.Millisecond, func() error {
		reloads.Add(1)
		return errors.New("store is damaged")
	}, log.options())

	loop.handleEvent(context.Background(), fsnotify.Event{Name: "account.key", Op: fsnotify.Write})
	eventually(t, "the failed reload's warning", func() bool {
		_, warn := log.snapshot()
		return len(warn) == 1
	})
	if _, warn := log.snapshot(); warn[0] != "error reloading keys/templates: store is damaged" {
		t.Fatalf("warning = %q", warn[0])
	}
	if got := reloads.Load(); got != 1 {
		t.Fatalf("reloads = %d, want 1", got)
	}
}

// A reload whose debounce ends after the context has ended does not run.
func TestDebouncedReloadIsSkippedOnceTheContextEnds(t *testing.T) {
	var reloads atomic.Int32
	loop := testLoop(t, time.Millisecond, func() error { reloads.Add(1); return nil }, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	loop.handleEvent(ctx, fsnotify.Event{Name: "account.key", Op: fsnotify.Write})
	time.Sleep(200 * time.Millisecond)
	if got := reloads.Load(); got != 0 {
		t.Fatalf("reloads after the context ended = %d, want 0", got)
	}
}

func TestWatchIfPendingWatchesADirectoryOnceItExists(t *testing.T) {
	var log messages
	loop := testLoop(t, time.Hour, noReload, log.options())
	later := filepath.Join(t.TempDir(), "keys")
	loop.pendingDirs[later] = true
	created := fsnotify.Event{Name: later, Op: fsnotify.Create}

	// The watcher cannot add a directory that is not there: it stays pending.
	loop.watchIfPending(created)
	if !loop.pendingDirs[later] {
		t.Fatal("a directory the watcher could not add stopped being pending")
	}
	if err := os.Mkdir(later, 0o700); err != nil {
		t.Fatal(err)
	}
	// Only its creation, and only its own name, starts the watch.
	loop.watchIfPending(fsnotify.Event{Name: later, Op: fsnotify.Write})
	loop.watchIfPending(fsnotify.Event{Name: later + "-other", Op: fsnotify.Create})
	if info, _ := log.snapshot(); !loop.pendingDirs[later] || len(info) != 0 {
		t.Fatalf("pending = %v, info = %q; want still pending and silent", loop.pendingDirs[later], info)
	}

	loop.watchIfPending(created)
	info, _ := log.snapshot()
	if loop.pendingDirs[later] || len(info) != 1 || info[0] != "now watching newly created directory: "+later {
		t.Fatalf("pending = %v, info = %q; want watched and announced", loop.pendingDirs[later], info)
	}
}

func TestSetupCountsExistingDirectoriesAndRemembersMissingOnes(t *testing.T) {
	existing := t.TempDir()
	missing := filepath.Join(existing, "missing")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watcher.Close() }()

	var log messages
	if got := watchExistingDirs(watcher, []string{existing, missing}, log.options()); got != 1 {
		t.Fatalf("watchExistingDirs() = %d, want 1", got)
	}
	if _, warn := log.snapshot(); len(warn) != 0 {
		t.Fatalf("warnings = %q, want none for a directory that is only missing", warn)
	}
	pending := missingDirs([]string{existing, missing})
	if len(pending) != 1 || !pending[missing] {
		t.Fatalf("missingDirs() = %v, want only %s", pending, missing)
	}
}

// run reports a watcher error, and when its context ends it returns and
// closes the watcher.
func TestRunWarnsOnWatcherErrorsAndClosesTheWatcher(t *testing.T) {
	var log messages
	loop := testLoop(t, time.Hour, noReload, log.options())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		loop.run(ctx)
		close(done)
	}()

	loop.watcher.Errors <- errors.New("queue overflow")
	eventually(t, "the watcher error's warning", func() bool {
		_, warn := log.snapshot()
		return len(warn) == 1
	})
	if _, warn := log.snapshot(); warn[0] != "file watcher error: queue overflow" {
		t.Fatalf("warning = %q", warn[0])
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return when its context ended")
	}
	if err := loop.watcher.Add(t.TempDir()); err == nil {
		t.Fatal("the watcher is still open after run returned")
	}
}

// The tests below run Start on the real watcher. They wait for something to
// happen and never assert how soon, so a slow machine cannot fail them.

func startWatcher(t *testing.T, dirs []string, opts Options) *atomic.Int32 {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var reloads atomic.Int32
	if err := Start(dirs, ctx, func() error { reloads.Add(1); return nil }, opts); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	return &reloads
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStartReloadsAfterAKeyChange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	reloads := startWatcher(t, []string{dir}, Options{})

	writeFile(t, filepath.Join(dir, "account.key"))
	eventually(t, "a reload after a key change", func() bool { return reloads.Load() >= 1 })
}

func TestStartIgnoresFilesThatAreNotReloadCandidates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	reloads := startWatcher(t, []string{dir}, Options{})

	// Well past the debounce window: no reload now means none is coming.
	writeFile(t, filepath.Join(dir, "state.json"))
	time.Sleep(2 * debounceDelay)
	if got := reloads.Load(); got != 0 {
		t.Fatalf("reloads for a .json file = %d, want 0", got)
	}
}

func TestStartWatchesADirectoryCreatedLater(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	later := filepath.Join(dir, "keys")
	var log messages
	reloads := startWatcher(t, []string{dir, later}, log.options())

	if err := os.Mkdir(later, 0o700); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new directory to be watched", func() bool {
		info, _ := log.snapshot()
		return len(info) == 2
	})
	writeFile(t, filepath.Join(later, "account.key"))
	eventually(t, "a reload for a key in the new directory", func() bool { return reloads.Load() >= 1 })

	info, _ := log.snapshot()
	want := []string{
		"file watcher enabled (1 directories) - keys and key types will auto-reload",
		"now watching newly created directory: " + later,
	}
	if info[0] != want[0] || info[1] != want[1] {
		t.Fatalf("info = %q, want %q", info, want)
	}
}

func TestStartFailsWithNoDirectoryToWatch(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing")
	err := Start([]string{missing}, context.Background(), noReload, Options{})
	if err == nil || err.Error() != "no directories available to watch" {
		t.Fatalf("Start() error = %v, want no directories available to watch", err)
	}
}
