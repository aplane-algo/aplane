// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package filewatcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/storepaths"

	"github.com/fsnotify/fsnotify"
)

type Logf func(format string, args ...interface{})

type Options struct {
	Infof Logf
	Warnf Logf
}

// Start watches dirs for managed credentials and .template changes and calls
// reloadFn after a short debounce window.
func Start(dirs []string, ctx context.Context, reloadFn func() error, opts Options) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	watchCount := watchExistingDirs(watcher, dirs, opts)
	if watchCount == 0 {
		_ = watcher.Close()
		return fmt.Errorf("no directories available to watch")
	}

	infof(opts, "file watcher enabled (%d directories) - keys and key types will auto-reload", watchCount)

	loop := &reloadLoop{
		watcher:     watcher,
		pendingDirs: missingDirs(dirs),
		reloadFn:    reloadFn,
		opts:        opts,
		delay:       debounceDelay,
	}
	go loop.run(ctx)

	return nil
}

// watchExistingDirs adds each directory that exists to the watcher and returns
// how many it is watching.
func watchExistingDirs(watcher *fsnotify.Watcher, dirs []string, opts Options) int {
	watchCount := 0
	for _, dir := range dirs {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			continue // Directory doesn't exist yet; may be added dynamically
		}
		if addErr := watcher.Add(dir); addErr != nil {
			warnf(opts, "failed to watch directory %s: %v", dir, addErr)
			continue
		}
		watchCount++
	}
	return watchCount
}

// missingDirs is the directories that do not exist yet, kept so the loop can
// watch each one when it is created.
func missingDirs(dirs []string) map[string]bool {
	pending := make(map[string]bool)
	for _, dir := range dirs {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			pending[dir] = true
		}
	}
	return pending
}

const debounceDelay = 500 * time.Millisecond

// reloadLoop turns watcher events into debounced reloads until its context
// ends or the watcher closes.
type reloadLoop struct {
	watcher       *fsnotify.Watcher
	pendingDirs   map[string]bool
	reloadFn      func() error
	opts          Options
	delay         time.Duration
	debounceTimer *time.Timer
}

func (l *reloadLoop) run(ctx context.Context) {
	defer func() {
		if l.debounceTimer != nil {
			l.debounceTimer.Stop()
		}
		_ = l.watcher.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-l.watcher.Events:
			if !ok {
				return
			}
			l.handleEvent(ctx, event)

		case err, ok := <-l.watcher.Errors:
			if !ok {
				return
			}
			warnf(l.opts, "file watcher error: %v", err)
		}
	}
}

func (l *reloadLoop) handleEvent(ctx context.Context, event fsnotify.Event) {
	l.watchIfPending(event)

	// Only react to key files and key type template files. Key type
	// state records (.json) are admin-mutated under the product-store
	// mutation lock; reacting to them would race the same admin
	// handlers that wrote them.
	if !isReloadCandidate(event.Name) {
		return
	}
	if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) == 0 {
		return
	}

	if l.debounceTimer != nil {
		l.debounceTimer.Stop()
	}
	l.debounceTimer = time.AfterFunc(l.delay, func() {
		if ctx.Err() != nil {
			return
		}
		if err := l.reloadFn(); err != nil {
			warnf(l.opts, "error reloading keys/templates: %v", err)
		}
	})
}

// watchIfPending starts watching a pending directory that was just created.
func (l *reloadLoop) watchIfPending(event fsnotify.Event) {
	if event.Op&fsnotify.Create == 0 || !l.pendingDirs[event.Name] {
		return
	}
	if addErr := l.watcher.Add(event.Name); addErr == nil {
		delete(l.pendingDirs, event.Name)
		infof(l.opts, "now watching newly created directory: %s", event.Name)
	}
}

// isReloadCandidate reports whether a change to path should reload keys:
// managed credentials, templates, and the store root. Source token files
// (source_tokens/*.enc) are deliberately not candidates, and their directory
// is not watched: the daemon is their only writer and publishes the token
// index itself after each write.
func isReloadCandidate(path string) bool {
	// Store-root replacement commits a new generation of the active
	// namespaces; the reload it triggers re-resolves the layout.
	if filepath.Base(path) == storepaths.StoreRootName {
		return true
	}
	return strings.HasSuffix(path, keys.AccountKeyExtension) ||
		strings.HasSuffix(path, keys.CosignerCredentialExtension) ||
		strings.HasSuffix(path, ".template")
}

func infof(opts Options, format string, args ...interface{}) {
	if opts.Infof != nil {
		opts.Infof(format, args...)
	}
}

func warnf(opts Options, format string, args ...interface{}) {
	if opts.Warnf != nil {
		opts.Warnf(format, args...)
	}
}
