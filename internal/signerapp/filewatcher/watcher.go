// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package filewatcher

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/keys"

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

	if watchCount == 0 {
		_ = watcher.Close()
		return fmt.Errorf("no directories available to watch")
	}

	infof(opts, "file watcher enabled (%d directories) - keys and key types will auto-reload", watchCount)

	// Keep the full list so we can add newly created directories.
	pendingDirs := make(map[string]bool)
	for _, dir := range dirs {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			pendingDirs[dir] = true
		}
	}

	go func() {
		var debounceTimer *time.Timer
		defer func() {
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			_ = watcher.Close()
		}()

		const debounceDelay = 500 * time.Millisecond

		for {
			select {
			case <-ctx.Done():
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// If a pending directory was just created, start watching it.
				if event.Op&fsnotify.Create != 0 {
					if pendingDirs[event.Name] {
						if addErr := watcher.Add(event.Name); addErr == nil {
							delete(pendingDirs, event.Name)
							infof(opts, "now watching newly created directory: %s", event.Name)
						}
					}
				}

				// Only react to key files and key type template files. Key type
				// state records (.json) are admin-mutated under the per-identity
				// mutation lock; reacting to them would race the same admin
				// handlers that wrote them.
				if !isReloadCandidate(event.Name) {
					continue
				}

				if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
					if debounceTimer != nil {
						debounceTimer.Stop()
					}

					debounceTimer = time.AfterFunc(debounceDelay, func() {
						if ctx.Err() != nil {
							return
						}
						if err := reloadFn(); err != nil {
							warnf(opts, "error reloading keys/templates: %v", err)
						}
					})
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				warnf(opts, "file watcher error: %v", err)
			}
		}
	}()

	return nil
}

func isReloadCandidate(path string) bool {
	return strings.HasSuffix(path, keys.AccountKeyExtension) ||
		strings.HasSuffix(path, keys.SentryCredentialExtension) ||
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
