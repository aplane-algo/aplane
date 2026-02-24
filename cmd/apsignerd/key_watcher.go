// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	"github.com/fsnotify/fsnotify"
)

// startKeyWatcher starts a file system watcher for the keys directory.
// It automatically reloads keys when .key or .template files are created, modified, or deleted.
func startKeyWatcher(server *Signer, ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Add the identity-scoped keys subdirectory to the watcher
	if err := watcher.Add(utilkeys.KeysDir(auth.DefaultIdentityID)); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("failed to watch keys directory: %w", err)
	}

	fmt.Println("✓ File watcher enabled - keys will auto-reload on filesystem changes")

	// Start watching in a goroutine
	go func() {
		defer func() { _ = watcher.Close() }()

		// Debounce timer to avoid rapid reloads
		var keyDebounceTimer *time.Timer
		const debounceDelay = 500 * time.Millisecond

		for {
			select {
			case <-ctx.Done():
				// Shutdown signal received
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Only react to .key and .template files for reloading
				if !strings.HasSuffix(event.Name, ".key") && !strings.HasSuffix(event.Name, ".template") {
					continue
				}

				// React to Create, Write, Remove, and Rename events
				if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Remove|fsnotify.Rename) != 0 {
					// Reset debounce timer
					if keyDebounceTimer != nil {
						keyDebounceTimer.Stop()
					}

					keyDebounceTimer = time.AfterFunc(debounceDelay, func() {
						if err := server.reloadKeys(); err != nil {
							fmt.Printf("⚠️  Error reloading keys: %v\n", err)
						}
					})
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("⚠️  File watcher error: %v\n", err)
			}
		}
	}()

	return nil
}
