// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"

	"github.com/fsnotify/fsnotify"
)

// startKeyWatcher starts a file system watcher for the keys directory and optionally the passphrase file.
// It automatically reloads keys when .key or .template files are created, modified, or deleted.
// If passphraseFile is set, it also watches that file and reloads the passphrase when it changes.
func startKeyWatcher(server *Signer, ctx context.Context, passphraseFile string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// Add the identity-scoped keys subdirectory to the watcher
	if err := watcher.Add(utilkeys.KeysDir(auth.DefaultIdentityID)); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("failed to watch keys directory: %w", err)
	}

	// Optionally watch passphrase file
	var watchedPassphraseFile string
	if passphraseFile != "" {
		// Watch the directory containing the passphrase file (fsnotify watches directories)
		passphraseDir := filepath.Dir(passphraseFile)
		if err := watcher.Add(passphraseDir); err != nil {
			fmt.Printf("⚠️  Warning: Cannot watch passphrase file directory: %v\n", err)
		} else {
			watchedPassphraseFile = passphraseFile
			fmt.Printf("✓ Watching passphrase file for changes: %s\n", passphraseFile)
		}
	}

	fmt.Println("✓ File watcher enabled - keys will auto-reload on filesystem changes")

	// Start watching in a goroutine
	go func() {
		defer func() { _ = watcher.Close() }()

		// Debounce timers to avoid rapid reloads
		var keyDebounceTimer *time.Timer
		var passDebounceTimer *time.Timer
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

				// Check if this is the passphrase file
				if watchedPassphraseFile != "" && event.Name == watchedPassphraseFile {
					if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
						// Reset debounce timer for passphrase reload
						if passDebounceTimer != nil {
							passDebounceTimer.Stop()
						}

						passDebounceTimer = time.AfterFunc(debounceDelay, func() {
							fmt.Println("🔄 Passphrase file changed, reloading...")
							if err := server.reloadPassphraseFile(watchedPassphraseFile); err != nil {
								fmt.Printf("⚠️  Error reloading passphrase: %v\n", err)
							} else {
								fmt.Println("✓ Passphrase reloaded successfully")
							}
						})
					}
					continue
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

// reloadPassphraseFile reads the new passphrase from the file and updates the server.
// After updating the passphrase, it reloads all keys with the new passphrase.
func (fs *Signer) reloadPassphraseFile(path string) error {
	// Read new passphrase from file as bytes for secure handling
	newPassphrase, err := util.ReadPassphraseFileBytes(path)
	if err != nil {
		return fmt.Errorf("failed to read passphrase file: %w", err)
	}
	defer crypto.ZeroBytes(newPassphrase)

	// Verify the new passphrase against the control file
	if err := crypto.VerifyPassphraseWithMetadata(newPassphrase, utilkeys.KeystorePath()); err != nil {
		return fmt.Errorf("new passphrase verification failed: %w", err)
	}

	// Update the encryption passphrase and reload keys under write lock
	fs.passphraseLock.Lock()
	if fs.encryptionPassphrase != nil {
		fs.encryptionPassphrase.Destroy()
	}
	fs.encryptionPassphrase = crypto.NewSecureStringFromBytes(newPassphrase)

	// Update the key session with the new passphrase
	fs.keySession.InitializeSession(newPassphrase)

	// Reload keys with the new passphrase (caller holds passphraseLock)
	err = fs.reloadKeysLocked()
	fs.passphraseLock.Unlock()
	if err != nil {
		return fmt.Errorf("failed to reload keys with new passphrase: %w", err)
	}

	return nil
}
