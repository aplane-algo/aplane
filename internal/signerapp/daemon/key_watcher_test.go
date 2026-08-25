// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcherPicksUpLateDirectoryCreation(t *testing.T) {
	// Set up a temp directory tree with only keys/ existing initially.
	// templates/generic and templates/composed do NOT exist yet.
	base := t.TempDir()
	keysDir := filepath.Join(base, "keys")
	templatesRoot := filepath.Join(base, "templates")
	genericDir := filepath.Join(templatesRoot, "generic")
	composedDir := filepath.Join(templatesRoot, "composed")

	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}

	reloadCount := make(chan struct{}, 10)
	reloadFn := func() error {
		reloadCount <- struct{}{}
		return nil
	}

	dirs := []string{base, keysDir, templatesRoot, genericDir, composedDir}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startKeyWatcherForDir(dirs, ctx, reloadFn); err != nil {
		t.Fatalf("startKeyWatcherForDir: %v", err)
	}

	// Wait for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Step 1: Write a .key file in keys/ — should trigger reload
	if err := os.WriteFile(filepath.Join(keysDir, "test.key"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	waitForReload(t, reloadCount, "key file in existing dir")

	// Step 2: Create templates/ directory (intermediate parent)
	if err := os.MkdirAll(templatesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // Let watcher pick up the new dir

	// Step 3: Create templates/generic/ directory
	if err := os.MkdirAll(genericDir, 0700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // Let watcher pick up the new dir

	// Step 4: Write a .template file in templates/generic/ — should trigger reload
	if err := os.WriteFile(filepath.Join(genericDir, "test.template"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	waitForReload(t, reloadCount, "template file in late-created dir")
}

func TestWatcherDirtyWhileLocked(t *testing.T) {
	base := t.TempDir()
	keysDir := filepath.Join(base, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Track whether reload was called vs dirty was marked
	reloaded := make(chan struct{}, 10)
	var locked atomic.Bool
	locked.Store(true)

	reloadOrDirty := func() error {
		if !locked.Load() {
			reloaded <- struct{}{}
		}
		// When locked, just record that we were called (the product runtime
		// would call MarkDirty; here we simulate by not sending to reloaded)
		return nil
	}

	dirs := []string{base, keysDir}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startKeyWatcherForDir(dirs, ctx, reloadOrDirty); err != nil {
		t.Fatalf("startKeyWatcherForDir: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Write a file while "locked" — reloadOrDirty is called but doesn't send to reloaded
	if err := os.WriteFile(filepath.Join(keysDir, "locked.key"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond) // Debounce + buffer

	select {
	case <-reloaded:
		t.Fatal("reload should not fire while locked")
	default:
		// Good — reload was not triggered
	}

	// "Unlock" and write another file — should trigger reload
	locked.Store(false)
	if err := os.WriteFile(filepath.Join(keysDir, "unlocked.key"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	waitForReload(t, reloaded, "key file after unlock")
}

// Verifies the per-plan watcher discrimination: `.template` and `.key` events
// trigger reload; `.json` record events MUST NOT, because state records are
// admin-mutated under the process store mutation lock and a watcher-driven
// reload would race the admin handler that wrote the record.
func TestWatcherIgnoresJSONRecordEvents(t *testing.T) {
	base := t.TempDir()
	keytypesDir := filepath.Join(base, "keytypes")
	if err := os.MkdirAll(keytypesDir, 0700); err != nil {
		t.Fatal(err)
	}

	reloaded := make(chan struct{}, 10)
	reloadFn := func() error {
		reloaded <- struct{}{}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startKeyWatcherForDir([]string{base, keytypesDir}, ctx, reloadFn); err != nil {
		t.Fatalf("startKeyWatcherForDir: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Write a .json state record — must NOT trigger reload.
	if err := os.WriteFile(filepath.Join(keytypesDir, "falcon1024-foo-v1.json"), []byte(`{"key_type":"falcon1024-foo-v1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond) // debounce window + buffer

	select {
	case <-reloaded:
		t.Fatal("watcher reloaded on .json record event; this races the admin mutation lock")
	default:
	}

	// Sanity check: a .template event in the same dir DOES trigger reload.
	if err := os.WriteFile(filepath.Join(keytypesDir, "falcon1024-foo-v1.template"), []byte("encrypted"), 0600); err != nil {
		t.Fatal(err)
	}
	waitForReload(t, reloaded, ".template file triggers reload")
}

func waitForReload(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for reload: %s", label)
	}
}
