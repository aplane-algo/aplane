// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bytes"
	"slices"
	"sync"
	"testing"
)

func TestCacheWarningsHeldForPaneAndWrittenToStderr(t *testing.T) {
	var stderr bytes.Buffer
	warnings := newCacheWarnings(&stderr)

	warnings.add("SECURITY: alias cache may have been tampered with")

	want := "[cache] warning: SECURITY: alias cache may have been tampered with"
	if got := warnings.takeStartup(); !slices.Equal(got, []string{want}) {
		t.Fatalf("takeStartup() = %q, want %q", got, want)
	}
	if got := stderr.String(); got != want+"\n" {
		t.Fatalf("stderr = %q, want the warning for failed startups", got)
	}
	if got := warnings.takeStartup(); len(got) != 0 {
		t.Fatalf("second takeStartup() = %q, want nothing", got)
	}
}

func TestCacheWarningsDeliveredLiveAfterAttach(t *testing.T) {
	var stderr bytes.Buffer
	warnings := newCacheWarnings(&stderr)
	warnings.add("before startup was taken")
	warnings.takeStartup()
	warnings.add("between take and attach")
	stderr.Reset()

	var delivered []string
	warnings.attach(func(line string) { delivered = append(delivered, line) })
	warnings.add("during the session")

	want := []string{
		"[cache] warning: between take and attach",
		"[cache] warning: during the session",
	}
	if !slices.Equal(delivered, want) {
		t.Fatalf("delivered = %q, want %q", delivered, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("live warning reached stderr, which is /dev/null during the TUI: %q", stderr.String())
	}
}

func TestCacheWarningsEscapeTerminalControls(t *testing.T) {
	var stderr bytes.Buffer
	warnings := newCacheWarnings(&stderr)

	warnings.add("failed to load \x1b[2Jcache")

	want := `[cache] warning: failed to load \x1b[2Jcache`
	if got := warnings.takeStartup(); !slices.Equal(got, []string{want}) {
		t.Fatalf("takeStartup() = %q, want %q", got, want)
	}
}

func TestCacheWarningsConcurrentWithAttach(t *testing.T) {
	var stderr bytes.Buffer
	warnings := newCacheWarnings(&stderr)

	var mu sync.Mutex
	count := 0
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			warnings.add("warning")
		}()
	}
	warnings.attach(func(string) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	wg.Wait()

	if count != 8 {
		t.Fatalf("delivered %d warnings, want 8", count)
	}
}
