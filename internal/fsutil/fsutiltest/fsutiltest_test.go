// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package fsutiltest

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/fsutil"
)

// fatalTB records Hold's fatal message and cleanups instead of failing the
// real test.
type fatalTB struct {
	testing.TB
	fatal    chan string
	cleanups []func()
}

func (f *fatalTB) Helper()           {}
func (f *fatalTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fatalTB) Fatal(args ...any) { f.fatal <- fmt.Sprint(args...); runtime.Goexit() }
func (f *fatalTB) Fatalf(format string, args ...any) {
	f.fatal <- fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (f *fatalTB) runCleanups() {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

// An update that returns before its write reaches the held step fails the
// test at once with its own error. Hold once waited ten seconds and then said
// only that the write never got there.
func TestHoldFailsAtOnceWhenTheUpdateReturnsFirst(t *testing.T) {
	tb := &fatalTB{TB: t, fatal: make(chan string, 1)}
	defer tb.runCleanups()
	go func() {
		Hold(tb, fsutil.OpRename, "/never/written", func() error { return errors.New("refused before saving") })
	}()
	select {
	case msg := <-tb.fatal:
		if !strings.Contains(msg, "refused before saving") {
			t.Fatalf("fatal = %q, want the update's own error", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hold did not fail when the update returned before the held step")
	}
}

// Only the first matching write is held and given Finish's error; a later
// matching write in the same test goes through. The hook once returned the
// release error to every later matching write.
func TestHoldFailsOnlyTheHeldWrite(t *testing.T) {
	const path = "/held/file"
	injected := errors.New("injected")
	var later error
	h := Hold(t, fsutil.OpRename, path, func() error {
		return fsutil.TestHook(fsutil.OpRename, path)
	})
	if err := h.Finish(injected); !errors.Is(err, injected) {
		t.Fatalf("held write = %v, want the injected error", err)
	}
	later = fsutil.TestHook(fsutil.OpRename, path)
	if later != nil {
		t.Fatalf("a later matching write = %v, want it to go through", later)
	}
}
