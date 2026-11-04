// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cache

import (
	"bytes"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// captureLog sends the default logger to a buffer for one test. Everything is
// enabled, so a test sees debug records too.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	previous := slog.Default()
	flags := log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	var out bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &out
}

func TestLogRecordsNameTheComponent(t *testing.T) {
	out := captureLog(t)

	Debug("hit", "asset_id", 7)
	infof("loaded %d", 3)
	warnf("failed %s", "save")

	got := out.String()
	for _, want := range []string{
		"level=DEBUG msg=hit component=cache asset_id=7",
		`level=INFO msg="loaded 3" component=cache`,
		`level=WARN msg="failed save" component=cache`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log = %q, want %q", got, want)
		}
	}
}

// A logger kept from before the host installed its handler would bypass it, and
// warnings such as cache tampering would go to the wrong place.
func TestLoggerFollowsTheInstalledDefault(t *testing.T) {
	first := captureLog(t)
	warnf("to the first")

	second := captureLog(t)
	warnf("to the second")

	if strings.Contains(first.String(), "second") || !strings.Contains(second.String(), "second") {
		t.Fatalf("first = %q, second = %q", first.String(), second.String())
	}
}
