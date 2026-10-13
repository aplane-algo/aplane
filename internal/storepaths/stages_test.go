// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storepaths

import (
	"path/filepath"
	"strings"
	"testing"
)

var testStageSelector = strings.Repeat("A", 58)

func TestStageTablePathsLiveBesideKeysOutsideGenerations(t *testing.T) {
	p := NewPaths("/data")
	want := filepath.Join("/data", "identities", "default", "stages")
	if got := p.StagesDir(); got != want {
		t.Fatalf("StagesDir() = %q, want %q", got, want)
	}
	got := p.StageTablePath(testStageSelector)
	if got != filepath.Join(want, testStageSelector+".stages") {
		t.Fatalf("StageTablePath() = %q", got)
	}
	if strings.Contains(got, "generations") || strings.Contains(got, string(filepath.Separator)+"keys"+string(filepath.Separator)) {
		t.Fatalf("stage table path %q must not live under generations or keys", got)
	}
}

func TestValidateStageSelector(t *testing.T) {
	if err := ValidateStageSelector(testStageSelector); err != nil {
		t.Fatalf("valid selector rejected: %v", err)
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 57), strings.Repeat("a", 58), strings.Repeat("A", 52), "../" + strings.Repeat("A", 55)} {
		if err := ValidateStageSelector(bad); err == nil {
			t.Errorf("selector %q accepted", bad)
		}
	}
}

func TestStageTablePathPanicsOnUnsafeSelector(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("unsafe selector did not panic")
		}
	}()
	NewPaths("/data").StageTablePath("../escape")
}
