// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storelock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAcquireExclusiveBlockedBySharedLock(t *testing.T) {
	dir := t.TempDir()

	shared, err := AcquireShared(dir)
	if err != nil {
		t.Fatalf("AcquireShared() error = %v", err)
	}
	defer func() { _ = shared.Close() }()

	exclusive, err := AcquireExclusive(dir)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("AcquireExclusive() error = %v, want ErrBusy", err)
	}
	if exclusive != nil {
		t.Fatal("AcquireExclusive() returned guard while shared lock held")
	}
}

func TestGuardReportsExclusiveDataDirectory(t *testing.T) {
	dir := t.TempDir()
	exclusive, err := AcquireExclusive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !exclusive.HoldsExclusiveFor(dir) {
		t.Fatal("exclusive guard does not report its data directory")
	}
	if exclusive.HoldsExclusiveFor(t.TempDir()) {
		t.Fatal("exclusive guard reports a different data directory")
	}
	if err := exclusive.Close(); err != nil {
		t.Fatal(err)
	}
	if exclusive.HoldsExclusiveFor(dir) {
		t.Fatal("closed guard still reports an exclusive lock")
	}

	shared, err := AcquireShared(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shared.Close() }()
	if shared.HoldsExclusiveFor(dir) {
		t.Fatal("shared guard reports an exclusive lock")
	}
}

func TestAcquireExclusiveRejectsSymlinkLock(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireExclusive(dir); err == nil {
		t.Fatal("AcquireExclusive() accepted symlink lock")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside changed: %q, %v", data, err)
	}
}

func TestAcquireExclusiveRejectsHardlinkedLockBeforeChmod(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(t.TempDir(), "original")
	if err := os.WriteFile(original, []byte("unchanged"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireExclusive(dir); err == nil || !strings.Contains(err.Error(), "exactly one link") {
		t.Fatalf("AcquireExclusive() error = %v, want hardlink rejection", err)
	}
	info, err := os.Stat(original)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("hardlink target mode changed to %04o", info.Mode().Perm())
	}
}
