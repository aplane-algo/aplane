// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package storelock

import (
	"errors"
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
