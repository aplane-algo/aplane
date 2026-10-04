// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
)

// A key write queued behind a generation commit must recheck the runtime
// under the mutation lock. If the commit failed and set recovery, the runtime
// may still be bound to the superseded, sealed generation, and writing there
// would lose the key and break that generation's seal.
func TestQueuedKeyWriteRefusesAfterRecovery(t *testing.T) {
	ir := setupProductRuntime(t)
	active, err := ir.ActivePaths()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	svc := Service{Runtime: ir, MutationLock: func() Locker { return &mu }}

	type outcome struct {
		result *GenerateResult
		err    *Error
	}
	done := make(chan outcome, 1)
	mu.Lock() // a generation commit holds the lock
	go func() {
		result, err := svc.GenerateKey(context.Background(), "ed25519", nil, nil)
		done <- outcome{result, err}
	}()
	time.Sleep(50 * time.Millisecond) // let the request queue on the lock
	ir.SetRecovery()                  // the commit's reload failed
	mu.Unlock()

	got := <-done
	if got.err == nil || got.err.Kind != ErrorLocked {
		t.Fatalf("queued GenerateKey() = (%+v, %+v), want a locked refusal", got.result, got.err)
	}
	entries, err := os.ReadDir(active.KeysDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("queued GenerateKey() wrote %d file(s) into the generation it was bound to", len(entries))
	}
}
