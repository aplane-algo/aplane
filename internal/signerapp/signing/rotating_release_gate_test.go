// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signing

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A spend waits for its own account's audited release to be restored after
// an unlock, and for nothing else.
func TestReleaseMemoryRestoreGate(t *testing.T) {
	m := &ReleaseMemory{}
	// A memory that was never reset holds nobody.
	if err := m.AwaitRestored(context.Background(), "A"); err != nil {
		t.Fatal(err)
	}
	// Reset holds every account until the log has been read.
	m.Reset()
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := m.AwaitRestored(short, "A"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("armed memory did not hold: %v", err)
	}
	// Reading the log names the accounts still pending; the rest go free.
	waitA := make(chan error, 1)
	go func() { waitA <- m.AwaitRestored(context.Background(), "A") }()
	m.Restoring([]string{"A", "B"})
	if err := m.AwaitRestored(context.Background(), "C"); err != nil {
		t.Fatalf("account without audit history held: %v", err)
	}
	select {
	case err := <-waitA:
		t.Fatalf("pending account released early: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	m.Restored("B")
	select {
	case err := <-waitA:
		t.Fatalf("restoring B released A: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	m.Restored("A")
	if err := <-waitA; err != nil {
		t.Fatal(err)
	}
	// RestoredAll opens the wait whatever was pending, and a cancelled
	// request returns its own error instead of waiting.
	m.Reset()
	m.Restoring([]string{"A"})
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := m.AwaitRestored(cancelled, "A"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait = %v", err)
	}
	m.RestoredAll()
	if err := m.AwaitRestored(context.Background(), "A"); err != nil {
		t.Fatal(err)
	}
}

// Merging a long history stays linear: a release onto a stage with many
// prior releases costs a scan, not a quadratic rebuild.
func TestReleaseMemoryMergeIsLinear(t *testing.T) {
	m := &ReleaseMemory{}
	const n = 20000
	audited := make([]LeafRelease, 0, n)
	for i := range n {
		txid := "T" + itoa(i)
		audited = append(audited, LeafRelease{Index: uint32(i % 64), TxID: txid})
	}
	start := time.Now()
	m.RecordAudited(ReleaseRecord{Account: "A", Stage: 1, TxID: audited[n-1].TxID, Leaves: audited})
	for i := range 50 {
		m.Record(ReleaseRecord{Account: "A", Stage: 1, TxID: "L" + itoa(i), Leaves: []LeafRelease{{Index: 3, TxID: "L" + itoa(i)}}})
	}
	m.RecordAudited(ReleaseRecord{Account: "A", Stage: 1, TxID: audited[n-1].TxID, Leaves: audited})
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("merging %d leaves took %v", n, d)
	}
	rec, _ := m.Get("A")
	if len(rec.Leaves) != n+50 || !rec.Reused {
		t.Fatalf("merged %d leaves, reused %v", len(rec.Leaves), rec.Reused)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
