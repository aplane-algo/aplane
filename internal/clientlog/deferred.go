// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientlog

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

const (
	// deferredCapacity bounds the records held, including an outstanding batch.
	deferredCapacity = 256
	// deferredBatchSize bounds a batch, which leaves records that can be evicted
	// even while a batch is pinned.
	deferredBatchSize = 64
)

// Batch is a set of records for a full-screen interface to store. Lost and
// LostWarnings count what was dropped since the previous batch; a batch can hold
// only those counts.
type Batch struct {
	ID           uint64
	Records      []Record
	Lost         uint64
	LostWarnings uint64
}

// LossMarkers returns display lines for what the batch reports as dropped.
func (b Batch) LossMarkers() []string {
	return lossMarkers(b.Lost, b.LostWarnings)
}

func lossMarkers(ordinary, warnings uint64) []string {
	var lines []string
	if warnings > 0 {
		lines = append(lines, fmt.Sprintf("[%s] warning: %d warnings dropped", defaultComponent, warnings))
	}
	if ordinary > 0 {
		lines = append(lines, fmt.Sprintf("[%s] %d log lines dropped", defaultComponent, ordinary))
	}
	return lines
}

type sequencedRecord struct {
	Record
	sequence uint64
}

// lossCheckpoint counts dropped records and remembers the oldest one's sequence.
// Its size is fixed, so a flood costs no memory.
type lossCheckpoint struct {
	ordinary uint64
	warnings uint64
	oldest   uint64
}

func (l *lossCheckpoint) empty() bool {
	return l.ordinary == 0 && l.warnings == 0
}

func (l *lossCheckpoint) add(sequence uint64, level slog.Level) {
	if l.empty() || sequence < l.oldest {
		l.oldest = sequence
	}
	if level >= slog.LevelWarn {
		l.warnings++
	} else {
		l.ordinary++
	}
}

// clearOf reports that nothing lost at or before sequence is held here.
func (l *lossCheckpoint) clearOf(sequence uint64) bool {
	return l.empty() || l.oldest > sequence
}

// Deferred is a Sink for a full-screen interface. While the interface owns the
// terminal, nothing may write to it directly, and a log call may come from the
// interface's own update loop, so a writer can't wait for the display. Deferred
// holds records in a bounded queue for the interface to pull. It holds them from
// before the interface exists, so startup warnings aren't lost.
//
// Records leave in the order they arrived. When the queue is full, ordinary
// records are evicted before warnings, and every drop is counted and reported:
// this queue promises order and accounting, not that nothing is lost.
//
// A batch stays held until the interface acknowledges it, which means the
// interface has stored it, not that anyone read it. A batch the interface never
// received is therefore still here for Close to write out.
//
// There is one consumer: it calls Next, stores the batch, calls Ack, and repeats.
type Deferred struct {
	mu sync.Mutex
	// records is in sequence order. The first pinned belong to the batch.
	records []sequencedRecord
	pinned  int
	// lastSequence numbers every submission, including one rejected on arrival,
	// so a loss always has a place in the order.
	lastSequence uint64
	// pendingLoss hasn't been put in a batch. frozenLoss is in the outstanding
	// batch, whose acknowledgment clears it.
	pendingLoss lossCheckpoint
	frozenLoss  lossCheckpoint
	batchID     uint64 // outstanding batch, or 0
	lastBatchID uint64
	// changed is closed and replaced whenever a waiter might be able to proceed.
	changed chan struct{}

	// closed is set once Close has begun. closeDone closes when its writes end.
	closed    bool
	closeDone chan struct{}
	closeErr  error
	fallback  io.Writer

	// ioMu covers the writes after Close, which can block, so it is separate from
	// mu. Close holds it throughout, so a later write can't overtake the backlog.
	ioMu sync.Mutex
}

var _ Sink = (*Deferred)(nil)

// NewDeferred returns an empty queue.
func NewDeferred() *Deferred {
	return &Deferred{
		changed:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}
}

func (d *Deferred) broadcastLocked() {
	close(d.changed)
	d.changed = make(chan struct{})
}

// WriteRecord queues a record without waiting for the interface or for space.
// After Close it writes straight to the fallback writer and can block.
func (d *Deferred) WriteRecord(record Record) error {
	d.mu.Lock()
	if d.closed {
		fallback := d.fallback
		d.mu.Unlock()
		d.ioMu.Lock()
		defer d.ioMu.Unlock()
		return writeLine(fallback, record.Line)
	}
	defer d.mu.Unlock()

	d.lastSequence++
	if len(d.records) >= deferredCapacity && !d.makeRoomLocked(record, d.lastSequence) {
		d.broadcastLocked()
		return nil
	}
	d.records = append(d.records, sequencedRecord{Record: record, sequence: d.lastSequence})
	d.broadcastLocked()
	return nil
}

// makeRoomLocked evicts one unpinned record for incoming, preferring the oldest
// below warn. It reports false if incoming was rejected instead: nothing ordinary
// is left to evict, and an ordinary record must not displace a warning.
func (d *Deferred) makeRoomLocked(incoming Record, sequence uint64) bool {
	oldestWarning := -1
	for i := d.pinned; i < len(d.records); i++ {
		if d.records[i].Level < slog.LevelWarn {
			d.evictLocked(i)
			return true
		}
		if oldestWarning < 0 {
			oldestWarning = i
		}
	}
	if incoming.Level < slog.LevelWarn {
		d.pendingLoss.add(sequence, incoming.Level)
		return false
	}
	d.evictLocked(oldestWarning)
	return true
}

func (d *Deferred) evictLocked(i int) {
	d.pendingLoss.add(d.records[i].sequence, d.records[i].Level)
	d.records = append(d.records[:i], d.records[i+1:]...)
}

// Next returns the next batch, waiting for one. It reports false once the queue
// is closed or ctx ends. It waits while a batch is outstanding.
func (d *Deferred) Next(ctx context.Context) (Batch, bool) {
	for {
		d.mu.Lock()
		if d.closed {
			done := d.closeDone
			d.mu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
			}
			return Batch{}, false
		}
		if d.batchID == 0 && (len(d.records) > 0 || !d.pendingLoss.empty()) {
			batch := d.buildBatchLocked()
			d.mu.Unlock()
			return batch, true
		}
		changed := d.changed
		d.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return Batch{}, false
		}
	}
}

func (d *Deferred) buildBatchLocked() Batch {
	d.pinned = min(len(d.records), deferredBatchSize)
	d.frozenLoss = d.pendingLoss
	d.pendingLoss = lossCheckpoint{}
	d.lastBatchID++
	d.batchID = d.lastBatchID

	records := make([]Record, d.pinned)
	for i := range records {
		records[i] = d.records[i].Record
	}
	return Batch{
		ID:           d.batchID,
		Records:      records,
		Lost:         d.frozenLoss.ordinary,
		LostWarnings: d.frozenLoss.warnings,
	}
}

// Ack releases the batch with this ID. Any other ID does nothing, so a duplicate
// or late acknowledgment can't release a later batch.
func (d *Deferred) Ack(id uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || id == 0 || id != d.batchID {
		return
	}
	d.records = append(d.records[:0], d.records[d.pinned:]...)
	d.pinned = 0
	d.frozenLoss = lossCheckpoint{}
	d.batchID = 0
	d.broadcastLocked()
}

// settledLocked reports that everything submitted up to sequence has been stored
// by the interface or reported to it as lost.
func (d *Deferred) settledLocked(sequence uint64) bool {
	if len(d.records) > 0 && d.records[0].sequence <= sequence {
		return false
	}
	return d.pendingLoss.clearOf(sequence) && d.frozenLoss.clearOf(sequence)
}

// Flush waits for what has been submitted so far, so output a command returns
// next appears after it. Later records don't extend the wait. A dropped record
// counts once the interface has been told: this orders output and does not
// promise that nothing was lost. It returns the context's error if ctx ends first,
// or Close's result if the queue closes. Never call it from the interface's update
// loop, which is what it is waiting for.
func (d *Deferred) Flush(ctx context.Context) error {
	d.mu.Lock()
	sequence := d.lastSequence
	for {
		if d.closed {
			done := d.closeDone
			d.mu.Unlock()
			select {
			case <-done:
				d.mu.Lock()
				defer d.mu.Unlock()
				return d.closeErr
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if d.settledLocked(sequence) {
			d.mu.Unlock()
			return nil
		}
		changed := d.changed
		d.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
		d.mu.Lock()
	}
}

// Close ends queuing and writes everything not acknowledged to w, the outstanding
// batch first and each set of drops after the records it interrupted. Later
// records go straight to w and can't overtake those. An outstanding batch may
// already be in the interface, so a line can appear twice, which is harmless once
// the interface has gone.
//
// Call it as soon as the interface stops, before anything that might exit. It
// writes every line it can and returns the first error; repeated calls return the
// same result. A caller whose stderr has failed has nowhere to report that and may
// ignore it.
func (d *Deferred) Close(w io.Writer) error {
	d.ioMu.Lock()
	defer d.ioMu.Unlock()

	d.mu.Lock()
	if d.closed {
		defer d.mu.Unlock()
		return d.closeErr
	}
	d.closed = true
	d.fallback = w
	outstanding := d.records[:d.pinned]
	queued := d.records[d.pinned:]
	frozen, pending := d.frozenLoss, d.pendingLoss
	d.records, d.pinned = nil, 0
	d.frozenLoss, d.pendingLoss = lossCheckpoint{}, lossCheckpoint{}
	d.batchID = 0
	d.broadcastLocked()
	d.mu.Unlock()

	var firstErr error
	write := func(line string) {
		if err := writeLine(w, line); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, record := range outstanding {
		write(record.Line)
	}
	for _, line := range lossMarkers(frozen.ordinary, frozen.warnings) {
		write(line)
	}
	for _, record := range queued {
		write(record.Line)
	}
	for _, line := range lossMarkers(pending.ordinary, pending.warnings) {
		write(line)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.closeErr = firstErr
	close(d.closeDone)
	return firstErr
}
