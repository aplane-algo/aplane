// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package clientlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func shortWait() <-chan time.Time { return time.After(30 * time.Millisecond) }

func patient(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func submit(t *testing.T, d *Deferred, level slog.Level, line string) {
	t.Helper()
	if err := d.WriteRecord(Record{Level: level, Line: line}); err != nil {
		t.Fatalf("WriteRecord() error = %v", err)
	}
}

func fill(t *testing.T, d *Deferred, level slog.Level, prefix string, n int) {
	t.Helper()
	for i := range n {
		submit(t, d, level, fmt.Sprintf("%s%d", prefix, i))
	}
}

func next(t *testing.T, d *Deferred) Batch {
	t.Helper()
	batch, ok := d.Next(patient(t))
	if !ok {
		t.Fatal("Next() reported no batch")
	}
	return batch
}

// drain acknowledges batches until the queue is empty, returning every line and
// the total counts.
func drain(t *testing.T, d *Deferred) (lines []string, lost, lostWarnings uint64) {
	t.Helper()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		batch, ok := d.Next(ctx)
		cancel()
		if !ok {
			return lines, lost, lostWarnings
		}
		for _, record := range batch.Records {
			lines = append(lines, record.Line)
		}
		lost += batch.Lost
		lostWarnings += batch.LostWarnings
		d.Ack(batch.ID)
	}
}

func TestDeferredHoldsRecordsUntilAConsumerArrives(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelWarn, "startup warning")

	batch := next(t, d)

	if len(batch.Records) != 1 || batch.Records[0].Line != "startup warning" {
		t.Fatalf("batch = %+v", batch)
	}
}

func TestDeferredDeliversInOrderInBoundedBatches(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelInfo, "r", 150)

	first := next(t, d)
	if len(first.Records) != deferredBatchSize {
		t.Fatalf("first batch has %d records, want %d", len(first.Records), deferredBatchSize)
	}
	d.Ack(first.ID)

	lines, lost, lostWarnings := drain(t, d)
	if len(lines) != 150-deferredBatchSize || lost != 0 || lostWarnings != 0 {
		t.Fatalf("drained %d lines, lost %d/%d", len(lines), lost, lostWarnings)
	}
	if lines[0] != fmt.Sprintf("r%d", deferredBatchSize) || lines[len(lines)-1] != "r149" {
		t.Fatalf("out of order: first %q last %q", lines[0], lines[len(lines)-1])
	}
}

func TestDeferredHoldsOneOutstandingBatch(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelInfo, "r", 10)
	first := next(t, d)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, ok := d.Next(ctx); ok {
		t.Fatal("Next() returned a second batch before the first was acknowledged")
	}

	d.Ack(first.ID)
	submit(t, d, slog.LevelInfo, "later")
	if batch := next(t, d); batch.Records[0].Line != "later" {
		t.Fatalf("batch = %+v", batch)
	}
}

func TestDeferredEvictsOrdinaryRecordsBeforeWarnings(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelWarn, "SECURITY")
	fill(t, d, slog.LevelInfo, "noise", deferredCapacity+50)

	lines, lost, lostWarnings := drain(t, d)

	if lines[0] != "SECURITY" {
		t.Fatalf("first line = %q, want the warning", lines[0])
	}
	if len(lines) != deferredCapacity || lost != 51 || lostWarnings != 0 {
		t.Fatalf("kept %d, lost %d, lost warnings %d", len(lines), lost, lostWarnings)
	}
	if lines[1] != "noise51" {
		t.Fatalf("second line = %q, want the oldest ordinary record gone", lines[1])
	}
}

func TestDeferredRejectsOrdinaryRecordWhenOnlyWarningsRemain(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "w", deferredCapacity)

	submit(t, d, slog.LevelInfo, "rejected")

	lines, lost, lostWarnings := drain(t, d)
	if len(lines) != deferredCapacity || slices.Contains(lines, "rejected") {
		t.Fatalf("kept %d lines; rejected present = %v", len(lines), slices.Contains(lines, "rejected"))
	}
	if lost != 1 || lostWarnings != 0 {
		t.Fatalf("lost %d, lost warnings %d, want the one rejection", lost, lostWarnings)
	}
}

func TestDeferredIncomingWarningEvictsOldestWarning(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "w", deferredCapacity)

	submit(t, d, slog.LevelError, "newest")

	lines, lost, lostWarnings := drain(t, d)
	if lines[0] != "w1" || lines[len(lines)-1] != "newest" {
		t.Fatalf("first %q last %q", lines[0], lines[len(lines)-1])
	}
	if lost != 0 || lostWarnings != 1 {
		t.Fatalf("lost %d, lost warnings %d, want one warning", lost, lostWarnings)
	}
}

func TestDeferredNeverEvictsAPinnedBatch(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelInfo, "pinned", deferredBatchSize)
	batch := next(t, d)

	fill(t, d, slog.LevelWarn, "w", 2*deferredCapacity)

	d.Ack(batch.ID)
	lines, _, lostWarnings := drain(t, d)
	wantKept := deferredCapacity - deferredBatchSize
	if len(lines) != wantKept {
		t.Fatalf("kept %d after the batch, want %d", len(lines), wantKept)
	}
	if want := uint64(2*deferredCapacity - wantKept); lostWarnings != want {
		t.Fatalf("lost warnings = %d, want %d", lostWarnings, want)
	}
	if strings.HasPrefix(lines[0], "pinned") {
		t.Fatalf("a pinned record came back: %q", lines[0])
	}
}

func TestDeferredWritersNeverBlock(t *testing.T) {
	d := NewDeferred()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 5 * deferredCapacity {
			_ = d.WriteRecord(Record{Level: slog.Level(i % 12), Line: "x"})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a writer waited with no consumer")
	}
}

func TestDeferredLossOnlyBatch(t *testing.T) {
	// A queue only drops while full, so records normally accompany a loss. Next
	// must still report one alone, rather than sit on it.
	d := NewDeferred()
	d.mu.Lock()
	d.pendingLoss.add(1, slog.LevelInfo)
	d.lastSequence = 1
	d.broadcastLocked()
	d.mu.Unlock()

	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()

	batch := next(t, d)
	if len(batch.Records) != 0 || batch.Lost != 1 {
		t.Fatalf("batch = %+v, want a loss with no records", batch)
	}
	select {
	case err := <-flushed:
		t.Fatalf("Flush() returned %v before the loss was acknowledged", err)
	case <-shortWait():
	}
	d.Ack(batch.ID)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
}

func TestLossMarkersSeparateWarningsFromOrdinaryLines(t *testing.T) {
	got := Batch{Lost: 3, LostWarnings: 2}.LossMarkers()
	want := []string{"[aplane] warning: 2 warnings dropped", "[aplane] 3 log lines dropped"}
	if !slices.Equal(got, want) {
		t.Fatalf("LossMarkers() = %q, want %q", got, want)
	}
	if got := (Batch{}).LossMarkers(); len(got) != 0 {
		t.Fatalf("LossMarkers() = %q, want none", got)
	}
}

func TestDeferredAckIgnoresDuplicateStaleAndWrongIDs(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelInfo, "a", 3)
	first := next(t, d)
	d.Ack(first.ID)
	fill(t, d, slog.LevelInfo, "b", 3)
	second := next(t, d)

	d.Ack(first.ID)      // Duplicate.
	d.Ack(0)             // No batch has this ID.
	d.Ack(second.ID + 7) // Never issued.

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, ok := d.Next(ctx); ok {
		t.Fatal("a stale acknowledgment released the outstanding batch")
	}
	d.Ack(second.ID)
	if lines, _, _ := drain(t, d); len(lines) != 0 {
		t.Fatalf("lines = %q", lines)
	}
}

func TestDeferredLaterLossSurvivesEarlierAck(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "w", deferredCapacity)
	batch := next(t, d)
	fill(t, d, slog.LevelInfo, "rejected", 2)

	d.Ack(batch.ID)

	if _, lost, _ := drain(t, d); lost != 2 {
		t.Fatalf("lost = %d; acknowledging an earlier batch cleared a later loss", lost)
	}
}

// consume acknowledges batches until stopped, recording what it saw.
func consume(t *testing.T, d *Deferred) (stop func() (lost uint64)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var lost uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			batch, ok := d.Next(ctx)
			if !ok {
				return
			}
			mu.Lock()
			lost += batch.Lost + batch.LostWarnings
			mu.Unlock()
			d.Ack(batch.ID)
		}
	}()
	return func() uint64 {
		cancel()
		<-done
		mu.Lock()
		defer mu.Unlock()
		return lost
	}
}

func TestFlushWaitsForTheConsumer(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelWarn, "before the result")

	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()
	select {
	case err := <-flushed:
		t.Fatalf("Flush() returned %v before the record was stored", err)
	case <-shortWait():
	}

	batch := next(t, d)
	select {
	case err := <-flushed:
		t.Fatalf("Flush() returned %v for a batch that is in flight", err)
	case <-shortWait():
	}

	d.Ack(batch.ID)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
}

func TestFlushOnEmptyQueueReturnsAtOnce(t *testing.T) {
	if err := NewDeferred().Flush(patient(t)); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
}

func TestFlushCompletesWhenTheFinalRecordWasEvicted(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "w", deferredCapacity)
	submit(t, d, slog.LevelInfo, "final") // Rejected: no later record is retained.

	stop := consume(t, d)
	if err := d.Flush(patient(t)); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if lost := stop(); lost != 1 {
		t.Fatalf("lost = %d, want the marker delivered before Flush returned", lost)
	}
}

func TestFlushWaitsForTheMarkerOfItsOwnLoss(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "w", deferredCapacity)
	submit(t, d, slog.LevelInfo, "lost")

	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()

	// Everything retained is delivered first, one batch at a time, while the loss
	// is still pending: the flush must not finish on retained records alone.
	first := next(t, d)
	if first.Lost != 1 {
		t.Fatalf("first batch Lost = %d, want the marker in the first batch", first.Lost)
	}
	select {
	case err := <-flushed:
		t.Fatalf("Flush() returned %v with the marker unacknowledged", err)
	case <-shortWait():
	}
	d.Ack(first.ID)
	stop := consume(t, d)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	stop()
}

func TestFlushIsNotExtendedByLaterTraffic(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "before")

	stop := consume(t, d)
	defer stop()
	flood, cancelFlood := context.WithCancel(context.Background())
	defer cancelFlood()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for flood.Err() == nil {
			_ = d.WriteRecord(Record{Level: slog.LevelInfo, Line: "later"})
		}
	}()

	if err := d.Flush(patient(t)); err != nil {
		t.Fatalf("Flush() error = %v; losses after the snapshot must not extend it", err)
	}
	cancelFlood()
	wg.Wait()
}

func TestFlushWithLossesContinuingAfterTheSnapshot(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "w", deferredCapacity)
	submit(t, d, slog.LevelInfo, "lost before the snapshot")

	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()
	<-shortWait()
	fill(t, d, slog.LevelInfo, "lost after the snapshot", 5)

	stop := consume(t, d)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	stop()
}

func TestFlushWithPinnedBatchAndWarningTraffic(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelInfo, "pinned", deferredBatchSize)
	batch := next(t, d)
	fill(t, d, slog.LevelWarn, "w", 2*deferredCapacity)

	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()
	d.Ack(batch.ID)
	stop := consume(t, d)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if lost := stop(); lost == 0 {
		t.Fatal("the warning overflow wasn't reported")
	}
}

func TestFlushReturnsOnCancellation(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "never stored")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := d.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush() error = %v, want the context's", err)
	}
}

func TestNextReturnsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, ok := NewDeferred().Next(ctx); ok {
		t.Fatal("Next() returned a batch from an empty queue")
	}
}

func TestCloseWritesTheBacklogInOrder(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelWarn, "first", deferredCapacity)
	submit(t, d, slog.LevelInfo, "rejected before the batch")
	batch := next(t, d)
	if batch.Lost != 1 {
		t.Fatalf("batch.Lost = %d", batch.Lost)
	}
	submit(t, d, slog.LevelInfo, "rejected after the batch")

	var out bytes.Buffer
	if err := d.Close(&out); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != deferredCapacity+2 {
		t.Fatalf("wrote %d lines", len(lines))
	}
	if lines[0] != "first0" || lines[deferredBatchSize-1] != fmt.Sprintf("first%d", deferredBatchSize-1) {
		t.Fatalf("outstanding batch out of place: %q", lines[0])
	}
	if lines[deferredBatchSize] != "[aplane] 1 log lines dropped" {
		t.Fatalf("frozen marker out of place: %q", lines[deferredBatchSize])
	}
	if lines[deferredBatchSize+1] != fmt.Sprintf("first%d", deferredBatchSize) {
		t.Fatalf("queued records out of place: %q", lines[deferredBatchSize+1])
	}
	if lines[len(lines)-1] != "[aplane] 1 log lines dropped" {
		t.Fatalf("pending marker out of place: %q", lines[len(lines)-1])
	}
}

func TestCloseWritesABatchTheConsumerNeverStored(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelWarn, "SECURITY")
	next(t, d) // Taken, then lost as the program stops.

	var out bytes.Buffer
	if err := d.Close(&out); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if out.String() != "SECURITY\n" {
		t.Fatalf("out = %q", out.String())
	}
}

func TestCloseIsIdempotentAndKeepsItsFirstResult(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "line")
	failure := errors.New("stderr is gone")

	first := d.Close(failingWriter{failure})
	var second bytes.Buffer
	if err := d.Close(&second); !errors.Is(err, failure) || !errors.Is(first, failure) {
		t.Fatalf("Close() = %v then %v, want the first failure both times", first, err)
	}
	if second.Len() != 0 {
		t.Fatalf("second Close() wrote %q", second.String())
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

func TestCloseReportsShortWrites(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "line")
	if err := d.Close(shortWriter{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Close() error = %v, want a short write", err)
	}
}

// countingWriter fails its first write and records the rest.
type countingWriter struct {
	lines []string
	wrote int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	w.wrote++
	if w.wrote == 1 {
		return 0, errors.New("first write failed")
	}
	w.lines = append(w.lines, string(p))
	return len(p), nil
}

func TestCloseKeepsWritingAfterAnError(t *testing.T) {
	d := NewDeferred()
	fill(t, d, slog.LevelInfo, "r", 3)
	w := &countingWriter{}
	if err := d.Close(w); err == nil {
		t.Fatal("Close() hid the failure")
	}
	if !slices.Equal(w.lines, []string{"r1\n", "r2\n"}) {
		t.Fatalf("lines = %q", w.lines)
	}
}

func TestRecordsAfterCloseGoStraightToTheWriter(t *testing.T) {
	d := NewDeferred()
	var out syncBuffer
	if err := d.Close(&out); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if err := d.WriteRecord(Record{Level: slog.LevelInfo, Line: "during shutdown"}); err != nil {
		t.Fatalf("WriteRecord() error = %v", err)
	}
	if out.String() != "during shutdown\n" {
		t.Fatalf("out = %q", out.String())
	}
	if err := d.WriteRecord(Record{Line: "x"}); err != nil {
		t.Fatalf("WriteRecord() error = %v", err)
	}
	d.Ack(1) // Late acknowledgment does nothing.
}

// gatedWriter holds the first write open until released.
type gatedWriter struct {
	syncBuffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.once.Do(func() {
		close(w.entered)
		<-w.release
	})
	return w.syncBuffer.Write(p)
}

func TestLaterWritesCannotOvertakeTheBacklog(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "backlog")
	w := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}

	closed := make(chan error, 1)
	go func() { closed <- d.Close(w) }()
	<-w.entered

	written := make(chan error, 1)
	go func() { written <- d.WriteRecord(Record{Line: "later"}) }()
	<-shortWait()
	close(w.release)

	if err := <-closed; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("WriteRecord() error = %v", err)
	}
	if got := w.String(); got != "backlog\nlater\n" {
		t.Fatalf("out = %q", got)
	}
}

func TestCloseWakesWaitersOnlyAfterItsWrites(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "unstored")
	w := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}

	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()
	<-shortWait()

	closed := make(chan error, 1)
	go func() { closed <- d.Close(w) }()
	<-w.entered

	select {
	case err := <-flushed:
		t.Fatalf("Flush() returned %v during the write pass", err)
	case <-shortWait():
	}
	close(w.release)
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCancellationIsObservedDuringTheWritePass(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "unstored")
	w := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	go func() { _ = d.Close(w) }()
	<-w.entered
	defer close(w.release)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := d.Flush(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush() error = %v, want cancellation to work during Close", err)
	}
}

func TestQuittingDuringFlushReleasesIt(t *testing.T) {
	d := NewDeferred()
	submit(t, d, slog.LevelInfo, "unstored")
	flushed := make(chan error, 1)
	go func() { flushed <- d.Flush(patient(t)) }()
	<-shortWait()

	var out bytes.Buffer
	if err := d.Close(&out); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := <-flushed; err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
}

func TestCloseWakesNext(t *testing.T) {
	d := NewDeferred()
	waited := make(chan bool, 1)
	go func() {
		_, ok := d.Next(context.Background())
		waited <- ok
	}()
	<-shortWait()

	if err := d.Close(io.Discard); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if ok := <-waited; ok {
		t.Fatal("Next() returned a batch after Close")
	}
}

func TestConcurrentProducersConsumerAndClose(t *testing.T) {
	d := NewDeferred()
	stop := consume(t, d)

	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 500 {
				_ = d.WriteRecord(Record{Level: slog.Level((g + i) % 12), Line: "x"})
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = d.Flush(patient(t))
	}()
	<-time.After(time.Millisecond)
	if err := d.Close(io.Discard); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	wg.Wait()
	stop()
}
