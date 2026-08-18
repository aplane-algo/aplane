// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminproto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
)

// stallWriter blocks every Write until Close is called, simulating a dead
// client on a transport without native write deadlines (e.g. an SSH channel).
type stallWriter struct {
	closedCh chan struct{}
	once     sync.Once
}

func newStallWriter() *stallWriter {
	return &stallWriter{closedCh: make(chan struct{})}
}

func (s *stallWriter) Read(p []byte) (int, error) {
	<-s.closedCh
	return 0, io.EOF
}

func (s *stallWriter) Write(p []byte) (int, error) {
	<-s.closedCh
	return 0, io.ErrClosedPipe
}

func (s *stallWriter) Close() error {
	s.once.Do(func() { close(s.closedCh) })
	return nil
}

func TestStreamAdminConnWriteStallForceClosesConnection(t *testing.T) {
	// A stalled write on a transport without native deadlines must be released
	// by the watchdog timer force-closing the connection.
	stall := newStallWriter()
	conn := NewStreamAdminConn(stall, "test")
	conn.writeTimeout = 50 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		done <- conn.WriteMessage([]byte(`{"type":"ping"}`))
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled write should fail once the watchdog closes the connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled write was not released by the watchdog timer")
	}
}

func TestStreamAdminConnWritesAreSerializedPerConnection(t *testing.T) {
	// Two connections must not share a write lock: a stalled write on one
	// connection cannot block writes on another.
	stalled := NewStreamAdminConn(newStallWriter(), "stalled")
	healthy := NewStreamAdminConn(nopReadWriteCloser{}, "healthy")

	stalledDone := make(chan struct{})
	go func() {
		_ = stalled.WriteMessage([]byte(`{"type":"ping"}`))
		close(stalledDone)
	}()
	time.Sleep(20 * time.Millisecond) // let the stalled write take its lock

	healthyDone := make(chan error, 1)
	go func() {
		healthyDone <- healthy.WriteMessage([]byte(`{"type":"ping"}`))
	}()

	select {
	case err := <-healthyDone:
		if err != nil {
			t.Fatalf("healthy connection write failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write on healthy connection blocked behind a stalled peer connection")
	}

	_ = stalled.Close()
	<-stalledDone
}

type byteAtATimeWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (w *byteAtATimeWriter) Read([]byte) (int, error) { return 0, io.EOF }

func (w *byteAtATimeWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		w.mu.Lock()
		_ = w.buffer.WriteByte(b)
		w.mu.Unlock()
		runtime.Gosched()
	}
	return len(p), nil
}

func (w *byteAtATimeWriter) Close() error { return nil }

func (w *byteAtATimeWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buffer.Bytes()...)
}

func TestStreamAdminConnConcurrentWritesRemainWholeJSONFrames(t *testing.T) {
	const writeCount = 32

	writer := &byteAtATimeWriter{}
	conn := NewStreamAdminConn(writer, "concurrent")
	var wg sync.WaitGroup
	errs := make(chan error, writeCount)
	for i := 0; i < writeCount; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf(`{"id":%d,"payload":"frame-%02d"}`, id, id))
			errs <- conn.WriteMessage(payload)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("WriteMessage() error = %v", err)
		}
	}

	lines := bytes.Split(bytes.TrimSpace(writer.Bytes()), []byte{'\n'})
	if len(lines) != writeCount {
		t.Fatalf("frame count = %d, want %d: %q", len(lines), writeCount, writer.Bytes())
	}
	seen := make(map[int]bool, writeCount)
	for _, line := range lines {
		var frame struct {
			ID      int    `json:"id"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(line, &frame); err != nil {
			t.Fatalf("interleaved JSON frame %q: %v", line, err)
		}
		if frame.Payload != fmt.Sprintf("frame-%02d", frame.ID) {
			t.Fatalf("frame = %+v, want matching id and payload", frame)
		}
		seen[frame.ID] = true
	}
	if len(seen) != writeCount {
		t.Fatalf("unique frame count = %d, want %d", len(seen), writeCount)
	}
}

type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }
