// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsonrpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// enteredWriter reports, by closing entered, the first time a write to w
// begins.
type enteredWriter struct {
	w       io.Writer
	once    sync.Once
	entered chan struct{}
}

func (e *enteredWriter) Write(p []byte) (int, error) {
	e.once.Do(func() { close(e.entered) })
	return e.w.Write(p)
}

// unreadClient is a client whose plugin never reads its input: writes go to a
// pipe nobody reads. The test writes the plugin's output to toClient.
func unreadClient(t *testing.T) (c *Client, entered chan struct{}, toClient io.Writer) {
	t.Helper()
	return unreadClientStarted(t, (*Client).Start)
}

func unreadClientStarted(t *testing.T, start func(*Client)) (c *Client, entered chan struct{}, toClient io.Writer) {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Closing the unread end unblocks a write still stuck in it.
	t.Cleanup(func() {
		_ = inR.Close()
		_ = inW.Close()
		_ = outW.Close()
	})
	entered = make(chan struct{})
	c = NewClient(outR, &enteredWriter{w: inW, entered: entered})
	start(c)
	return c, entered, outW
}

// bigParams is larger than any pipe buffer, so its write cannot finish
// unless the plugin reads.
func bigParams() map[string]string {
	return map[string]string{"x": strings.Repeat("a", 256*1024)}
}

// within runs fn and fails the test if it has not returned after limit.
func within(t *testing.T, limit time.Duration, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("%s still blocked after %v", what, limit)
		return nil
	}
}

// The call's timeout covers sending the request: a request the plugin does not
// read ends the call on time, and the client, whose input may now hold part
// of a frame, refuses later calls.
func TestCallTimeoutCoversAStalledWrite(t *testing.T) {
	c, _, _ := unreadClient(t)
	err := within(t, 2*time.Second, "CallContext", func() error {
		return c.CallContext(context.Background(), MethodExecute, bigParams(), nil, 100*time.Millisecond)
	})
	if !errors.Is(err, ErrWriteStalled) {
		t.Fatalf("CallContext() error = %v, want %v", err, ErrWriteStalled)
	}
	err = within(t, time.Second, "the next call", func() error {
		return c.CallContext(context.Background(), MethodExecute, ExecuteParams{}, nil, 30*time.Second)
	})
	if !errors.Is(err, ErrWriteStalled) {
		t.Fatalf("next call error = %v, want %v", err, ErrWriteStalled)
	}
}

// ctx ends a call whose request the plugin does not read, as it ends one
// waiting for the answer.
func TestCallContextCoversAStalledWrite(t *testing.T) {
	c, _, _ := unreadClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := within(t, 2*time.Second, "CallContext", func() error {
		return c.CallContext(ctx, MethodExecute, bigParams(), nil, 30*time.Second)
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CallContext() error = %v, want the ctx deadline", err)
	}
}

// A call waiting to write behind a stalled one ends when the stalled one
// fails the client, not at its own, longer, timeout.
func TestCallQueuedBehindAStalledWriteEndsWithIt(t *testing.T) {
	c, entered, _ := unreadClient(t)
	go func() { _ = c.CallContext(context.Background(), MethodExecute, bigParams(), nil, 300*time.Millisecond) }()
	<-entered
	err := within(t, 2*time.Second, "the queued call", func() error {
		return c.CallContext(context.Background(), MethodExecute, ExecuteParams{}, nil, 30*time.Second)
	})
	if !errors.Is(err, ErrWriteStalled) {
		t.Fatalf("queued call error = %v, want %v", err, ErrWriteStalled)
	}
}

// Shutdown waits only briefly behind a frame the plugin is not reading.
func TestShutdownDoesNotWaitForAStalledWrite(t *testing.T) {
	c, entered, _ := unreadClient(t)
	go func() { _ = c.CallContext(context.Background(), MethodExecute, bigParams(), nil, 30*time.Second) }()
	<-entered
	err := within(t, 500*time.Millisecond, "Shutdown", func() error {
		return c.Shutdown(5 * time.Second)
	})
	if err == nil {
		t.Fatal("Shutdown() = nil, want it not sent")
	}
}

// A reply to a plugin's request, waiting to write behind a stalled request,
// ends when that request fails the client.
func TestCallbackReplyQueuedBehindAStalledWriteEndsWithIt(t *testing.T) {
	var ended <-chan struct{}
	c, entered, _ := unreadClientStarted(t, func(c *Client) { ended = startWatched(c) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.CallContext(ctx, MethodExecute, bigParams(), nil, time.Minute) }()
	<-entered
	// The queue has room for one more than it holds only once the reply at its
	// head has been taken, to wait behind the request.
	for range cap(c.replies) + 1 {
		c.replies <- &Response{Jsonrpc: Version, ID: 7}
	}
	cancel()
	waitForReplyWriter(t, ended)
}

// A write that has returned has freed the writer, so a Shutdown right after a
// healthy write is sent, never taken for one waiting behind a stalled write.
func TestWriteFreesTheWriterBeforeItReturns(t *testing.T) {
	c := NewClient(&bytes.Buffer{}, io.Discard)
	for i := 0; i < 50000; i++ {
		if err := c.writeFrame(context.Background(), NewRequest(MethodExecute, ExecuteParams{}, nil), 0); err != nil {
			t.Fatalf("writeFrame() error = %v", err)
		}
		select {
		case c.writeSlot <- struct{}{}:
			<-c.writeSlot
		default:
			t.Fatalf("write %d returned with the writer still held", i)
		}
	}
}

// slowWriter takes delay to accept each frame, as a plugin that reads slowly
// does. entered closes when the first write begins.
type slowWriter struct {
	delay   time.Duration
	once    sync.Once
	entered chan struct{}
	mu      sync.Mutex
	frames  []string
}

func (w *slowWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	time.Sleep(w.delay)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.frames = append(w.frames, string(p))
	return len(p), nil
}

// Shutdown behind a write that is about to finish waits for it, and is sent.
func TestShutdownWaitsForAWriteAboutToFinish(t *testing.T) {
	w := &slowWriter{delay: 30 * time.Millisecond, entered: make(chan struct{})}
	c := NewClient(&bytes.Buffer{}, w)
	go func() {
		_ = c.writeFrame(context.Background(), NewRequest(MethodExecute, ExecuteParams{}, nil), 0)
	}()
	<-w.entered
	if err := c.Shutdown(200 * time.Millisecond); errors.Is(err, errWriterBusy) {
		t.Fatalf("Shutdown() error = %v, want it sent", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.frames) != 2 || !strings.Contains(w.frames[1], MethodShutdown) {
		t.Fatalf("frames written = %q, want the first frame then the shutdown", w.frames)
	}
}

// countingWriter counts the frames written to it.
type countingWriter struct{ n atomic.Int64 }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n.Add(1)
	return len(p), nil
}

// A frame whose context has already ended is not sent, and does not fail a
// healthy client.
func TestEndedContextSendsNothingAndKeepsTheClient(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		send func(*Client) error
	}{
		{name: "frame with an ended ctx", send: func(c *Client) error {
			return c.writeFrame(ended, NewRequest(MethodExecute, ExecuteParams{}, nil), 0)
		}},
		{name: "call with no time left", send: func(c *Client) error {
			return c.CallContext(context.Background(), MethodExecute, ExecuteParams{}, nil, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 300; i++ {
				w := &countingWriter{}
				c := NewClient(&bytes.Buffer{}, w)
				if err := tc.send(c); err == nil {
					t.Fatal("send = nil, want the ended ctx")
				}
				if err := c.terminalError(); err != nil {
					t.Fatalf("attempt %d failed the client: %v", i, err)
				}
				if n := w.n.Load(); n != 0 {
					t.Fatalf("attempt %d wrote %d frame(s), want none", i, n)
				}
			}
		})
	}
}

// A call waiting for its answer when the client fails reports that first
// failure, not one that follows it, such as the client being closed.
func TestWaitingCallReportsTheClientsFirstFailure(t *testing.T) {
	first := errors.New("first failure")
	for i := 0; i < 50; i++ {
		entered := make(chan struct{})
		c := NewClient(&bytes.Buffer{}, &enteredWriter{w: io.Discard, entered: entered})
		callErr := make(chan error, 1)
		go func() {
			callErr <- c.CallContext(context.Background(), MethodExecute, ExecuteParams{}, nil, 5*time.Second)
		}()
		<-entered
		time.Sleep(5 * time.Millisecond) // let the call reach its wait for the answer
		c.failPending(first)
		c.Close()
		if err := <-callErr; !errors.Is(err, first) {
			t.Fatalf("attempt %d: error = %v, want the first failure", i, err)
		}
	}
}
