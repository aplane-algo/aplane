// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsonrpc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
)

// inboundClient is a started client whose plugin output the test writes to
// toClient and whose frames to the plugin arrive, one line each, on frames.
func inboundClient(t *testing.T) (toClient io.Writer, frames <-chan string) {
	t.Helper()
	fromPlugin, toClientW := io.Pipe()
	toPlugin, fromClient := io.Pipe()
	t.Cleanup(func() {
		_ = toClientW.Close()
		_ = toPlugin.Close()
	})
	client := NewClient(fromPlugin, fromClient)
	client.Start()

	out := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(toPlugin)
		for scanner.Scan() {
			out <- scanner.Text()
		}
	}()
	return toClientW, out
}

// A plugin-initiated request with an id is answered with an error, and a
// notification is not answered. The version is checked before the id's type,
// and both before the method: a request that passes both is answered
// method-not-found, whatever the method, since apshell serves none.
func TestInboundRequestReplies(t *testing.T) {
	for _, tc := range []struct {
		name, request, reply string
	}{
		{
			name:    "numeric id",
			request: `{"jsonrpc":"2.0","method":"getBalance","params":{"address":"ADDR"},"id":7}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found: getBalance"},"id":7}`,
		},
		{
			name:    "string id",
			request: `{"jsonrpc":"2.0","method":"log","id":"abc"}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found: log"},"id":"abc"}`,
		},
		{
			name:    "wrong version",
			request: `{"jsonrpc":"1.0","method":"getBalance","id":8}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid JSON-RPC version"},"id":8}`,
		},
		{
			name:    "no version",
			request: `{"method":"getBalance","id":9}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid JSON-RPC version"},"id":9}`,
		},
		{
			name:    "boolean id",
			request: `{"jsonrpc":"2.0","method":"getBalance","id":true}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid request id type bool"},"id":true}`,
		},
		{
			name:    "object id",
			request: `{"jsonrpc":"2.0","method":"getBalance","id":{"n":1}}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid request id type map[string]interface {}"},"id":{"n":1}}`,
		},
		{
			name:    "wrong version and boolean id",
			request: `{"jsonrpc":"1.0","method":"getBalance","id":false}`,
			reply:   `{"jsonrpc":"2.0","error":{"code":-32600,"message":"invalid JSON-RPC version"},"id":false}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			toClient, frames := inboundClient(t)
			if _, err := toClient.Write([]byte(tc.request + "\n")); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-frames:
				if got != tc.reply {
					t.Fatalf("reply = %s\n want %s", got, tc.reply)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no reply")
			}
		})
	}
}

func TestInboundNotificationIsNotAnswered(t *testing.T) {
	for _, notification := range []string{
		`{"jsonrpc":"2.0","method":"log","params":{"message":"hello"}}`,
		`{"jsonrpc":"2.0","method":"log","id":null}`,
		`{"jsonrpc":"1.0","method":"log"}`,
	} {
		t.Run(notification, func(t *testing.T) {
			toClient, frames := inboundClient(t)
			const sentinel = `{"jsonrpc":"2.0","method":"sentinel","id":"s"}`
			if _, err := toClient.Write([]byte(notification + "\n" + sentinel + "\n")); err != nil {
				t.Fatal(err)
			}
			const sentinelReply = `{"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found: sentinel"},"id":"s"}`
			deadline := time.After(2 * time.Second)
			for seenSentinel := false; ; {
				select {
				case got := <-frames:
					if got != sentinelReply {
						t.Fatalf("the notification was answered: %s", got)
					}
					seenSentinel = true
				case <-time.After(100 * time.Millisecond):
					if seenSentinel {
						return
					}
				case <-deadline:
					t.Fatal("no reply to the request sent after the notification")
				}
			}
		})
	}
}

// gatedWriter passes its first write and holds every later one until release
// closes. held closes when the second write begins.
type gatedWriter struct {
	mu      sync.Mutex
	writes  int
	first   chan struct{}
	held    chan struct{}
	release chan struct{}
}

func (w *gatedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	n := w.writes
	w.mu.Unlock()
	switch n {
	case 1:
		close(w.first)
		return len(p), nil
	case 2:
		close(w.held)
	}
	<-w.release
	return len(p), nil
}

// The reply to a plugin's request is written off the read goroutine: while
// the plugin is not reading that reply, the answer to a call in progress is
// still read and delivered.
func TestInboundReplyDoesNotHoldUpTheReadLoop(t *testing.T) {
	fromPlugin, toClient := io.Pipe()
	w := &gatedWriter{first: make(chan struct{}), held: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		close(w.release)
		_ = toClient.Close()
	})
	client := NewClient(fromPlugin, w)
	client.Start()

	done := make(chan error, 1)
	go func() {
		done <- client.CallContext(context.Background(), MethodExecute, ExecuteParams{}, nil, 2*time.Second)
	}()
	<-w.first
	if _, err := toClient.Write([]byte(`{"jsonrpc":"2.0","method":"ping","id":"p"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-w.held:
	case <-time.After(2 * time.Second):
		t.Fatal("the reply to the plugin's request was never written")
	}
	// Written from a goroutine: a read loop held up by the reply would never
	// take it.
	go func() { _, _ = toClient.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"success":true}}` + "\n")) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("call error = %v, want its answer delivered", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the call's answer was not delivered while the reply was held")
	}
}

// stalledReplies is a client whose first reply to the plugin is being written
// and will not finish until release closes. countWrites reports the frames
// written so far, that one included.
func stalledReplies(t *testing.T) (client *Client, toClient io.Writer, release chan struct{}, countWrites func() int) {
	t.Helper()
	fromPlugin, toClientW := io.Pipe()
	w := &gatedWriter{first: make(chan struct{}), held: make(chan struct{}), release: make(chan struct{})}
	client = NewClient(fromPlugin, w)
	client.Start()
	release = make(chan struct{})
	var once sync.Once
	go func() {
		<-release
		once.Do(func() { close(w.release) })
	}()
	t.Cleanup(func() {
		once.Do(func() { close(w.release) })
		_ = toClientW.Close()
	})
	// The writer passes its first frame and holds the second.
	for i := 0; i < 2; i++ {
		if _, err := fmt.Fprintf(toClientW, `{"jsonrpc":"2.0","method":"ping","id":"first-%d"}`+"\n", i); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-w.held:
	case <-time.After(2 * time.Second):
		t.Fatal("the reply was never written")
	}
	return client, toClientW, release, func() int {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.writes
	}
}

// sendRequests sends n requests that want a reply.
func sendRequests(toClient io.Writer, n int) error {
	for i := 0; i < n; i++ {
		if _, err := fmt.Fprintf(toClient, `{"jsonrpc":"2.0","method":"ping","id":%d}`+"\n", i); err != nil {
			return err
		}
	}
	return nil
}

func waitForWrites(t *testing.T, countWrites func() int, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for countWrites() != want {
		if time.Now().After(deadline) {
			t.Fatalf("frames written = %d, want %d", countWrites(), want)
		}
		time.Sleep(time.Millisecond)
	}
	// Nothing more follows.
	time.Sleep(50 * time.Millisecond)
	if got := countWrites(); got != want {
		t.Fatalf("frames written = %d, want %d", got, want)
	}
}

// A plugin that floods the host with requests and reads no replies costs a
// bounded queue, not a goroutine each: the excess is dropped, and the answer to
// a call is still delivered.
func TestInboundRequestFloodIsBounded(t *testing.T) {
	client, toClient, release, countWrites := stalledReplies(t)
	before := runtime.NumGoroutine()
	// Bounded, since a read loop that blocks on a reply takes no more of it.
	if err := within(t, 5*time.Second, "the flood", func() error { return sendRequests(toClient, 1000) }); err != nil {
		t.Fatal(err)
	}
	if grown := runtime.NumGoroutine() - before; grown > 5 {
		t.Fatalf("1000 unread requests left %d more goroutines", grown)
	}

	// The call's own request can't be written, but an answer is delivered to
	// it all the same.
	respChan := make(chan *Response, 1)
	client.mu.Lock()
	client.pending[77] = respChan
	client.mu.Unlock()
	if _, err := toClient.Write([]byte(`{"jsonrpc":"2.0","id":77,"result":{"success":true}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-respChan:
	case <-time.After(2 * time.Second):
		t.Fatal("an answer was not delivered during the flood")
	}

	close(release)
	// The first two replies, and a full queue.
	waitForWrites(t, countWrites, 2+maxQueuedReplies)
}

// Notifications need no reply, so they take none of the queue's slots.
func TestInboundNotificationsTakeNoReplySlots(t *testing.T) {
	_, toClient, release, countWrites := stalledReplies(t)
	if err := within(t, 5*time.Second, "the notifications", func() error {
		for i := 0; i < 10*maxQueuedReplies; i++ {
			if _, err := toClient.Write([]byte(`{"jsonrpc":"2.0","method":"log"}` + "\n")); err != nil {
				return err
			}
		}
		if err := sendRequests(toClient, maxQueuedReplies); err != nil {
			return err
		}
		// The pipe is unbuffered, so this returns once the last request has
		// been handled.
		_, err := toClient.Write([]byte("\n"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	close(release)
	waitForWrites(t, countWrites, 2+maxQueuedReplies)
}

// Closing the client, or the plugin's output ending, ends the goroutine that
// writes replies, with one stalled and more queued.
func TestReplyWriterEndsWithTheClient(t *testing.T) {
	client, toClient, _, _ := stalledReplies(t)
	if _, err := toClient.Write([]byte(`{"jsonrpc":"2.0","method":"ping","id":1}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if replyWriters() == 0 {
		t.Fatal("no goroutine is writing replies")
	}
	before := replyWriters()
	client.Close()
	waitForReplyWriterToEnd(t, before)
}

// waitForReplyWriterToEnd waits for one of the before goroutines that were
// writing replies to end.
func waitForReplyWriterToEnd(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for replyWriters() >= before {
		if time.Now().After(deadline) {
			t.Fatal("the goroutine writing replies outlived the client")
		}
		time.Sleep(time.Millisecond)
	}
}

func replyWriters() int {
	stacks := make([]byte, 1<<20)
	stacks = stacks[:runtime.Stack(stacks, true)]
	return bytes.Count(stacks, []byte("(*Client).writeReplies("))
}

// ReadDone closes when the plugin's output ends, and not when the client fails
// for another reason.
func TestReadDoneClosesOnlyWhenTheOutputEnds(t *testing.T) {
	fromPlugin, toClient := io.Pipe()
	client := NewClient(fromPlugin, io.Discard)
	client.Start()
	client.Close()
	select {
	case <-client.ReadDone():
		t.Fatal("ReadDone closed while the plugin's output was still open")
	case <-time.After(50 * time.Millisecond):
	}
	_ = toClient.Close()
	select {
	case <-client.ReadDone():
	case <-time.After(2 * time.Second):
		t.Fatal("ReadDone did not close at the end of the plugin's output")
	}
}
