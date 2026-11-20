// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package jsonrpc

import (
	"bufio"
	"io"
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
	go func() { done <- client.CallWithTimeout(MethodExecute, ExecuteParams{}, nil, 2*time.Second) }()
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
