// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bufio"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
)

func TestNewSSHAdminUsesCurrentProductIdentity(t *testing.T) {
	client := NewSSHAdmin("localhost", 22, "token", "identity", "known-hosts")
	if client.identityID != auth.CurrentProductIdentityID() {
		t.Fatalf("identityID = %q, want %q", client.identityID, auth.CurrentProductIdentityID())
	}
}

func TestNewSSHAdminForIdentityUsesExplicitIdentity(t *testing.T) {
	client := NewSSHAdminForIdentity("localhost", 22, "alice", "token", "identity", "known-hosts")
	if client.identityID != "alice" {
		t.Fatalf("identityID = %q, want alice", client.identityID)
	}
}

func TestSSHAdminClientCloseClosesClientWithoutStream(t *testing.T) {
	c := &SSHAdminClient{
		client: sshtunnel.NewClient("localhost", 22, 0, 0, "", ""),
	}

	c.Close()

	if c.client != nil {
		t.Fatal("client should be cleared after Close")
	}
	if c.stream != nil {
		t.Fatal("stream should be cleared after Close")
	}
}

func TestSSHAdminClientReadTimeoutClosesStream(t *testing.T) {
	stream := newBlockingSSHAdminStream()
	c := &SSHAdminClient{
		stream: stream,
		reader: bufio.NewReader(stream),
	}
	c.SetReadDeadline(time.Millisecond)

	_, err := c.ReadMessage()
	if err == nil || !strings.Contains(err.Error(), "read timed out") {
		t.Fatalf("ReadMessage() error = %v, want read timed out", err)
	}

	select {
	case <-stream.closed:
	case <-time.After(time.Second):
		t.Fatal("stream was not closed after read timeout")
	}

	c.mu.Lock()
	reader := c.reader
	transportStream := c.stream
	c.mu.Unlock()
	if reader != nil {
		t.Fatal("reader should be cleared after timeout close")
	}
	if transportStream != nil {
		t.Fatal("stream should be cleared after timeout close")
	}
}

func TestSSHAdminClientAdminDispatcherConcurrentSafe(t *testing.T) {
	c := &SSHAdminClient{}
	const workers = 32

	var wg sync.WaitGroup
	results := make(chan *dispatcher, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- c.adminDispatcher()
		}()
	}
	wg.Wait()
	close(results)

	var first *dispatcher
	for got := range results {
		if got == nil {
			t.Fatal("adminDispatcher() returned nil")
		}
		if first == nil {
			first = got
			continue
		}
		if got != first {
			t.Fatal("adminDispatcher() returned different dispatchers")
		}
	}
}

type blockingSSHAdminStream struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingSSHAdminStream() *blockingSSHAdminStream {
	return &blockingSSHAdminStream{closed: make(chan struct{})}
}

func (s *blockingSSHAdminStream) Read(_ []byte) (int, error) {
	<-s.closed
	return 0, io.EOF
}

func (s *blockingSSHAdminStream) Write(p []byte) (int, error) {
	return len(p), nil
}

func (s *blockingSSHAdminStream) Close() error {
	s.once.Do(func() {
		close(s.closed)
	})
	return nil
}
