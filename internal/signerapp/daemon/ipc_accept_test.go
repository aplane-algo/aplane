// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"context"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type acceptResult struct {
	conn net.Conn
	err  error
}

// scriptedListener returns the queued Accept results in order, then blocks
// until Close, after which Accept fails with net.ErrClosed as a real
// listener does.
type scriptedListener struct {
	results   chan acceptResult
	closed    chan struct{}
	closeOnce sync.Once
	// accepted, when set, receives once for each queued result Accept returns.
	accepted chan struct{}
}

func newScriptedListener(results ...acceptResult) *scriptedListener {
	l := &scriptedListener{
		results: make(chan acceptResult, len(results)),
		closed:  make(chan struct{}),
	}
	for _, r := range results {
		l.results <- r
	}
	return l
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	select {
	case r := <-l.results:
		if l.accepted != nil {
			l.accepted <- struct{}{}
		}
		return r.conn, r.err
	case <-l.closed:
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: net.ErrClosed}
	}
}

func (l *scriptedListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return &net.UnixAddr{Name: "scripted", Net: "unix"} }

// An Accept that fails because the process is out of descriptors once ended
// the accept loop for good: the daemon kept running, but no apadmin could
// connect to unlock or approve until it restarted. The loop now retries, and
// ends only when the listener is closed.
func TestIPCAcceptLoopSurvivesAFailedAccept(t *testing.T) {
	server := newLoginTimeoutTestServer(t)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	emfile := &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	listener := newScriptedListener(
		acceptResult{err: emfile},
		acceptResult{err: emfile},
		acceptResult{conn: serverConn},
	)
	server.listener = listener

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		server.acceptLoop()
	}()

	// The connection accepted after the failures is served.
	readAdminMessageType(t, clientConn, bufio.NewReader(clientConn), protocol.MsgTypeAuthRequired)

	_ = listener.Close()
	select {
	case <-loopDone:
	case <-time.After(ipcDisconnectTestTimeout):
		t.Fatal("accept loop did not end after the listener closed")
	}
}

// Stop during a backoff wait ends the loop at once, rather than when the
// wait (up to a second) is over.
func TestIPCAcceptLoopStopEndsABackoffAtOnce(t *testing.T) {
	signer, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	server := NewIPCServer("", signer)
	const failures = 5 // the fifth failure waits 400ms
	emfile := &net.OpError{Op: "accept", Net: "unix", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	results := make([]acceptResult, failures)
	for i := range results {
		results[i] = acceptResult{err: emfile}
	}
	listener := newScriptedListener(results...)
	listener.accepted = make(chan struct{}, failures)
	server.listener = listener

	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		server.acceptLoop()
	}()
	for i := 0; i < failures; i++ {
		select {
		case <-listener.accepted:
		case <-time.After(ipcDisconnectTestTimeout):
			t.Fatalf("accept loop stopped after %d failure(s)", i)
		}
	}

	stopped := time.Now()
	_ = server.Stop(context.Background())
	select {
	case <-loopDone:
	case <-time.After(ipcDisconnectTestTimeout):
		t.Fatal("accept loop did not end after Stop")
	}
	if waited := time.Since(stopped); waited > 200*time.Millisecond {
		t.Fatalf("accept loop ended %s after Stop, want at once", waited)
	}
}

func TestNextIPCAcceptBackoffDoublesToTheCap(t *testing.T) {
	tests := []struct {
		current, want time.Duration
	}{
		{0, initialIPCAcceptBackoff},
		{initialIPCAcceptBackoff, 2 * initialIPCAcceptBackoff},
		{maxIPCAcceptBackoff / 2 * 3, maxIPCAcceptBackoff},
		{maxIPCAcceptBackoff, maxIPCAcceptBackoff},
	}
	for _, tt := range tests {
		if got := nextIPCAcceptBackoff(tt.current); got != tt.want {
			t.Errorf("nextIPCAcceptBackoff(%s) = %s, want %s", tt.current, got, tt.want)
		}
	}
}
