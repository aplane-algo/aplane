// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Connections beyond the cap wait in the accept queue instead of each
// holding a handler and its buffers; closing one admits the next.
func TestLimitListenerBoundsOpenConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 2)
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 3)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
	}
	first := <-accepted
	<-accepted
	select {
	case <-accepted:
		t.Fatal("accepted a connection beyond the cap")
	case <-time.After(100 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("closing a connection did not admit the waiting one")
	}
}

// Closing the listener unblocks an Accept that is waiting for a slot.
func TestLimitListenerCloseUnblocksAccept(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := newLimitListener(inner, 1)
	conn, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := ln.Accept(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ln.Accept()
		done <- err
	}()
	_ = ln.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept after Close returned a connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept stayed blocked after Close")
	}
}

// Request headers beyond the cap are refused before any handler runs.
func TestHTTPServerRefusesOversizedHeaders(t *testing.T) {
	srv := buildHTTPServer(&Signer{}, 0)
	if srv.MaxHeaderBytes != maxHTTPHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, maxHTTPHeaderBytes)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// The server may answer before the whole header is written, so a write
	// error is expected and only the response matters.
	go func() {
		_, _ = fmt.Fprintf(conn, "GET /health HTTP/1.1\r\nHost: x\r\nX-Pad: %s\r\n\r\n", strings.Repeat("a", 2*maxHTTPHeaderBytes))
	}()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}
}
