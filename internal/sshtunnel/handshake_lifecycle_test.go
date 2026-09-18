// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestClientHandshakeInterruptsStalledPeer(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					accepted <- conn
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := time.Second
			if mode == "timeout" {
				timeout = 50 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() {
				_, err := dialWithContext(ctx, "tcp", listener.Addr().String(), &ssh.ClientConfig{
					User: "aplane", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: timeout,
				})
				done <- err
			}()
			var peer net.Conn
			select {
			case peer = <-accepted:
			case <-time.After(time.Second):
				t.Fatal("client did not connect")
			}
			defer func() { _ = peer.Close() }()
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				want := context.Canceled
				if mode == "timeout" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("stalled handshake did not terminate")
			}
		})
	}
}

func TestServerHandshakeTimeoutAndShutdown(t *testing.T) {
	for _, mode := range []string{"timeout", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			srv, _ := testServer(t)
			if mode == "timeout" {
				srv.handshakeTimeout = 50 * time.Millisecond
			}
			if err := srv.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = srv.Stop() }()
			conn, err := net.Dial("tcp", srv.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			// Reading the version proves the handler has entered the handshake.
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 256)
			if _, err := conn.Read(buf); err != nil {
				t.Fatal(err)
			}
			if mode == "shutdown" {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := srv.StopContext(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := conn.Read(buf); err == nil {
				t.Fatal("expected socket closure")
			} else if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("server retained stalled connection")
			}
		})
	}
}

func TestServerBoundsHandshakeAdmission(t *testing.T) {
	srv, _ := testServer(t)
	var conns []net.Conn
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < maxPendingSSHHandshakes; i++ {
		a, b := net.Pipe()
		conns = append(conns, a, b)
		if !srv.admitConnection(a) {
			t.Fatalf("rejected slot %d", i)
		}
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if srv.admitConnection(a) {
		t.Fatal("admitted beyond handshake limit")
	}
	close(srv.closeChan)
	srv.sshConnsMu.Lock()
	srv.pendingHandshakes = 0
	srv.sshConnsMu.Unlock()
	if srv.admitConnection(a) {
		t.Fatal("admitted after shutdown")
	}
}
