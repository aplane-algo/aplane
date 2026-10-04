// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"context"
	"errors"
	"fmt"
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
		a, b := pipeFrom(fmt.Sprintf("192.0.2.%d", i+1))
		conns = append(conns, a, b)
		if !srv.admitConnection(a) {
			t.Fatalf("rejected slot %d", i)
		}
	}
	a, b := pipeFrom("198.51.100.1")
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

// remoteAddrConn reports a chosen remote address, so admission tests can
// model connections from distinct hosts.
type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func pipeFrom(ip string) (net.Conn, net.Conn) {
	a, b := net.Pipe()
	return remoteAddrConn{Conn: a, remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}, b
}

// One host cannot take every handshake slot: its pending handshakes are
// capped, other hosts are still admitted, and a finished handshake frees the
// host's slot.
func TestServerBoundsHandshakeAdmissionPerHost(t *testing.T) {
	srv, _ := testServer(t)
	var conns []net.Conn
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	var fromBusyHost []net.Conn
	for i := 0; i < maxPendingSSHHandshakesPerHost; i++ {
		a, b := pipeFrom("192.0.2.7")
		conns = append(conns, a, b)
		fromBusyHost = append(fromBusyHost, a)
		if !srv.admitConnection(a) {
			t.Fatalf("rejected slot %d for one host", i)
		}
	}
	extra, peer := pipeFrom("192.0.2.7")
	conns = append(conns, extra, peer)
	if srv.admitConnection(extra) {
		t.Fatal("admitted a host beyond its handshake share")
	}
	other, otherPeer := pipeFrom("192.0.2.8")
	conns = append(conns, other, otherPeer)
	if !srv.admitConnection(other) {
		t.Fatal("rejected another host while one host was at its share")
	}

	srv.sshConnsMu.Lock()
	srv.finishPendingHandshakeLocked(fromBusyHost[0])
	srv.sshConnsMu.Unlock()
	if !srv.admitConnection(extra) {
		t.Fatal("finished handshake did not free the host's slot")
	}
}
