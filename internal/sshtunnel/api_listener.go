// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"errors"
	"net"
	"sync"
)

var (
	// ErrAPIListenerClosed reports a handoff to a listener that was closed.
	ErrAPIListenerClosed = errors.New("API listener closed")
	// ErrAPIListenerFull reports a handoff refused because the accept queue
	// is full.
	ErrAPIListenerFull = errors.New("API listener queue full")
)

// APIListener hands tunneled API channels to an HTTP server as accepted
// connections. The node owns it, not the SSH server, so an SSH listener
// restart does not disturb the HTTP side. Handoff never blocks: a full queue
// refuses the channel, which the SSH server reports to the client as a
// resource shortage.
type APIListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

// NewAPIListener creates a listener whose accept queue holds capacity
// connections between handoff and Accept.
func NewAPIListener(capacity int) *APIListener {
	if capacity < 1 {
		capacity = 1
	}
	return &APIListener{conns: make(chan net.Conn, capacity), done: make(chan struct{})}
}

// Handoff queues a tunneled connection for Accept. It is an APIHandoff.
func (l *APIListener) Handoff(conn *APIConn) error {
	select {
	case <-l.done:
		return ErrAPIListenerClosed
	default:
	}
	select {
	case l.conns <- conn:
		return nil
	case <-l.done:
		return ErrAPIListenerClosed
	default:
		return ErrAPIListenerFull
	}
}

// Accept returns the next handed-off connection.
func (l *APIListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops Accept and closes any connection still queued.
func (l *APIListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		for {
			select {
			case conn := <-l.conns:
				_ = conn.Close()
			default:
				return
			}
		}
	})
	return nil
}

// Addr names the listener; there is no socket behind it.
func (l *APIListener) Addr() net.Addr { return apiListenerAddr{} }

type apiListenerAddr struct{}

func (apiListenerAddr) Network() string { return "ssh-channel" }
func (apiListenerAddr) String() string  { return "api-channels" }

// NewAPIConn builds the connection the SSH server hands to the API listener
// for a channel opened by the enrolled key with the given fingerprint. Tests
// and in-process fronts use it; the server builds its own.
func NewAPIConn(conn net.Conn, fingerprint string, remote, local net.Addr) *APIConn {
	return &APIConn{Conn: conn, fingerprint: fingerprint, remote: remote, local: local}
}
