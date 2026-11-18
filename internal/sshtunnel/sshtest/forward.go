// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtest

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
)

// APIDialer opens a channel to a node's REST API over an SSH connection, as
// sshtunnel.Client.DialSignerAPI does.
type APIDialer interface {
	DialSignerAPI(ctx context.Context) (net.Conn, error)
}

// ForwardAPI listens on a loopback port and carries each connection to it
// over its own channel from dialer, so a test can reach a node's REST API by
// URL. Clients never do this: they dial in-process, and nothing listens. The
// returned function stops the listener and closes every forwarded
// connection; it is safe to call more than once.
func ForwardAPI(dialer APIDialer) (string, func(), error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("listen for the forwarded REST API: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				forwardConn(ctx, local, dialer)
			}()
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			_ = listener.Close()
			wg.Wait()
		})
	}
	return "http://" + listener.Addr().String(), stop, nil
}

// forwardConn copies between local and a new channel until either side
// closes or ctx ends, then closes both.
func forwardConn(ctx context.Context, local net.Conn, dialer APIDialer) {
	defer func() { _ = local.Close() }()
	remote, err := dialer.DialSignerAPI(ctx)
	if err != nil {
		return
	}
	defer func() { _ = remote.Close() }()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, local); done <- struct{}{} }()
	go func() { _, _ = io.Copy(local, remote); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
