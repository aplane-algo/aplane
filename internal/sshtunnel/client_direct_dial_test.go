// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sshtunnel

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

func TestClientDialSignerAPIUsesAuthenticatedDirectChannel(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()
	targetDone := make(chan error, 1)
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr != nil {
			targetDone <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		line, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr != nil {
			targetDone <- readErr
			return
		}
		if line != "ping\n" {
			targetDone <- &unexpectedLineError{got: line}
			return
		}
		_, writeErr := conn.Write([]byte("pong\n"))
		targetDone <- writeErr
	}()

	tmpDir := t.TempDir()
	srv, err := NewServer(
		"127.0.0.1:0", target.Addr().String(), filepath.Join(tmpDir, "host_key"),
		filepath.Join(tmpDir, "authorized_keys"), "test-token",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPub, identityPath := generateClientIdentityFile(t, tmpDir)
	srv.authKeysMu.Lock()
	srv.authKeys = append(srv.authKeys, clientPub)
	srv.authKeysMu.Unlock()
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	if err := srv.Start(serverCtx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop() }()

	host, sshPort := splitHostPort(t, srv.listener.Addr().String())
	_, targetPort := splitHostPort(t, target.Addr().String())
	knownHostsPath := filepath.Join(tmpDir, "known_hosts")
	knownHost := knownhosts.Line([]string{hostWithPort(host, sshPort)}, srv.hostKey.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(knownHost), 0o600); err != nil {
		t.Fatal(err)
	}

	client := NewClient(host, sshPort, 0, targetPort, identityPath, knownHostsPath)
	client.SetAPIToken("test-token")
	if err := client.ConnectWithKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	conn, err := client.DialSignerAPI(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	type exchangeResult struct {
		line string
		err  error
	}
	exchangeDone := make(chan exchangeResult, 1)
	go func() {
		if _, writeErr := conn.Write([]byte("ping\n")); writeErr != nil {
			exchangeDone <- exchangeResult{err: writeErr}
			return
		}
		line, readErr := bufio.NewReader(conn).ReadString('\n')
		exchangeDone <- exchangeResult{line: line, err: readErr}
	}()
	var exchange exchangeResult
	select {
	case exchange = <-exchangeDone:
	case <-time.After(5 * time.Second):
		_ = conn.Close()
		t.Fatal("timed out waiting for direct-channel reply")
	}
	if exchange.err != nil {
		t.Fatal(exchange.err)
	}
	line := exchange.line
	if line != "pong\n" {
		t.Fatalf("reply = %q, want pong", line)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

type unexpectedLineError struct {
	got string
}

func (e *unexpectedLineError) Error() string {
	return "unexpected target line: " + e.got
}
