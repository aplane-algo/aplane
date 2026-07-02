// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

func TestErrors(t *testing.T) {
	// Test that sentinel errors are properly defined
	if !errors.Is(ErrAlreadyConnected, ErrAlreadyConnected) {
		t.Error("ErrAlreadyConnected is not itself")
	}
	if !errors.Is(ErrUnauthorized, ErrUnauthorized) {
		t.Error("ErrUnauthorized is not itself")
	}

	// Test error messages
	if ErrAlreadyConnected.Error() == "" {
		t.Error("ErrAlreadyConnected has empty message")
	}
	if ErrUnauthorized.Error() == "" {
		t.Error("ErrUnauthorized has empty message")
	}
}

func TestNewIPC(t *testing.T) {
	client := NewIPC("/tmp/test.sock")
	switch {
	case client == nil:
		t.Fatal("NewIPC returned nil")
	case client.socketPath != "/tmp/test.sock":
		t.Errorf("socketPath = %q, want %q", client.socketPath, "/tmp/test.sock")
	}
}

func TestIPCCloseNilConn(t *testing.T) {
	// Close should not panic when conn is nil
	client := NewIPC("/tmp/test.sock")
	client.Close() // Should not panic
}

func TestIPCSetDeadlineNilConn(t *testing.T) {
	// SetReadDeadline and ClearReadDeadline should not panic when conn is nil
	client := NewIPC("/tmp/test.sock")
	client.SetReadDeadline(5)  // Should not panic
	client.ClearReadDeadline() // Should not panic
}

func TestIPCLazyDispatcherInitialization(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	if client.dispatcher != nil {
		t.Fatal("dispatcher should start nil")
	}
	if client.Notifications() == nil {
		t.Fatal("Notifications() returned nil channel")
	}
	if client.dispatcher == nil {
		t.Fatal("Notifications() did not initialize dispatcher")
	}
	existing := client.dispatcher
	if client.LifecycleEvents() == nil {
		t.Fatal("LifecycleEvents() returned nil channel")
	}
	if client.dispatcher != existing {
		t.Fatal("LifecycleEvents() replaced existing dispatcher unexpectedly")
	}
}

func TestIPCAdminDispatcherConcurrentSafe(t *testing.T) {
	client := NewIPC("/tmp/test.sock")
	const workers = 32

	var wg sync.WaitGroup
	results := make(chan *dispatcher, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- client.adminDispatcher()
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

func TestIPCSendAndReceiveInitializesDispatcher(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	go func() {
		reader := bufio.NewReader(serverConn)
		line, _ := reader.ReadBytes('\n')
		var req protocol.ListKeysMessage
		_ = json.Unmarshal(line[:len(line)-1], &req)
		_, _ = serverConn.Write(mustJSONLine(t, protocol.KeysListMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysList, ID: req.ID},
			Keys:        []protocol.KeyInfo{},
		}))
	}()

	_, err := client.SendAndReceive(protocol.ListKeysMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListKeys, ID: "keys-1"},
	}, time.Second)
	if err != nil {
		t.Fatalf("SendAndReceive() error = %v", err)
	}
	if client.dispatcher == nil {
		t.Fatal("SendAndReceive() did not initialize dispatcher")
	}
}

func TestIPCUnlockInitializesDispatcher(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	go func() {
		reader := bufio.NewReader(serverConn)
		line, _ := reader.ReadBytes('\n')
		var req protocol.UnlockMessage
		_ = json.Unmarshal(line[:len(line)-1], &req)
		_, _ = serverConn.Write(mustJSONLine(t, protocol.UnlockResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeUnlockResult, ID: req.ID},
			Success:     true,
			KeyCount:    1,
		}))
	}()

	got, err := client.Unlock("secret", time.Second)
	if err != nil {
		t.Fatalf("Unlock() error = %v", err)
	}
	if !got.Success || got.KeyCount != 1 {
		t.Fatalf("Unlock() = %+v, want success/key_count=1", got)
	}
	if client.dispatcher == nil {
		t.Fatal("Unlock() did not initialize dispatcher")
	}
}

func TestIPCCloseClearsDispatcher(t *testing.T) {
	client := NewIPC("/tmp/test.sock")
	client.dispatcher = newDispatcher(&stubAdminProtocolConn{})
	client.Close()
	if client.dispatcher != nil {
		t.Fatal("Close() did not clear dispatcher")
	}
}

func TestTransportInterface(t *testing.T) {
	// Verify IPC client implements Transport interface
	var _ Transport = (*IPCClient)(nil)
}

func TestIPCAuthenticateHappyPath(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)

		if _, err := serverConn.Write(mustJSONLine(t, protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired})); err != nil {
			errCh <- err
			return
		}

		reader := bufio.NewReader(serverConn)
		line, err := reader.ReadBytes('\n')
		if err != nil {
			errCh <- err
			return
		}

		var auth protocol.AuthMessage
		if err := json.Unmarshal([]byte(strings.TrimSuffix(string(line), "\n")), &auth); err != nil {
			errCh <- err
			return
		}
		if auth.Type != protocol.MsgTypeAuth || auth.Kind != protocol.MessageKindRequest || string(auth.Passphrase) != "secret" {
			errCh <- errors.New("unexpected auth request payload")
			return
		}
		if auth.ProtocolVersion == nil || *auth.ProtocolVersion != protocol.CurrentAdminProtocolVersion() {
			errCh <- fmt.Errorf("auth protocol_version = %+v, want %+v", auth.ProtocolVersion, protocol.CurrentAdminProtocolVersion())
			return
		}

		if _, err := serverConn.Write(mustJSONLine(t, protocol.AuthResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
			Success:     true,
		})); err != nil {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	if err := client.Authenticate("secret", time.Second); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server side error = %v", err)
	}
}

func TestIPCAuthenticateClientExistsMismatch(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	go func() {
		// Send client_exists message
		_, _ = serverConn.Write(mustJSONLine(t, protocol.ClientExistsMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeClientExists},
		}))
		// The authenticate() loop handles client_exists by writing displace_confirm
		// and then looping to read the next message. We must drain the displace_confirm
		// so the client's WriteJSON doesn't block on the unbuffered pipe, then close
		// so the next ReadMessage returns EOF.
		reader := bufio.NewReader(serverConn)
		_, _ = reader.ReadBytes('\n')
		_ = serverConn.Close()
	}()

	err := client.Authenticate("secret", time.Second)
	if err == nil {
		t.Fatal("Authenticate() error = nil, want error after displacement")
	}
	if errors.Is(err, ErrAlreadyConnected) {
		t.Fatalf("Authenticate() unexpectedly mapped to ErrAlreadyConnected: %v", err)
	}
	// After displacement, the client reads again and gets EOF (connection closed)
	if !strings.Contains(err.Error(), "failed to receive auth_required") {
		t.Fatalf("Authenticate() error = %q, want auth_required failure after displacement", err)
	}
}

func TestIPCAuthenticateUnauthorizedReturnsFormattedError(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)

		if _, err := serverConn.Write(mustJSONLine(t, protocol.BaseMessage{Type: protocol.MsgTypeAuthRequired})); err != nil {
			errCh <- err
			return
		}

		reader := bufio.NewReader(serverConn)
		if _, err := reader.ReadBytes('\n'); err != nil {
			errCh <- err
			return
		}

		if _, err := serverConn.Write(mustJSONLine(t, protocol.AuthResultMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeAuthResult},
			Success:     false,
			Error:       "invalid passphrase",
		})); err != nil {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	err := client.Authenticate("secret", time.Second)
	if err == nil {
		t.Fatal("Authenticate() error = nil, want auth failure")
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Authenticate() unexpectedly mapped to ErrUnauthorized: %v", err)
	}
	if !strings.Contains(err.Error(), "authentication failed: invalid passphrase") {
		t.Fatalf("Authenticate() error = %q, want formatted auth failure", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server side error = %v", err)
	}
}

func TestIPCAuthenticatePreAuthErrorIncludesServerReason(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	client := NewIPC("/tmp/test.sock")
	client.conn = clientConn
	client.reader = bufio.NewReader(clientConn)

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		_, err := serverConn.Write(mustJSONLine(t, protocol.ErrorMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError},
			Error:       "another apadmin client is currently authenticating",
		}))
		errCh <- err
	}()

	err := client.Authenticate("secret", time.Second)
	if err == nil {
		t.Fatal("Authenticate() error = nil, want server rejection")
	}
	if !strings.Contains(err.Error(), "another apadmin client is currently authenticating") {
		t.Fatalf("Authenticate() error = %q, want server reason", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server side error = %v", err)
	}
}

func mustJSONLine(t *testing.T, v any) []byte {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	return append(data, '\n')
}
