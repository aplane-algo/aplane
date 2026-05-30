// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
	tea "github.com/charmbracelet/bubbletea"
)

func TestWaitForMessageCmdReturnsErrorWhenDisconnected(t *testing.T) {
	m := Model{}
	msg := m.waitForMessageCmd()()
	errMsg, ok := msg.(ErrorMsg)
	if !ok {
		t.Fatalf("m.waitForMessageCmd() message type = %T, want ErrorMsg", msg)
	}
	if errMsg.Error == nil || errMsg.Error.Error() != "not connected" {
		t.Fatalf("m.waitForMessageCmd() error = %v, want not connected", errMsg.Error)
	}
}

func TestIPCClientForwardsSignRequestCanceled(t *testing.T) {
	raw, err := protocol.MarshalAdminMessage(protocol.SignRequestCanceledMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignRequestCanceled, ID: "sign-1"},
		Reason:      "client_canceled",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage(sign_request_canceled): %v", err)
	}

	client := &IPCClient{
		msgChan:   make(chan queuedMsg, 2),
		done:      make(chan struct{}),
		sessionID: 1,
	}
	notifications := make(chan transport.Notification, 1)
	lifecycle := make(chan transport.LifecycleEvent)
	go client.forwardMessages(1, client.done, notifications, lifecycle)
	defer close(client.done)

	notifications <- transport.Notification{
		Base: protocol.BaseMessage{
			Kind: protocol.MessageKindNotification,
			Type: protocol.MsgTypeSignRequestCanceled,
			ID:   "sign-1",
		},
		Raw: raw,
	}

	msg := client.ListenForMessages()()
	canceled, ok := msg.(SignRequestCanceledMsg)
	if !ok {
		t.Fatalf("forwarded message type = %T, want SignRequestCanceledMsg", msg)
	}
	if canceled.ID != "sign-1" || canceled.Reason != "client_canceled" {
		t.Fatalf("SignRequestCanceledMsg = %#v, want sign-1 client_canceled", canceled)
	}
}

func TestIPCClientSendBackupRestoreMessagesUseSensitivePassphraseWireString(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	client := NewAdminClient(&queueConnector{
		conns: []io.ReadWriteCloser{clientConn},
	})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	reader := bufio.NewReader(serverConn)
	backupLineCh := make(chan []byte, 1)
	backupErrCh := make(chan error, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			backupErrCh <- err
			return
		}
		backupLineCh <- line
	}()
	if err := client.SendBackup("backup-passphrase"); err != nil {
		t.Fatalf("SendBackup() error = %v", err)
	}
	var line []byte
	select {
	case err := <-backupErrCh:
		t.Fatalf("ReadBytes(backup) error = %v", err)
	case line = <-backupLineCh:
	case <-time.After(time.Second):
		t.Fatal("timed out reading backup message")
	}
	var backup protocol.BackupMessage
	if err := json.Unmarshal(line, &backup); err != nil {
		t.Fatalf("Unmarshal(backup) error = %v", err)
	}
	if backup.Type != protocol.MsgTypeBackup {
		t.Fatalf("backup.Type = %q, want %q", backup.Type, protocol.MsgTypeBackup)
	}
	if string(backup.ExportPassphrase) != "backup-passphrase" {
		t.Fatalf("backup.ExportPassphrase = %q", string(backup.ExportPassphrase))
	}

	passphrase := []byte("export-passphrase")
	previewLineCh := make(chan []byte, 1)
	previewErrCh := make(chan error, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			previewErrCh <- err
			return
		}
		previewLineCh <- line
	}()
	if err := client.SendPreviewRestore("aplane-backup.tar.gz", passphrase); err != nil {
		t.Fatalf("SendPreviewRestore() error = %v", err)
	}
	select {
	case err := <-previewErrCh:
		t.Fatalf("ReadBytes(preview) error = %v", err)
	case line = <-previewLineCh:
	case <-time.After(time.Second):
		t.Fatal("timed out reading preview message")
	}
	var preview protocol.PreviewRestoreMessage
	if err := json.Unmarshal(line, &preview); err != nil {
		t.Fatalf("Unmarshal(preview) error = %v", err)
	}
	if preview.Type != protocol.MsgTypePreviewRestore {
		t.Fatalf("preview.Type = %q, want %q", preview.Type, protocol.MsgTypePreviewRestore)
	}
	if preview.ArchivePath != "aplane-backup.tar.gz" {
		t.Fatalf("preview.ArchivePath = %q", preview.ArchivePath)
	}
	if string(preview.ExportPassphrase) != "export-passphrase" {
		t.Fatalf("preview.ExportPassphrase = %q", string(preview.ExportPassphrase))
	}

	restoreLineCh := make(chan []byte, 1)
	restoreErrCh := make(chan error, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			restoreErrCh <- err
			return
		}
		restoreLineCh <- line
	}()
	if err := client.SendRestoreBackup("aplane-backup.tar.gz", []string{"ADDR1"}, true, passphrase); err != nil {
		t.Fatalf("SendRestoreBackup() error = %v", err)
	}
	select {
	case err := <-restoreErrCh:
		t.Fatalf("ReadBytes(restore) error = %v", err)
	case line = <-restoreLineCh:
	case <-time.After(time.Second):
		t.Fatal("timed out reading restore message")
	}
	var restore protocol.RestoreBackupMessage
	if err := json.Unmarshal(line, &restore); err != nil {
		t.Fatalf("Unmarshal(restore) error = %v", err)
	}
	if restore.Type != protocol.MsgTypeRestoreBackup {
		t.Fatalf("restore.Type = %q, want %q", restore.Type, protocol.MsgTypeRestoreBackup)
	}
	if len(restore.Addresses) != 1 || restore.Addresses[0] != "ADDR1" {
		t.Fatalf("restore.Addresses = %#v, want [ADDR1]", restore.Addresses)
	}
	if !restore.Overwrite {
		t.Fatal("restore.Overwrite = false, want true")
	}
	if string(restore.ExportPassphrase) != "export-passphrase" {
		t.Fatalf("restore.ExportPassphrase = %q", string(restore.ExportPassphrase))
	}
}

func TestIPCClientSendActivityAndLockMessages(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	client := NewAdminClient(&queueConnector{
		conns: []io.ReadWriteCloser{clientConn},
	})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	reader := bufio.NewReader(serverConn)
	type lineResult struct {
		line []byte
		err  error
	}
	startReadLine := func() <-chan lineResult {
		ch := make(chan lineResult, 1)
		go func() {
			line, err := reader.ReadBytes('\n')
			ch <- lineResult{line: line, err: err}
		}()
		return ch
	}
	awaitLine := func(ch <-chan lineResult) []byte {
		t.Helper()
		select {
		case result := <-ch:
			if result.err != nil {
				t.Fatalf("ReadBytes() error = %v", result.err)
			}
			return result.line
		case <-time.After(time.Second):
			t.Fatal("timed out reading IPC message")
			return nil
		}
	}

	activityLineCh := startReadLine()
	if err := client.SendAdminActivity(); err != nil {
		t.Fatalf("SendAdminActivity() error = %v", err)
	}
	activityLine := awaitLine(activityLineCh)
	var activity protocol.AdminActivityMessage
	if err := json.Unmarshal(activityLine, &activity); err != nil {
		t.Fatalf("Unmarshal(activity) error = %v", err)
	}
	if activity.Type != protocol.MsgTypeAdminActivity || activity.ID == "" {
		t.Fatalf("activity = %+v, want admin_activity with ID", activity)
	}

	lockLineCh := startReadLine()
	if err := client.SendLockIdentity(manualLockReason); err != nil {
		t.Fatalf("SendLockIdentity() error = %v", err)
	}
	lockLine := awaitLine(lockLineCh)
	var lock protocol.LockIdentityMessage
	if err := json.Unmarshal(lockLine, &lock); err != nil {
		t.Fatalf("Unmarshal(lock) error = %v", err)
	}
	if lock.Type != protocol.MsgTypeLockIdentity || lock.ID == "" {
		t.Fatalf("lock = %+v, want lock_identity with ID", lock)
	}
	if lock.Reason != manualLockReason {
		t.Fatalf("lock.Reason = %q", lock.Reason)
	}
}

func TestIPCClientSendReplacePolicyMessage(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	client := NewAdminClient(&queueConnector{
		conns: []io.ReadWriteCloser{clientConn},
	})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	reader := bufio.NewReader(serverConn)
	lineCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			errCh <- err
			return
		}
		lineCh <- line
	}()

	if err := client.SendReplacePolicy("max_fee_microalgos: 4321\n", "abc123"); err != nil {
		t.Fatalf("SendReplacePolicy() error = %v", err)
	}

	var line []byte
	select {
	case err := <-errCh:
		t.Fatalf("ReadBytes(replace policy) error = %v", err)
	case line = <-lineCh:
	case <-time.After(time.Second):
		t.Fatal("timed out reading replace policy message")
	}
	var msg protocol.ReplacePolicyMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		t.Fatalf("Unmarshal(replace policy) error = %v", err)
	}
	if msg.Type != protocol.MsgTypeReplacePolicy || msg.ID == "" {
		t.Fatalf("replace policy = %+v, want replace_policy with ID", msg)
	}
	if msg.PolicyYAML != "max_fee_microalgos: 4321\n" || msg.ExpectedCurrentSHA256 != "abc123" {
		t.Fatalf("replace policy payload = %+v, want YAML and expected SHA", msg)
	}
}

type queueConnector struct {
	mu    sync.Mutex
	conns []io.ReadWriteCloser
	next  int
}

func (c *queueConnector) Connect() (io.ReadWriteCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next >= len(c.conns) {
		return nil, fmt.Errorf("no queued connection")
	}
	conn := c.conns[c.next]
	c.next++
	return conn, nil
}

func (c *queueConnector) Label() string { return "test" }

func (c *queueConnector) connectCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.next
}

func waitForClientMsg(t *testing.T, client *IPCClient, timeout time.Duration) tea.Msg {
	t.Helper()

	resultCh := make(chan tea.Msg, 1)
	go func() {
		resultCh <- client.ListenForMessages()()
	}()

	select {
	case msg := <-resultCh:
		return msg
	case <-time.After(timeout):
		t.Fatal("timed out waiting for client message")
		return nil
	}
}

func assertNoClientMsg(t *testing.T, client *IPCClient, timeout time.Duration) {
	t.Helper()

	resultCh := make(chan tea.Msg, 1)
	go func() {
		resultCh <- client.ListenForMessages()()
	}()

	select {
	case msg := <-resultCh:
		if msg != nil {
			t.Fatalf("unexpected follow-up message: %T %#v", msg, msg)
		}
	case <-time.After(timeout):
	}
}

func TestIPCClientReconnectCreatesFreshDoneChannelAndKeepsReading(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()
	defer func() { _ = server1.Close() }()
	defer func() { _ = server2.Close() }()

	client := NewAdminClient(&queueConnector{
		conns: []io.ReadWriteCloser{client1, client2},
	})

	if err := client.Connect(); err != nil {
		t.Fatalf("first Connect() error = %v", err)
	}
	firstDone := client.done
	if firstDone == nil {
		t.Fatal("first connection done channel is nil")
	}

	client.Disconnect()
	if client.done != nil {
		t.Fatal("Disconnect() should clear done channel")
	}

	if err := client.Connect(); err != nil {
		t.Fatalf("second Connect() error = %v", err)
	}
	if client.done == nil {
		t.Fatal("second connection done channel is nil")
	}
	if client.done == firstDone {
		t.Fatal("Connect() reused the old done channel after disconnect")
	}

	statusLine, err := protocol.MarshalAdminMessage(StatusMessage{
		BaseMessage: BaseMessage{Type: MsgTypeStatus, ID: "status-1"},
		State:       "unlocked",
		KeyCount:    2,
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage(status) error = %v", err)
	}
	if _, err := server2.Write(append(statusLine, '\n')); err != nil {
		t.Fatalf("server2.Write() error = %v", err)
	}

	msg := waitForClientMsg(t, client, 2*time.Second)
	statusMsg, ok := msg.(SignerStatusMsg)
	if !ok {
		t.Fatalf("msg type = %T, want SignerStatusMsg", msg)
	}
	if statusMsg.Locked || statusMsg.KeyCount != 2 {
		t.Fatalf("SignerStatusMsg = %#v, want unlocked with key count 2", statusMsg)
	}

	client.Disconnect()
}

func TestIPCClientReconnectsAfterConnectionLossAndKeepsReading(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()
	defer func() { _ = server1.Close() }()
	defer func() { _ = server2.Close() }()

	connector := &queueConnector{
		conns: []io.ReadWriteCloser{client1, client2},
	}
	client := NewAdminClient(connector)
	client.reconnectDelay = 10 * time.Millisecond
	client.maxDelay = 20 * time.Millisecond

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	if err := server1.Close(); err != nil {
		t.Fatalf("server1.Close() error = %v", err)
	}

	msg := waitForClientMsg(t, client, 2*time.Second)
	if reconnectingMsg, ok := msg.(ReconnectingMsg); !ok {
		t.Fatalf("first reconnect message type = %T, want ReconnectingMsg", msg)
	} else if reconnectingMsg.Delay <= 0 {
		t.Fatalf("ReconnectingMsg delay = %v, want positive", reconnectingMsg.Delay)
	}

	msg = waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ConnectedMsg); !ok {
		t.Fatalf("second reconnect message type = %T, want ConnectedMsg", msg)
	}

	statusLine, err := protocol.MarshalAdminMessage(StatusMessage{
		BaseMessage: BaseMessage{Type: MsgTypeStatus, ID: "status-after-reconnect"},
		State:       "unlocked",
		KeyCount:    3,
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage(status) error = %v", err)
	}
	if _, err := server2.Write(append(statusLine, '\n')); err != nil {
		t.Fatalf("server2.Write() error = %v", err)
	}

	msg = waitForClientMsg(t, client, 2*time.Second)
	statusMsg, ok := msg.(SignerStatusMsg)
	if !ok {
		t.Fatalf("msg type = %T, want SignerStatusMsg", msg)
	}
	if statusMsg.Locked || statusMsg.KeyCount != 3 {
		t.Fatalf("SignerStatusMsg = %#v, want unlocked with key count 3", statusMsg)
	}
}

func TestIPCClientDisplacementSuppressesReconnect(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()
	defer func() { _ = server1.Close() }()
	defer func() { _ = server2.Close() }()

	connector := &queueConnector{
		conns: []io.ReadWriteCloser{client1, client2},
	}
	client := NewAdminClient(connector)
	client.reconnectDelay = 10 * time.Millisecond
	client.maxDelay = 20 * time.Millisecond

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	displacedLine, err := protocol.MarshalAdminMessage(DisplacedMessage{
		BaseMessage: BaseMessage{Type: MsgTypeDisplaced, ID: "displaced-1"},
		Reason:      "another client authenticated",
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage(displaced) error = %v", err)
	}
	if _, err := server1.Write(append(displacedLine, '\n')); err != nil {
		t.Fatalf("server1.Write() error = %v", err)
	}

	msg := waitForClientMsg(t, client, 2*time.Second)
	displacedMsg, ok := msg.(DisplacedMsg)
	if !ok {
		t.Fatalf("msg type = %T, want DisplacedMsg", msg)
	}
	if displacedMsg.Reason != "another client authenticated" {
		t.Fatalf("DisplacedMsg reason = %q", displacedMsg.Reason)
	}

	time.Sleep(100 * time.Millisecond)
	if got := connector.connectCount(); got != 1 {
		t.Fatalf("connector connect count = %d, want 1 after displacement", got)
	}

	assertNoClientMsg(t, client, 100*time.Millisecond)
}

func TestIPCClientReconnectFiltersQueuedOldSessionNotification(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()
	defer func() { _ = server1.Close() }()
	defer func() { _ = server2.Close() }()

	connector := &queueConnector{
		conns: []io.ReadWriteCloser{client1, client2},
	}
	client := NewAdminClient(connector)
	client.reconnectDelay = 10 * time.Millisecond
	client.maxDelay = 20 * time.Millisecond

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	// Send a notification on the old connection before triggering reconnect.
	// This message is legitimately emitted during the current session, so it
	// will be delivered before the reconnect lifecycle messages.
	statusOld, err := protocol.MarshalAdminMessage(StatusMessage{
		BaseMessage: BaseMessage{Type: MsgTypeStatus, ID: "status-old"},
		State:       "unlocked",
		KeyCount:    99,
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage(status-old) error = %v", err)
	}
	if _, err := server1.Write(append(statusOld, '\n')); err != nil {
		t.Fatalf("server1.Write(status-old) error = %v", err)
	}

	// The old-session status arrives first since it was emitted before disconnect.
	msg := waitForClientMsg(t, client, 2*time.Second)
	if oldStatus, ok := msg.(SignerStatusMsg); !ok {
		t.Fatalf("pre-reconnect message type = %T, want SignerStatusMsg", msg)
	} else if oldStatus.KeyCount != 99 {
		t.Fatalf("pre-reconnect KeyCount = %d, want 99", oldStatus.KeyCount)
	}

	if err := server1.Close(); err != nil {
		t.Fatalf("server1.Close() error = %v", err)
	}

	msg = waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ReconnectingMsg); !ok {
		t.Fatalf("first reconnect message type = %T, want ReconnectingMsg", msg)
	}

	msg = waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ConnectedMsg); !ok {
		t.Fatalf("second reconnect message type = %T, want ConnectedMsg", msg)
	}

	// After reconnect, new-session messages arrive on the fresh connection.
	statusNew, err := protocol.MarshalAdminMessage(StatusMessage{
		BaseMessage: BaseMessage{Type: MsgTypeStatus, ID: "status-new"},
		State:       "unlocked",
		KeyCount:    3,
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage(status-new) error = %v", err)
	}
	if _, err := server2.Write(append(statusNew, '\n')); err != nil {
		t.Fatalf("server2.Write(status-new) error = %v", err)
	}

	msg = waitForClientMsg(t, client, 2*time.Second)
	statusMsg, ok := msg.(SignerStatusMsg)
	if !ok {
		t.Fatalf("post-reconnect msg type = %T, want SignerStatusMsg", msg)
	}
	if statusMsg.KeyCount != 3 {
		t.Fatalf("post-reconnect KeyCount = %d, want 3", statusMsg.KeyCount)
	}
}

func TestIPCClientRapidReconnectCyclesDoNotDuplicateLifecycle(t *testing.T) {
	client1, server1 := net.Pipe()
	client2, server2 := net.Pipe()
	client3, server3 := net.Pipe()
	defer func() { _ = server1.Close() }()
	defer func() { _ = server2.Close() }()
	defer func() { _ = server3.Close() }()

	connector := &queueConnector{
		conns: []io.ReadWriteCloser{client1, client2, client3},
	}
	client := NewAdminClient(connector)
	client.reconnectDelay = 10 * time.Millisecond
	client.maxDelay = 20 * time.Millisecond

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	if err := server1.Close(); err != nil {
		t.Fatalf("server1.Close() error = %v", err)
	}
	msg := waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ReconnectingMsg); !ok {
		t.Fatalf("cycle 1 first message = %T, want ReconnectingMsg", msg)
	}
	msg = waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ConnectedMsg); !ok {
		t.Fatalf("cycle 1 second message = %T, want ConnectedMsg", msg)
	}

	if err := server2.Close(); err != nil {
		t.Fatalf("server2.Close() error = %v", err)
	}
	msg = waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ReconnectingMsg); !ok {
		t.Fatalf("cycle 2 first message = %T, want ReconnectingMsg", msg)
	}
	msg = waitForClientMsg(t, client, 2*time.Second)
	if _, ok := msg.(ConnectedMsg); !ok {
		t.Fatalf("cycle 2 second message = %T, want ConnectedMsg", msg)
	}

	if got := connector.connectCount(); got != 3 {
		t.Fatalf("connector connect count = %d, want 3", got)
	}
}

func TestIPCClientManualDisconnectDoesNotEmitReconnectLifecycle(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	client := NewAdminClient(&queueConnector{
		conns: []io.ReadWriteCloser{clientConn},
	})
	client.reconnectDelay = 10 * time.Millisecond
	client.maxDelay = 20 * time.Millisecond

	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	client.Disconnect()

	assertNoClientMsg(t, client, 100*time.Millisecond)
}
