// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

type fakeNotificationStream struct {
	dropped    atomic.Uint64
	drops      chan struct{}
	readerDone chan struct{}
}

func newFakeNotificationStream() *fakeNotificationStream {
	return &fakeNotificationStream{drops: make(chan struct{}, 1), readerDone: make(chan struct{})}
}

func (s *fakeNotificationStream) DroppedNotifications() uint64       { return s.dropped.Load() }
func (s *fakeNotificationStream) NotificationDrops() <-chan struct{} { return s.drops }
func (s *fakeNotificationStream) ReaderDone() <-chan struct{}        { return s.readerDone }

func (s *fakeNotificationStream) drop(n uint64) {
	s.dropped.Add(n)
	select {
	case s.drops <- struct{}{}:
	default:
	}
}

func waitForLossChange(t *testing.T, loss *notificationLoss) {
	t.Helper()
	select {
	case <-loss.changed:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a change signal")
	}
}

func waitForLiveStreams(t *testing.T, loss *notificationLoss, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		loss.mu.Lock()
		live := len(loss.live)
		loss.mu.Unlock()
		if live == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("live streams did not reach %d", want)
}

func TestNotificationLossCountsEachStreamOnce(t *testing.T) {
	loss := newNotificationLoss()
	first := newFakeNotificationStream()
	loss.track(first)

	for _, step := range []struct {
		drop uint64
		want uint64
	}{{2, 2}, {3, 5}, {0, 5}} {
		first.drop(step.drop)
		waitForLossChange(t, loss)
		if got := loss.total(); got != step.want {
			t.Fatalf("total() = %d, want %d", got, step.want)
		}
	}

	close(first.readerDone)
	waitForLiveStreams(t, loss, 0)
	if got := loss.total(); got != 5 {
		t.Fatalf("total() after retiring = %d, want 5, counted once", got)
	}

	second := newFakeNotificationStream()
	loss.track(second)
	second.drop(1)
	waitForLossChange(t, loss)
	if got := loss.total(); got != 6 {
		t.Fatalf("total() after reconnect = %d, want 6", got)
	}
	close(second.readerDone)
	waitForLiveStreams(t, loss, 0)
}

func TestNotificationLossCountsDropsAfterTheStreamIsReplaced(t *testing.T) {
	loss := newNotificationLoss()
	old := newFakeNotificationStream()
	loss.track(old)
	old.drop(1)

	// Closing a stream doesn't stop its reader at once: it can still drop while
	// the replacement is running.
	replacement := newFakeNotificationStream()
	loss.track(replacement)
	old.drop(2)
	replacement.drop(4)
	if got := loss.total(); got != 7 {
		t.Fatalf("total() = %d, want 7 with both streams counted", got)
	}

	old.drop(8)
	close(old.readerDone)
	waitForLiveStreams(t, loss, 1)
	if got := loss.total(); got != 15 {
		t.Fatalf("total() = %d, want 15 including the late drop", got)
	}
	close(replacement.readerDone)
	waitForLiveStreams(t, loss, 0)
	if got := loss.total(); got != 15 {
		t.Fatalf("final total() = %d, want 15", got)
	}
}

func TestNotificationLossTotalNeverDecreasesDuringRetirement(t *testing.T) {
	loss := newNotificationLoss()
	const streams = 20

	stop := make(chan struct{})
	var observer sync.WaitGroup
	observer.Add(1)
	go func() {
		defer observer.Done()
		var last uint64
		for {
			select {
			case <-stop:
				return
			default:
			}
			total := loss.total()
			if total < last {
				t.Errorf("total went from %d to %d", last, total)
				return
			}
			last = total
		}
	}()

	var wg sync.WaitGroup
	for range streams {
		stream := newFakeNotificationStream()
		loss.track(stream)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				stream.drop(1)
			}
			close(stream.readerDone)
		}()
	}
	wg.Wait()
	waitForLiveStreams(t, loss, 0)
	close(stop)
	observer.Wait()

	if got := loss.total(); got != streams*100 {
		t.Fatalf("total() = %d, want %d", got, streams*100)
	}
}

func TestNotificationLossSignalsWhenAStreamRetires(t *testing.T) {
	loss := newNotificationLoss()
	stream := newFakeNotificationStream()
	loss.track(stream)

	close(stream.readerDone)

	waitForLossChange(t, loss)
}

func keysChangedFrame(t *testing.T) []byte {
	t.Helper()
	frame, err := protocol.MarshalAdminMessage(KeysChangedMessage{
		BaseMessage: BaseMessage{Type: MsgTypeKeysChanged},
	})
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	return append(frame, '\n')
}

// overflowClient queues frames from nobody reading the client until the buffers
// overflow, so notifications are dropped.
func overflowClient(t *testing.T, server net.Conn) {
	t.Helper()
	frame := keysChangedFrame(t)
	// net.Pipe has no buffer, so a client that stopped reading would hang here.
	if err := server.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}
	for range 120 {
		if _, err := server.Write(frame); err != nil {
			t.Fatalf("server.Write() error = %v", err)
		}
	}
}

func drainForLoss(t *testing.T, client *IPCClient, want uint64) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	var got uint64
	for {
		result := make(chan tea.Msg, 1)
		go func() { result <- client.ListenForMessages()() }()
		select {
		case msg := <-result:
			if lost, ok := msg.(NotificationsLostMsg); ok {
				got = max(got, lost.Total)
				if got == want {
					return
				}
				if got > want {
					t.Fatalf("reported %d lost, want %d", got, want)
				}
			}
		case <-deadline:
			t.Fatalf("timed out with %d reported lost, want %d", got, want)
		}
	}
}

func TestIPCClientReportsOverflowFollowedByDisconnect(t *testing.T) {
	clientConn, server := net.Pipe()
	client := NewAdminClient(&queueConnector{conns: []io.ReadWriteCloser{clientConn}})
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	overflowClient(t, server)
	_ = server.Close()
	waitForLiveStreams(t, client.notificationLoss, 0)

	total := client.notificationLoss.total()
	if total == 0 {
		t.Fatal("expected the overflow to drop notifications")
	}
	drainForLoss(t, client, total)
}

func TestIPCClientLossTotalSurvivesReconnect(t *testing.T) {
	firstConn, firstServer := net.Pipe()
	secondConn, secondServer := net.Pipe()
	defer func() { _ = secondServer.Close() }()
	connector := &queueConnector{conns: []io.ReadWriteCloser{firstConn, secondConn}}
	client := NewAdminClient(connector)
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	defer client.Disconnect()

	overflowClient(t, firstServer)
	_ = firstServer.Close()
	waitForLiveStreams(t, client.notificationLoss, 0)
	first := client.notificationLoss.total()
	drainForLoss(t, client, first)

	// The forwarder reconnects only once it has handed over what it queued, and
	// client.connected stays true until then, so watch the connector itself.
	deadline := time.Now().Add(10 * time.Second)
	for connector.connectCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the reconnect")
		}
		select {
		case <-client.msgChan:
		case <-time.After(5 * time.Millisecond):
		}
	}

	overflowClient(t, secondServer)
	_ = secondServer.Close()
	deadline = time.Now().Add(5 * time.Second)
	for client.notificationLoss.total() <= first {
		if time.Now().After(deadline) {
			t.Fatalf("total stayed at %d after a second overflow", first)
		}
		time.Sleep(time.Millisecond)
	}
	waitForLiveStreams(t, client.notificationLoss, 0)
	drainForLoss(t, client, client.notificationLoss.total())
}

func TestReconnectCmdKeepsLossTotalAcrossClients(t *testing.T) {
	firstConn, firstServer := net.Pipe()
	secondConn, secondServer := net.Pipe()
	defer func() { _ = secondServer.Close() }()
	connector := &queueConnector{conns: []io.ReadWriteCloser{firstConn, secondConn}}
	oldClient := NewAdminClient(connector)
	if err := oldClient.Connect(); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	overflowClient(t, firstServer)
	_ = firstServer.Close()
	waitForLiveStreams(t, oldClient.notificationLoss, 0)
	total := oldClient.notificationLoss.total()
	if total == 0 {
		t.Fatal("expected the overflow to drop notifications")
	}

	msg := Model{connector: connector, adminClient: oldClient}.reconnectCmd()()
	connected, ok := msg.(ConnectedMsg)
	if !ok {
		t.Fatalf("reconnectCmd() = %T, want ConnectedMsg", msg)
	}
	newClient := connected.Client
	defer newClient.Disconnect()

	if got := newClient.notificationLoss.total(); got != total {
		t.Fatalf("new client's total = %d, want %d carried over", got, total)
	}
	lost, ok := waitForClientMsg(t, newClient, 2*time.Second).(NotificationsLostMsg)
	if !ok || lost.Total != total {
		t.Fatalf("first message = %#v, want the carried-over total %d", lost, total)
	}
}

func TestModelKeepsHighestReportedLossAcrossOutOfOrderTotals(t *testing.T) {
	m := Model{}
	for _, total := range []uint64{2, 5, 5, 3} {
		updated, _ := m.Update(NotificationsLostMsg{Total: total})
		m = updated.(Model)
	}
	if m.notificationsLost != 5 {
		t.Fatalf("notificationsLost = %d, want 5", m.notificationsLost)
	}
}

func TestStatusBarShowsLossPersistently(t *testing.T) {
	for _, tc := range []struct {
		total uint64
		want  string
	}{
		{1, "Warning: 1 signer notification lost"},
		{3, "Warning: 3 signer notifications lost"},
	} {
		t.Run(fmt.Sprint(tc.total), func(t *testing.T) {
			bar := Model{notificationsLost: tc.total, lastWarning: "", lastNotice: "saved"}.renderStatusBar()
			if !strings.Contains(bar, tc.want) {
				t.Fatalf("status bar %q does not contain %q", bar, tc.want)
			}
		})
	}
	if bar := (Model{}).renderStatusBar(); strings.Contains(bar, "lost") {
		t.Fatalf("status bar %q reports a loss that did not happen", bar)
	}
}
