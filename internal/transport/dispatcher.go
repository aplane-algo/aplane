// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

type dispatcherLifecycleType string

const (
	dispatcherLifecycleConnectionLost dispatcherLifecycleType = "connection_lost"
	dispatcherLifecycleProtocolError  dispatcherLifecycleType = "fatal_protocol_error"
	dispatcherLifecycleReaderStopped  dispatcherLifecycleType = "reader_stopped"
)

type Notification struct {
	Base protocol.BaseMessage
	Raw  []byte
}

type LifecycleType string

const (
	LifecycleConnectionLost LifecycleType = LifecycleType(dispatcherLifecycleConnectionLost)
	LifecycleProtocolError  LifecycleType = LifecycleType(dispatcherLifecycleProtocolError)
	LifecycleReaderStopped  LifecycleType = LifecycleType(dispatcherLifecycleReaderStopped)
)

type LifecycleEvent struct {
	Type LifecycleType
	Err  error
}

type dispatcher struct {
	conn adminProtocolConn
	// strictUnknownResponses keeps synchronous request flows fail-closed:
	// unmatched responses become protocol errors instead of being surfaced to
	// the notification stream.
	strictUnknownResponses bool

	mu            sync.Mutex
	started       bool
	closed        bool
	pending       map[string]chan dispatchResult
	notifications chan Notification
	lifecycle     chan LifecycleEvent

	// droppedNotifications counts notifications discarded because the
	// notifications buffer was full. Approval-request notifications flow
	// through this channel, so drops must be observable rather than silent.
	droppedNotifications atomic.Uint64
}

type dispatchResult struct {
	raw []byte
	err error
}

func newDispatcher(conn adminProtocolConn) *dispatcher {
	return newDispatcherWithMode(conn, true)
}

func newDispatcherWithMode(conn adminProtocolConn, strictUnknownResponses bool) *dispatcher {
	return &dispatcher{
		conn:                   conn,
		strictUnknownResponses: strictUnknownResponses,
		pending:                make(map[string]chan dispatchResult),
		notifications:          make(chan Notification, 64),
		lifecycle:              make(chan LifecycleEvent, 16),
	}
}

// DroppedNotifications reports how many notifications were discarded because
// the notification buffer was full.
func (d *dispatcher) DroppedNotifications() uint64 {
	return d.droppedNotifications.Load()
}

func (d *dispatcher) request(msg interface{}, timeout time.Duration) ([]byte, error) {
	requestID, err := messageID(msg)
	if err != nil {
		return nil, err
	}
	if requestID == "" {
		return nil, fmt.Errorf("dispatcher request missing message ID")
	}

	waiter := make(chan dispatchResult, 1)

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, fmt.Errorf("dispatcher closed")
	}
	if _, exists := d.pending[requestID]; exists {
		d.mu.Unlock()
		return nil, fmt.Errorf("duplicate pending request ID: %s", requestID)
	}
	d.pending[requestID] = waiter
	shouldStart := !d.started
	d.mu.Unlock()

	if err := d.conn.WriteJSON(msg); err != nil {
		d.mu.Lock()
		delete(d.pending, requestID)
		d.mu.Unlock()
		return nil, err
	}

	if shouldStart {
		d.mu.Lock()
		d.startLocked()
		d.mu.Unlock()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-waiter:
		return result.raw, result.err
	case <-timer.C:
		d.mu.Lock()
		delete(d.pending, requestID)
		d.mu.Unlock()
		return nil, fmt.Errorf("timed out waiting for response to %s", requestID)
	}
}

func (d *dispatcher) notificationsChan() <-chan Notification {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started && !d.closed {
		d.startLocked()
	}
	return d.notifications
}

func (d *dispatcher) lifecycleChan() <-chan LifecycleEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started && !d.closed {
		d.startLocked()
	}
	return d.lifecycle
}

func (d *dispatcher) startLocked() {
	if d.started || d.closed {
		return
	}
	d.started = true
	go d.readLoop()
}

func (d *dispatcher) readLoop() {
	for {
		response, err := d.conn.ReadMessage()
		if err != nil {
			d.failAll(dispatcherLifecycleConnectionLost, err)
			return
		}

		base, err := parseBaseMessage(response)
		if err != nil {
			d.failAll(dispatcherLifecycleProtocolError, err)
			return
		}

		d.mu.Lock()
		waiter, ok := d.pending[base.ID]
		if ok {
			delete(d.pending, base.ID)
			d.mu.Unlock()
			waiter <- dispatchResult{raw: response}
			continue
		}

		if base.Kind == protocol.MessageKindNotification ||
			(base.Kind == protocol.MessageKindResponse && !d.strictUnknownResponses) {
			notification := Notification{Base: base, Raw: response}
			d.mu.Unlock()
			select {
			case d.notifications <- notification:
			default:
				dropped := d.droppedNotifications.Add(1)
				slog.Warn("admin notification dropped: buffer full",
					"type", base.Type,
					"id", base.ID,
					"dropped_total", dropped)
			}
			continue
		}

		d.mu.Unlock()
		d.failAll(dispatcherLifecycleProtocolError, fmt.Errorf("unexpected %s message without pending waiter: type=%s id=%s", base.Kind, base.Type, base.ID))
		return
	}
}

func (d *dispatcher) failAll(kind dispatcherLifecycleType, err error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	pending := d.pending
	d.pending = make(map[string]chan dispatchResult)
	lifecycleCh := d.lifecycle
	d.mu.Unlock()

	sendLifecycleEvent(lifecycleCh, LifecycleEvent{Type: LifecycleType(kind), Err: err})
	sendLifecycleEvent(lifecycleCh, LifecycleEvent{Type: LifecycleReaderStopped})

	for _, waiter := range pending {
		waiter <- dispatchResult{err: err}
	}
}

func sendLifecycleEvent(ch chan LifecycleEvent, event LifecycleEvent) {
	select {
	case ch <- event:
	default:
	}
}
