// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import "sync"

// notificationStream is the part of an admin stream that loss tracking reads.
type notificationStream interface {
	DroppedNotifications() uint64
	NotificationDrops() <-chan struct{}
	ReaderDone() <-chan struct{}
}

// notificationLoss totals the admin notifications lost across every stream of a
// TUI session. Approval requests travel as notifications, so a loss must stay
// visible. The total never decreases: it counts each finished stream once and
// each stream still reading as it stands.
//
// Reconnecting replaces the stream, and a forced reconnect replaces the IPCClient
// too, so the clients of one session share a single notificationLoss.
//
// A stream is retired by the goroutine watching it, once its reader has exited
// and its count can no longer change. Closing a stream doesn't prove that, so
// neither Disconnect nor the forwarder's cleanup retires anything, and a stream
// cannot be counted twice.
type notificationLoss struct {
	mu      sync.Mutex
	retired uint64
	live    map[notificationStream]struct{}
	// changed holds one pending signal that total may have moved. A watcher
	// outlives the client that started it, so the signal is shared too: losses
	// on an old stream are reported by whichever client is current.
	changed chan struct{}
}

func newNotificationLoss() *notificationLoss {
	return &notificationLoss{
		live:    make(map[notificationStream]struct{}),
		changed: make(chan struct{}, 1),
	}
}

// track counts stream from now until its reader exits.
func (l *notificationLoss) track(stream notificationStream) {
	l.mu.Lock()
	l.live[stream] = struct{}{}
	l.mu.Unlock()
	go l.watch(stream)
}

func (l *notificationLoss) watch(stream notificationStream) {
	readerDone := stream.ReaderDone()
	for {
		select {
		case <-stream.NotificationDrops():
			l.signalChanged()
		case <-readerDone:
			l.mu.Lock()
			l.retired += stream.DroppedNotifications()
			delete(l.live, stream)
			l.mu.Unlock()
			l.signalChanged()
			return
		}
	}
}

func (l *notificationLoss) signalChanged() {
	select {
	case l.changed <- struct{}{}:
	default:
	}
}

func (l *notificationLoss) total() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	total := l.retired
	for stream := range l.live {
		total += stream.DroppedNotifications()
	}
	return total
}
