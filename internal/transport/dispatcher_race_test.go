// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package transport

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// raceConn hands the read loop the frames a test pushes, reports each write's
// request ID, and fails a write when writeErr says so.
type raceConn struct {
	reads    chan []byte
	writes   chan string
	done     chan struct{}
	writeErr func(id string) error
}

func newRaceConn(t *testing.T) *raceConn {
	c := &raceConn{reads: make(chan []byte), writes: make(chan string, 8), done: make(chan struct{})}
	t.Cleanup(func() { close(c.done) })
	return c
}

func (c *raceConn) WriteJSON(v interface{}) error {
	id, _ := messageID(v)
	c.writes <- id
	if c.writeErr != nil {
		return c.writeErr(id)
	}
	return nil
}

func (c *raceConn) ReadMessage() ([]byte, error) {
	select {
	case frame := <-c.reads:
		return frame, nil
	case <-c.done:
		return nil, errors.New("test over")
	}
}

func raceReply(t *testing.T, id, marker string) []byte {
	t.Helper()
	return mustMarshalProtocolMessage(t, protocol.KeysListMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeKeysList, ID: id},
		Keys:        []protocol.AdminKeyInfo{{Address: marker}},
	})
}

func raceRequest(id string) protocol.ListKeysMessage {
	return protocol.ListKeysMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeListKeys, ID: id}}
}

type raceResult struct {
	raw []byte
	err error
}

func startRequest(d *dispatcher, id string, timeout time.Duration) <-chan raceResult {
	out := make(chan raceResult, 1)
	go func() {
		raw, err := d.request(raceRequest(id), timeout)
		out <- raceResult{raw, err}
	}()
	return out
}

// awaitMatched waits until the read loop has taken id's waiter from pending,
// which it does just before sending that waiter its reply.
func awaitMatched(t *testing.T, d *dispatcher, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		_, pending := d.pending[id]
		d.mu.Unlock()
		if !pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the read loop never matched %s", id)
}

func awaitResult(t *testing.T, name string, results <-chan raceResult) raceResult {
	t.Helper()
	select {
	case r := <-results:
		return r
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never returned", name)
		return raceResult{}
	}
}

// onFirstTimeout runs fn in the first request whose timer fires, before it
// handles the timeout.
func onFirstTimeout(d *dispatcher, fn func()) {
	var once sync.Once
	d.afterTimeout = func() { once.Do(fn) }
}

// A reply the read loop matches after the request's timer fired, but before
// the timeout is handled, is returned to the request.
func TestTimeoutReturnsAReplyMatchedBeforeItIsHandled(t *testing.T) {
	conn := newRaceConn(t)
	d := newDispatcher(conn)
	reply := raceReply(t, "X", "reply-a")
	onFirstTimeout(d, func() {
		conn.reads <- reply
		awaitMatched(t, d, "X")
	})

	a := startRequest(d, "X", 10*time.Millisecond)
	<-conn.writes
	got := awaitResult(t, "the request", a)
	if got.err != nil || !bytes.Equal(got.raw, reply) {
		t.Fatalf("request = %q, %v; want its matched reply", got.raw, got.err)
	}
}

// A request whose timeout is handled after its reply was matched, and after a
// second request took the same ID, takes its own reply and leaves the second
// request's entry alone; the second request then gets its own reply.
func TestTimeoutLeavesALaterRequestWithTheSameIDAlone(t *testing.T) {
	conn := newRaceConn(t)
	d := newDispatcher(conn)
	replyA, replyB := raceReply(t, "X", "reply-a"), raceReply(t, "X", "reply-b")
	var b <-chan raceResult
	onFirstTimeout(d, func() {
		conn.reads <- replyA
		awaitMatched(t, d, "X")
		// Shorter than awaitResult's wait, so a request stuck past its own
		// timeout shows as never returning.
		b = startRequest(d, "X", 2*time.Second)
		<-conn.writes
	})

	a := startRequest(d, "X", 10*time.Millisecond)
	<-conn.writes
	gotA := awaitResult(t, "the first request", a)
	if gotA.err != nil || !bytes.Equal(gotA.raw, replyA) {
		t.Errorf("first request = %q, %v; want its matched reply", gotA.raw, gotA.err)
	}
	conn.reads <- replyB
	gotB := awaitResult(t, "the second request", b)
	if gotB.err != nil || !bytes.Equal(gotB.raw, replyB) {
		t.Fatalf("second request = %q, %v; want its own reply", gotB.raw, gotB.err)
	}
}

// A request whose write fails after a reply with its ID was matched to it
// zeroes that reply and leaves a later request with the same ID alone.
func TestWriteFailureLeavesALaterRequestWithTheSameIDAlone(t *testing.T) {
	conn := newRaceConn(t)
	d := newDispatcher(conn)
	stale, replyB := raceReply(t, "X", "stale"), raceReply(t, "X", "reply-b")
	// Start the read loop with a request that completes normally.
	first := startRequest(d, "warm-up", 5*time.Second)
	<-conn.writes
	conn.reads <- raceReply(t, "warm-up", "ok")
	if r := awaitResult(t, "the warm-up request", first); r.err != nil {
		t.Fatal(r.err)
	}

	var b <-chan raceResult
	var writes atomic.Int32
	conn.writeErr = func(id string) error {
		if writes.Add(1) > 1 {
			return nil
		}
		conn.reads <- stale
		awaitMatched(t, d, "X")
		b = startRequest(d, "X", 5*time.Second)
		<-conn.writes
		return errors.New("write failed")
	}
	a := startRequest(d, "X", 5*time.Second)
	<-conn.writes
	if r := awaitResult(t, "the failed request", a); r.err == nil || r.err.Error() != "write failed" {
		t.Fatalf("failed request = %q, %v; want the write error", r.raw, r.err)
	}
	if !isZeroed(stale) {
		t.Fatalf("reply matched to the failed request left as %q", stale)
	}
	conn.reads <- replyB
	gotB := awaitResult(t, "the second request", b)
	if gotB.err != nil || !bytes.Equal(gotB.raw, replyB) {
		t.Fatalf("second request = %q, %v; want its own reply", gotB.raw, gotB.err)
	}
}
