// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/transport"
)

// fromListener is msg as the listener delivers it.
func fromListener(msg tea.Msg) tea.Msg { return listenerMsg{msg: msg} }

// isListenerWait reports whether msg is what a listener wait on a
// listenerTestClient returned.
func isListenerWait(msg tea.Msg) bool {
	_, ok := Unwrap(msg).(listenerMarker)
	return ok
}

// listenerMarker stands in for a queued notification on a listenerTestClient.
type listenerMarker struct{}

// listenerTestClient returns a client that is not connected, so every send
// fails at once, holding markers for listener waits to take: a wait started
// on it returns at once.
func listenerTestClient() *IPCClient {
	client := &IPCClient{msgChan: make(chan queuedMsg, 64), done: make(chan struct{}), notificationLoss: newNotificationLoss()}
	for range cap(client.msgChan) {
		client.msgChan <- queuedMsg{msg: listenerMarker{}}
	}
	return client
}

// runPrompt runs cmd as Bubble Tea does, every command in its own goroutine,
// and returns what they deliver at once. Timers and other waits that deliver
// nothing within a moment are left running.
func runPrompt(cmd tea.Cmd) []tea.Msg {
	results := make(chan tea.Msg, 256)
	var pending sync.WaitGroup
	var run func(tea.Cmd)
	run = func(c tea.Cmd) {
		if c == nil {
			return
		}
		pending.Add(1)
		go func() {
			defer pending.Done()
			msg := c()
			if batch, ok := msg.(tea.BatchMsg); ok {
				for _, inner := range batch {
					run(inner)
				}
				return
			}
			if msg != nil {
				results <- msg
			}
		}()
	}
	run(cmd)
	finished := make(chan struct{})
	go func() { pending.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(100 * time.Millisecond):
	}
	var msgs []tea.Msg
	for {
		select {
		case msg := <-results:
			msgs = append(msgs, msg)
		default:
			return msgs
		}
	}
}

func TestListenStartsNothingWithoutAClient(t *testing.T) {
	if cmd := (Model{}).listen(); cmd != nil {
		t.Fatal("listen() with no client started a wait")
	}
}

// Exactly one listener wait is in flight while a session lasts, whatever the
// operator presses and whatever arrives: the first connection starts it, and
// each message it delivers starts the next only once handled. With two, the
// goroutines race for the queue and can hand the model a sign request's
// cancellation before the request.
func TestExactlyOneListenerWaitIsInFlight(t *testing.T) {
	client := listenerTestClient()
	defer close(client.done)
	m := sizedForTest(t, Model{viewState: ViewAuth}, MinWidth, MinHeight)
	inFlight := 0
	var local []tea.Msg

	// apply hands msg to the model and runs what it returns. A message from
	// the signer can arrive only through a wait in flight, and ends it.
	apply := func(step string, msg tea.Msg, fromSigner bool) {
		t.Helper()
		if fromSigner {
			if inFlight == 0 {
				t.Fatalf("%s: no listener wait was in flight to deliver it", step)
			}
			inFlight--
			msg = fromListener(msg)
		}
		next, cmd := m.Update(msg)
		m = next.(Model)
		for _, result := range runPrompt(cmd) {
			if isListenerWait(result) {
				inFlight++
			} else {
				local = append(local, result)
			}
		}
	}
	// settle hands the model what its commands delivered, such as send
	// failures, as Bubble Tea would.
	settle := func(step string) {
		t.Helper()
		for len(local) > 0 {
			msg := local[0]
			local = local[1:]
			apply(step+" result", msg, false)
		}
		if inFlight != 1 {
			t.Fatalf("after %s: %d listener waits in flight, want 1", step, inFlight)
		}
	}
	key := func(k string) tea.KeyMsg {
		switch k {
		case "enter":
			return tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			return tea.KeyMsg{Type: tea.KeyEsc}
		}
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	}

	apply("connect", ConnectedMsg{Client: client}, false)
	settle("connect")
	for _, step := range []struct {
		name string
		msg  tea.Msg
		from bool
	}{
		{"auth required", AuthRequiredMsg{}, true},
		{"type a passphrase", key("pw"), false},
		{"submit it", key("enter"), false},
		{"auth result", AuthResultMsg{Success: true}, true},
		{"unlocked", SignerStatusMsg{State: "unlocked", KeyCount: 1}, true},
		{"key list", KeysListMsg{Keys: []KeyInfo{{Address: "ADDR", KeyType: "ed25519"}}}, true},
		{"open the clients screen", key("c"), false},
		{"its lists", EnrolledKeysListMsg{}, true},
		{"leave it", key("esc"), false},
		{"open details", key("enter"), false},
		{"sign request", SignRequestReceivedMsg{Request: PendingSignRequest{ID: "sign-1"}}, true},
		{"reject it", key("n"), false},
		{"another request's cancellation", SignRequestCanceledMsg{ID: "sign-2"}, true},
		{"a daemon error", ErrorMsg{Error: errors.New("list failed")}, true},
		{"a send failure", sendFailedMsg{Error: errors.New("not connected")}, false},
		{"open generate", key("g"), false},
		{"leave it", key("esc"), false},
		{"connection lost", ErrorMsg{Error: errors.New("connection reset")}, true},
		{"reconnecting", ReconnectingMsg{Delay: time.Second}, true},
		{"reconnected", ConnectedMsg{}, true},
		{"auth required again", AuthRequiredMsg{}, true},
	} {
		apply(step.name, step.msg, step.from)
		settle(step.name)
	}

	// A displacement ends the session: no wait is left behind.
	apply("displaced", DisplacedMsg{Reason: "replaced"}, true)
	for _, msg := range local {
		apply("displaced result", msg, false)
	}
	if inFlight != 0 {
		t.Fatalf("after a displacement: %d listener waits in flight, want none", inFlight)
	}
}

// A login timeout also ends the session, and the TUI stays disconnected
// rather than retake the signer's single login slot, so nothing listens on.
func TestLoginTimeoutStopsListening(t *testing.T) {
	client := listenerTestClient()
	defer close(client.done)
	m := Model{viewState: ViewAuth, connectionState: ConnectionConnected, adminClient: client}
	_, cmd := m.Update(fromListener(AuthResultMsg{Code: protocol.ErrCodeLoginTimeout}))
	for _, result := range runPrompt(cmd) {
		if isListenerWait(result) {
			t.Fatal("a login timeout started another listener wait")
		}
	}
}

// testLoop plays Bubble Tea's part for a model: commands run in their own
// goroutines, and what they deliver is handed to Update one at a time.
type testLoop struct {
	t    *testing.T
	m    Model
	msgs chan tea.Msg
	seen []string
}

func newTestLoop(t *testing.T, m Model) *testLoop {
	return &testLoop{t: t, m: m, msgs: make(chan tea.Msg, 64)}
}

func (l *testLoop) run(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	go func() {
		msg := cmd()
		if batch, ok := msg.(tea.BatchMsg); ok {
			for _, inner := range batch {
				l.run(inner)
			}
			return
		}
		if msg != nil {
			l.msgs <- msg
		}
	}()
}

func (l *testLoop) update(msg tea.Msg) {
	l.seen = append(l.seen, fmt.Sprintf("%T", Unwrap(msg)))
	next, cmd := l.m.Update(msg)
	l.m = next.(Model)
	l.run(cmd)
}

// until handles delivered messages until done reports true.
func (l *testLoop) until(done func(Model) bool) {
	l.t.Helper()
	deadline := time.After(5 * time.Second)
	for !done(l.m) {
		select {
		case msg := <-l.msgs:
			l.update(msg)
		case <-deadline:
			l.t.Fatalf("timed out; handled %v", l.seen)
		}
	}
}

// A burst of notifications is handled in the order the signer sent it: the
// cancellation that follows a sign request never overtakes it, however the
// operator used the screen before.
func TestListenerHandlesABurstInOrder(t *testing.T) {
	encode := func(msg any) transport.Notification {
		raw, err := protocol.MarshalAdminMessage(msg)
		if err != nil {
			t.Fatal(err)
		}
		var base protocol.BaseMessage
		if err := json.Unmarshal(raw, &base); err != nil {
			t.Fatal(err)
		}
		base.Kind = protocol.MessageKindNotification
		return transport.Notification{Base: base, Raw: raw}
	}
	for round := range 20 {
		client := &IPCClient{msgChan: make(chan queuedMsg, 10), done: make(chan struct{}), sessionID: 1, notificationLoss: newNotificationLoss()}
		notifications := make(chan transport.Notification, 4)
		go client.forwardMessages(1, client.done, notifications, make(chan transport.LifecycleEvent))

		loop := newTestLoop(t, sizedForTest(t, Model{viewState: ViewKeyList, signerState: signerRuntimeUnlocked}, MinWidth, MinHeight))
		loop.update(ConnectedMsg{Client: client})
		loop.m.viewState = ViewKeyList
		// Screens the operator opens send requests of their own.
		for _, key := range []tea.KeyMsg{{Type: tea.KeyRunes, Runes: []rune("c")}, {Type: tea.KeyEsc}, {Type: tea.KeyRunes, Runes: []rune("c")}} {
			loop.update(key)
		}

		notifications <- encode(protocol.SignRequestMessage{BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignRequest, ID: "sign-1"}, Address: "ADDR"})
		notifications <- encode(protocol.SignRequestCanceledMessage{
			BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeSignRequestCanceled, ID: "sign-1"}, Reason: protocol.SignRequestCancelReasonClientCanceled,
		})
		canceled := fmt.Sprintf("%T", SignRequestCanceledMsg{})
		loop.until(func(Model) bool {
			for _, seen := range loop.seen {
				if seen == canceled {
					return true
				}
			}
			return false
		})
		close(client.done)

		received := fmt.Sprintf("%T", SignRequestReceivedMsg{})
		var order []string
		for _, seen := range loop.seen {
			if seen == received || seen == canceled {
				order = append(order, seen)
			}
		}
		if len(order) != 2 || order[0] != received {
			t.Fatalf("round %d: handled %v, want the request before its cancellation", round, order)
		}
		if loop.m.signing.request != nil {
			t.Fatalf("round %d: the canceled request is still on screen", round)
		}
	}
}
