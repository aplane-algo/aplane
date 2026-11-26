// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

// ipcTestClient is an admin client on one end of a pipe whose other end an
// IPC server's handler serves.
type ipcTestClient struct {
	conn   net.Conn
	reader *bufio.Reader
	done   chan struct{} // closed when the server's handler returns
}

func connectIPCTestClient(t *testing.T, ipcServer *IPCServer) *ipcTestClient {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	c := &ipcTestClient{conn: clientConn, reader: bufio.NewReader(clientConn), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		ipcServer.acceptAdminSession(adminproto.NewUnixAdminConn(serverConn))
	}()
	t.Cleanup(func() { _ = clientConn.Close() })
	return c
}

// login authenticates with msgType and reads the answer, and for an owner
// the status after it. Whatever the server sends next is read and dropped,
// as a socket's buffer would take it: the pipe has none.
func (c *ipcTestClient) login(t *testing.T, msgType string) {
	t.Helper()
	readAdminMessageType(t, c.conn, c.reader, protocol.MsgTypeAuthRequired)
	c.authenticate(t, msgType)
}

func (c *ipcTestClient) authenticate(t *testing.T, msgType string) {
	t.Helper()
	writeAdminMessage(t, c.conn, protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: msgType},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: protocol.AdminProtocolVersion,
	})
	var result protocol.AuthResultMessage
	if err := json.Unmarshal(readAdminMessageType(t, c.conn, c.reader, protocol.MsgTypeAuthResult), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Fatalf("%s login failed: %+v", msgType, result)
	}
	if msgType == protocol.MsgTypeAuth {
		readAdminMessageType(t, c.conn, c.reader, protocol.MsgTypeStatus)
	} else {
		// An observer frees the login slot just after its answer: a request
		// it serves is past that.
		writeAdminMessage(t, c.conn, protocol.GetAdminSettingsMessage{
			BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeGetAdminSettings, ID: "settings-1"},
		})
		readAdminMessageType(t, c.conn, c.reader, protocol.MsgTypeAdminSettings)
	}
	go func() {
		for {
			if _, err := c.reader.ReadBytes('\n'); err != nil {
				return
			}
		}
	}()
}

func (c *ipcTestClient) ended(t *testing.T) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(ipcDisconnectTestTimeout):
		t.Fatal("the session's handler did not return")
	}
}

func sessionAuditServer(t *testing.T) (*IPCServer, string) {
	t.Helper()
	signer, cleanup := setupTestSigner(t)
	t.Cleanup(cleanup)
	auditPath := useTestAuditLog(t, signer)
	ir := signer.productRuntime()
	ir.SetUnlocked()
	ir.Config().SetLockOnDisconnect(true)
	ipcServer := &IPCServer{signer: signer, manager: adminserver.NewSessionManager()}
	signer.ipcServer = ipcServer
	signer.hub = signer.ipcServer
	return ipcServer, auditPath
}

// sessionAudit is the session and lock entries, each as event, session and
// reason. Sessions are named A, B, ... in the order they first appear: their
// IDs count across the process's tests.
func sessionAudit(t *testing.T, path string) []string {
	t.Helper()
	names := map[any]string{}
	var out []string
	for _, e := range auditEntries(t, path, "SESSION_CONNECTED", "SESSION_DISCONNECTED", "IDENTITY_LOCKED") {
		id := e["admin_session_id"]
		if _, seen := names[id]; !seen {
			names[id] = string(rune('A' + len(names)))
		}
		reason, _ := e["reason"].(string)
		out = append(out, fmt.Sprintf("%v %s %s", e["event"], names[id], reason))
	}
	return out
}

// displaceToLogin confirms the displacement offered when an owner holds the
// signer, and reads the login prompt after it.
func (c *ipcTestClient) displaceToLogin(t *testing.T) {
	t.Helper()
	readAdminMessageType(t, c.conn, c.reader, protocol.MsgTypeClientExists)
	writeAdminMessage(t, c.conn, protocol.DisplaceConfirmMessage{
		BaseMessage: protocol.BaseMessage{Kind: protocol.MessageKindRequest, Type: protocol.MsgTypeDisplaceConfirm},
	})
	readAdminMessageType(t, c.conn, c.reader, protocol.MsgTypeAuthRequired)
}

// An owner another session displaces has its end recorded, as displaced; the
// owner that took over records its own end, and the lock its end makes.
func TestADisplacedOwnersEndIsRecorded(t *testing.T) {
	ipcServer, auditPath := sessionAuditServer(t)
	first := connectIPCTestClient(t, ipcServer)
	first.login(t, protocol.MsgTypeAuth)

	second := connectIPCTestClient(t, ipcServer)
	second.displaceToLogin(t)
	second.authenticate(t, protocol.MsgTypeAuth)
	first.ended(t)
	_ = second.conn.Close()
	second.ended(t)

	want := []string{
		"SESSION_CONNECTED A ",
		"SESSION_CONNECTED B ",
		"SESSION_DISCONNECTED A displaced",
		"SESSION_DISCONNECTED B ",
		"IDENTITY_LOCKED B lock_on_disconnect",
	}
	if got := sessionAudit(t, auditPath); !slices.Equal(got, want) {
		t.Fatalf("audit =\n%q\nwant\n%q", got, want)
	}
}

// Stop ends every session it serves, whatever its state, and returns once
// each has ended, so their entries are written before the audit log closes.
// The owner's end leaves the lock to the shutdown's own teardown. A
// connection that arrives after Stop is closed.
func TestStopEndsEverySessionBeforeReturning(t *testing.T) {
	ipcServer, auditPath := sessionAuditServer(t)
	owner := connectIPCTestClient(t, ipcServer)
	owner.login(t, protocol.MsgTypeAuth)
	observer := connectIPCTestClient(t, ipcServer)
	observer.displaceToLogin(t)
	observer.authenticate(t, protocol.MsgTypeAuthOnly)
	// Not yet logged in: the login slot is free once the owner holds the
	// signer, and its handler waits on the login.
	unauthenticated := connectIPCTestClient(t, ipcServer)
	readAdminMessageType(t, unauthenticated.conn, unauthenticated.reader, protocol.MsgTypeClientExists)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ipcServer.Stop(ctx); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
	if !ipcServer.sessionsEnded() {
		t.Fatal("Stop returned with sessions still being served")
	}
	got := sessionAudit(t, auditPath)
	slices.Sort(got)
	want := []string{"SESSION_CONNECTED A ", "SESSION_CONNECTED B auth_only", "SESSION_DISCONNECTED A ", "SESSION_DISCONNECTED B auth_only"}
	if !slices.Equal(got, want) {
		t.Fatalf("audit = %q, want %q", got, want)
	}
	if !ipcServer.signer.productRuntime().IsUnlocked() {
		t.Fatal("the owner's end locked the signer during shutdown")
	}
	for _, c := range []*ipcTestClient{owner, observer, unauthenticated} {
		c.ended(t)
	}

	late := connectIPCTestClient(t, ipcServer)
	late.ended(t)
}

// The owner's end during shutdown does not wait on a key user: the lock and
// its drain, which has no deadline, are left to the shutdown's teardown.
func TestStopDoesNotWaitOnAKeyUser(t *testing.T) {
	ipcServer, auditPath := sessionAuditServer(t)
	owner := connectIPCTestClient(t, ipcServer)
	owner.login(t, protocol.MsgTypeAuth)
	_, release := ipcServer.signer.productRuntime().KeyUseContext(context.Background())
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ipcServer.Stop(ctx); err != nil {
		t.Fatalf("Stop() behind a key user = %v", err)
	}
	if got := sessionAudit(t, auditPath); !slices.Equal(got, []string{"SESSION_CONNECTED A ", "SESSION_DISCONNECTED A "}) {
		t.Fatalf("audit = %q", got)
	}
}

// A deadline already passed, with nothing to wait for, is a clean stop.
func TestStopWithAPassedDeadlineAndNoSessions(t *testing.T) {
	for range 200 {
		ipcServer := &IPCServer{manager: adminserver.NewSessionManager()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := ipcServer.Stop(ctx); err != nil {
			t.Fatalf("Stop() with no sessions = %v", err)
		}
	}
}

// gatedConn holds a failed read until gate closes, so a handler whose
// connection Stop closed is still running at the deadline.
type gatedConn struct {
	*adminproto.StreamAdminConn
	gate chan struct{}
}

func (c *gatedConn) ReadMessage() ([]byte, error) {
	line, err := c.StreamAdminConn.ReadMessage()
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
		<-c.gate
	}
	return line, err
}

// An admin handler still running at the shutdown deadline keeps the
// lifecycle from closing the audit log, so its entries are written when it
// ends, after the incomplete stop is recorded.
func TestTheLifecycleKeepsTheAuditLogOpenForAnAdminHandler(t *testing.T) {
	ipcServer, auditPath := sessionAuditServer(t)
	gate := make(chan struct{})
	serverConn, clientConn := net.Pipe()
	owner := &ipcTestClient{conn: clientConn, reader: bufio.NewReader(clientConn), done: make(chan struct{})}
	go func() {
		defer close(owner.done)
		ipcServer.acceptAdminSession(&gatedConn{StreamAdminConn: adminproto.NewUnixAdminConn(serverConn), gate: gate})
	}()
	t.Cleanup(func() { _ = clientConn.Close() })
	owner.login(t, protocol.MsgTypeAuth)

	plan := ipcServer.signer.lifecyclePlan(nil, &http.Server{}, nil, func() {})
	plan.Services = slices.DeleteFunc(plan.Services, func(svc signerstartup.LifecycleService) bool { return svc.Name != "IPC server" })
	if len(plan.Services) != 1 {
		t.Fatalf("IPC services = %d", len(plan.Services))
	}
	plan.ShutdownTimeout = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := signerstartup.RunLifecycle(ctx, plan); err != nil {
		t.Fatalf("RunLifecycle() = %v", err)
	}
	close(gate)
	owner.ended(t)

	var got []string
	for _, e := range auditEntries(t, auditPath, "SESSION_CONNECTED", "SESSION_DISCONNECTED", "SERVER_STOP", "SERVER_STOP_INCOMPLETE") {
		reason, _ := e["reason"].(string)
		got = append(got, fmt.Sprintf("%v %s", e["event"], reason))
	}
	want := []string{
		"SESSION_CONNECTED ",
		"SERVER_STOP_INCOMPLETE IPC server: admin sessions still ending: context deadline exceeded",
		"SESSION_DISCONNECTED ",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("audit =\n%q\nwant\n%q", got, want)
	}
}

// A session that does not end within Stop's deadline is reported as such,
// which is what keeps the lifecycle from closing the audit log under it.
func TestStopReportsASessionThatDoesNotEnd(t *testing.T) {
	ipcServer, _ := sessionAuditServer(t)
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(serverConn), ipcServer.signer.adminSessionDeps(), adminserver.OriginLocal)
	if !ipcServer.track(session) {
		t.Fatal("track refused before Stop")
	}
	t.Cleanup(func() { ipcServer.untrack(session) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := ipcServer.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Stop() = %v, want the deadline", err)
	}
}
