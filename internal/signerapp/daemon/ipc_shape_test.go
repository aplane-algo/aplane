// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/authz"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func testAdminProtocolVersion() *protocol.ProtocolVersion {
	version := protocol.CurrentAdminProtocolVersion()
	return &version
}

func TestAuthenticateClientRejectsMissingKind(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	authLine := `{"type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":5,"minor":0}}` + "\n"
	recorder := &ipcJSONRecorderConn{}
	session := adminserver.NewSession(
		adminproto.NewUnixAdminConn(recorder, bufio.NewReader(strings.NewReader(authLine))),
		server.adminSessionDeps(),
	)
	if ok := session.Authenticate(); ok {
		t.Fatal("Authenticate() = true, want false for missing kind")
	}

	msgs := recorder.messages(t)
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind": string(protocol.MessageKindNotification),
		"type": protocol.MsgTypeAuthRequired,
		"protocol_version": map[string]any{
			"major": float64(protocol.AdminProtocolVersionMajor),
			"minor": float64(protocol.AdminProtocolVersionMinor),
		},
	}) {
		t.Fatalf("auth_required shape mismatch: %#v", msgs[0])
	}
	if !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": false,
		"code":    protocol.ErrCodeInvalidMessageFormat,
		"error":   "invalid message format",
	}) {
		t.Fatalf("auth_result shape mismatch: %#v", msgs[1])
	}
}

func TestAuthenticateClientEmitsAuthHandshakeMessages(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	authLine := `{"kind":"request","type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":5,"minor":0}}` + "\n"
	recorder := &ipcJSONRecorderConn{}
	session := adminserver.NewSession(
		adminproto.NewUnixAdminConn(recorder, bufio.NewReader(strings.NewReader(authLine))),
		server.adminSessionDeps(),
	)
	if ok := session.Authenticate(); !ok {
		t.Fatal("Authenticate() = false, want true")
	}

	if session.Identity() == nil {
		t.Fatal("Authenticate() did not attach identity")
	}
	if session.Identity().ID != authz.SystemProductAdminPrincipalID {
		t.Fatalf("identity.ID = %q, want %q", session.Identity().ID, authz.SystemProductAdminPrincipalID)
	}
	if session.Identity().Method != "ipc-passphrase" {
		t.Fatalf("identity.Method = %q, want %q", session.Identity().Method, "ipc-passphrase")
	}

	msgs := recorder.messages(t)
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}

	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind": string(protocol.MessageKindNotification),
		"type": protocol.MsgTypeAuthRequired,
		"id":   "",
		"protocol_version": map[string]any{
			"major": float64(protocol.AdminProtocolVersionMajor),
			"minor": float64(protocol.AdminProtocolVersionMinor),
		},
	}) {
		t.Fatalf("auth_required shape mismatch: %#v", msgs[0])
	}

	if !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": true,
	}) {
		t.Fatalf("auth_result shape mismatch: %#v", msgs[1])
	}
	if _, ok := msgs[1]["error"]; ok {
		t.Fatalf("successful auth_result should omit error: %#v", msgs[1])
	}
}

func TestAuthenticateClientRejectsNewAdminAfterNodeFailure(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	server.nodeFailState.Fail(errors.New("identity role conflict"))

	authLine := `{"kind":"request","type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":5,"minor":0}}` + "\n"
	recorder := &ipcJSONRecorderConn{}
	session := adminserver.NewSession(
		adminproto.NewUnixAdminConn(recorder, bufio.NewReader(strings.NewReader(authLine))),
		server.adminSessionDeps(),
	)
	if ok := session.Authenticate(); ok {
		t.Fatal("Authenticate() = true after node failure")
	}
	msgs := recorder.messages(t)
	if len(msgs) != 2 || !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": false,
		"code":    protocol.ErrCodeNodeFailClosed,
	}) {
		t.Fatalf("node-fail auth result mismatch: %#v", msgs)
	}
}

func TestSendStatusEmitsCurrentStateAndKeyCount(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.productIdentityRuntime()
	ir.PublishSnapshot(
		map[string]string{"ADDR": "identities/default/keys/ADDR.key"},
		map[string]string{"ADDR": "ed25519"},
	)

	recorder := &ipcJSONRecorderConn{}
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)
	if err := session.SendStatus(); err != nil {
		t.Fatalf("SendStatus() error = %v", err)
	}

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":      string(protocol.MessageKindNotification),
		"type":      protocol.MsgTypeStatus,
		"state":     SignerStateUnlocked.String(),
		"key_count": float64(1),
	}) {
		t.Fatalf("status shape mismatch: %#v", msgs[0])
	}
}

func TestNotifyKeysChangedEmitsNotificationShape(t *testing.T) {
	recorder := &ipcJSONRecorderConn{}
	ipcServer := newIPCServerWithActiveConn(recorder)

	ipcServer.NotifyKeysChanged(adminproto.KeysChangedNotification{KeyCount: 7})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":      string(protocol.MessageKindNotification),
		"type":      protocol.MsgTypeKeysChanged,
		"key_count": float64(7),
	}) {
		t.Fatalf("keys_changed shape mismatch: %#v", msgs[0])
	}
}

func TestHandleListKeysRejectsUnboundSession(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	recorder := &ipcJSONRecorderConn{}
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(recorder, bufio.NewReader(bytes.NewReader(nil))), server.adminSessionDeps())
	session.Bind(&auth.Identity{ID: "other-identity", Type: "service", Method: "test"}, nil)
	session.HandleListKeys("req-1")

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	// With identity session binding, an unbound session is rejected before
	// the unlock check, so the error is about the missing session binding.
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind": string(protocol.MessageKindResponse),
		"type": protocol.MsgTypeError,
		"id":   "req-1",
		"code": protocol.ErrCodeNoIdentityBound,
	}) {
		t.Fatalf("error shape mismatch: %#v", msgs[0])
	}
	errStr, _ := msgs[0]["error"].(string)
	if errStr == "" {
		t.Fatal("expected error message, got empty")
	}
}

func TestHandleUpdateAdminSettingPersistsIdentityScopedConfigSeparately(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	configPath := filepath.Join(server.dataDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("theme: auto\nuser_auto_approve: false\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	recorder := &ipcJSONRecorderConn{}
	ir := server.productIdentityRuntime()
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)
	session.HandleUpdateAdminSetting(&protocol.UpdateAdminSettingMessage{
		BaseMessage: protocol.BaseMessage{ID: "req-1"},
		Key:         "user_auto_approve",
		Value:       "true",
	})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"type":    protocol.MsgTypeUpdateAdminSettingResult,
		"id":      "req-1",
		"success": true,
		"key":     "user_auto_approve",
		"value":   "true",
	}) {
		t.Fatalf("update_admin_setting_result shape mismatch: %#v", msgs[0])
	}

	diskCfg, err := serverconfig.LoadServerConfig(server.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if diskCfg.UserAutoApprove {
		t.Fatal("global config.yaml was modified for identity-scoped user_auto_approve")
	}

	storedCfg, err := identity.LoadStoredConfig(server.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if storedCfg.UserAutoApprove == nil || !*storedCfg.UserAutoApprove {
		t.Fatal("identity config did not persist user_auto_approve override")
	}
}

func TestHandleClientAuditsIPCSessionLifecycle(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	auditPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logger.Close() }()
	server.auditLog = logger

	authLine := `{"kind":"request","type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":5,"minor":0}}` + "\n"
	conn := newIPCMockConn(authLine, "unix:/tmp/test-ipc.sock")

	ipcServer := &IPCServer{signer: server}
	ipcServer.handleClient(conn)

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit entry count = %d, want 2", len(lines))
	}

	var connected AuditEntry
	if err := json.Unmarshal([]byte(lines[0]), &connected); err != nil {
		t.Fatal(err)
	}
	if connected.Event != AuditSessionConnected {
		t.Fatalf("first event = %q, want %q", connected.Event, AuditSessionConnected)
	}
	if connected.IdentityID != auth.CurrentProductIdentityID() {
		t.Fatalf("connected identity_id = %q, want %q", connected.IdentityID, auth.CurrentProductIdentityID())
	}
	if connected.AdminSessionID == "" {
		t.Fatal("connected admin_session_id is empty")
	}
	if connected.Transport != adminserver.TransportIPC {
		t.Fatalf("connected transport = %q, want %q", connected.Transport, adminserver.TransportIPC)
	}
	if connected.TargetIdentityID != auth.CurrentProductIdentityID() {
		t.Fatalf("connected target_identity_id = %q, want %q", connected.TargetIdentityID, auth.CurrentProductIdentityID())
	}

	var disconnected AuditEntry
	if err := json.Unmarshal([]byte(lines[1]), &disconnected); err != nil {
		t.Fatal(err)
	}
	if disconnected.Event != AuditSessionDisconnected {
		t.Fatalf("second event = %q, want %q", disconnected.Event, AuditSessionDisconnected)
	}
	if disconnected.IdentityID != auth.CurrentProductIdentityID() {
		t.Fatalf("disconnected identity_id = %q, want %q", disconnected.IdentityID, auth.CurrentProductIdentityID())
	}
	if disconnected.AdminSessionID != connected.AdminSessionID {
		t.Fatalf("disconnected admin_session_id = %q, want %q", disconnected.AdminSessionID, connected.AdminSessionID)
	}
	if disconnected.Transport != adminserver.TransportIPC {
		t.Fatalf("disconnected transport = %q, want %q", disconnected.Transport, adminserver.TransportIPC)
	}
	if disconnected.TargetIdentityID != auth.CurrentProductIdentityID() {
		t.Fatalf("disconnected target_identity_id = %q, want %q", disconnected.TargetIdentityID, auth.CurrentProductIdentityID())
	}
}

func TestHandleRegisteredClientReturnsGenericErrorForUnknownMessageType(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	authLine := `{"kind":"request","type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":5,"minor":0}}` + "\n"
	unknownLine := `{"kind":"request","type":"definitely_unknown","id":"req-1"}` + "\n"
	conn := newIPCMockConn(authLine+unknownLine, "unix:/tmp/test-ipc.sock")

	ipcServer := &IPCServer{signer: server}
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), server.adminSessionDeps())
	session.SetAuthMethod("ipc-passphrase")
	if !ipcServer.sessionManager().RegisterPreAuthPending(session) {
		t.Fatal("RegisterPreAuthPending() = false, want true")
	}

	ipcServer.handleRegisteredClient(session, "ipc", nil)

	msgs := parseJSONLines(t, conn.writes.Bytes())
	if len(msgs) < 4 {
		t.Fatalf("message count = %d, want at least 4", len(msgs))
	}
	last := msgs[len(msgs)-1]
	if !reflectJSONSubset(last, map[string]any{
		"kind": string(protocol.MessageKindResponse),
		"type": protocol.MsgTypeError,
		"code": protocol.ErrCodeUnknownMessageType,
		"id":   "req-1",
	}) {
		t.Fatalf("error shape mismatch: %#v", last)
	}
	if got, _ := last["error"].(string); got != "unknown message type: definitely_unknown" {
		t.Fatalf("error = %q, want %q", got, "unknown message type: definitely_unknown")
	}
}

func TestIPCConnWriteJSONSerializesConcurrentWriters(t *testing.T) {
	conn := &interleavingRecorderConn{}
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, bufio.NewReader(bytes.NewReader(nil))), adminserver.SessionDeps{})

	msgA := protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError, ID: "a"},
		Error:       strings.Repeat("A", 128),
	}
	msgB := protocol.ErrorMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeError, ID: "b"},
		Error:       strings.Repeat("B", 128),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := session.WriteJSON(msgA); err != nil {
			t.Errorf("WriteJSON(msgA) error = %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := session.WriteJSON(msgB); err != nil {
			t.Errorf("WriteJSON(msgB) error = %v", err)
		}
	}()
	wg.Wait()

	lines := bytes.Split(bytes.TrimSpace(conn.buf.Bytes()), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatalf("line count = %d, want 2 (raw=%q)", len(lines), conn.buf.String())
	}

	var gotIDs []string
	for i, line := range lines {
		var msg protocol.ErrorMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			t.Fatalf("line %d did not decode as JSON: %v (line=%q)", i, err, string(line))
		}
		gotIDs = append(gotIDs, msg.ID)
	}

	sawA, sawB := false, false
	for _, id := range gotIDs {
		if id == "a" {
			sawA = true
		}
		if id == "b" {
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Fatalf("decoded IDs = %v, want both a and b", gotIDs)
	}
}

type ipcJSONRecorderConn struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (c *ipcJSONRecorderConn) messages(t *testing.T) []map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	raw := bytes.TrimSpace(c.buf.Bytes())
	if len(raw) == 0 {
		return nil
	}
	lines := bytes.Split(raw, []byte{'\n'})
	msgs := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal(line, &msg); err != nil {
			t.Fatalf("failed to decode JSON line %q: %v", string(line), err)
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

func reflectJSONSubset(got map[string]any, want map[string]any) bool {
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			return false
		}
	}
	return true
}

func parseJSONLines(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	raw := bytes.TrimSpace(data)
	if len(raw) == 0 {
		return nil
	}
	lines := bytes.Split(raw, []byte{'\n'})
	msgs := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal(line, &msg); err != nil {
			t.Fatalf("failed to decode JSON line %q: %v", string(line), err)
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

func (c *ipcJSONRecorderConn) Read([]byte) (int, error) { return 0, nil }
func (c *ipcJSONRecorderConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}
func (c *ipcJSONRecorderConn) Close() error                     { return nil }
func (c *ipcJSONRecorderConn) LocalAddr() net.Addr              { return nil }
func (c *ipcJSONRecorderConn) RemoteAddr() net.Addr             { return nil }
func (c *ipcJSONRecorderConn) SetDeadline(time.Time) error      { return nil }
func (c *ipcJSONRecorderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ipcJSONRecorderConn) SetWriteDeadline(time.Time) error { return nil }

type ipcMockConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
	remote net.Addr
}

func newIPCMockConn(input, remote string) *ipcMockConn {
	return &ipcMockConn{
		reader: bytes.NewReader([]byte(input)),
		remote: ipcMockAddr(remote),
	}
}

func (c *ipcMockConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *ipcMockConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *ipcMockConn) Close() error                     { return nil }
func (c *ipcMockConn) LocalAddr() net.Addr              { return ipcMockAddr("local") }
func (c *ipcMockConn) RemoteAddr() net.Addr             { return c.remote }
func (c *ipcMockConn) SetDeadline(time.Time) error      { return nil }
func (c *ipcMockConn) SetReadDeadline(time.Time) error  { return nil }
func (c *ipcMockConn) SetWriteDeadline(time.Time) error { return nil }

type ipcMockAddr string

func (a ipcMockAddr) Network() string { return "unix" }
func (a ipcMockAddr) String() string  { return string(a) }

type interleavingRecorderConn struct {
	buf bytes.Buffer
	mu  sync.Mutex
}

func (c *interleavingRecorderConn) Read([]byte) (int, error)         { return 0, nil }
func (c *interleavingRecorderConn) Close() error                     { return nil }
func (c *interleavingRecorderConn) LocalAddr() net.Addr              { return nil }
func (c *interleavingRecorderConn) RemoteAddr() net.Addr             { return nil }
func (c *interleavingRecorderConn) SetDeadline(time.Time) error      { return nil }
func (c *interleavingRecorderConn) SetReadDeadline(time.Time) error  { return nil }
func (c *interleavingRecorderConn) SetWriteDeadline(time.Time) error { return nil }

func (c *interleavingRecorderConn) Write(p []byte) (int, error) {
	for i := 0; i < len(p); i++ {
		c.mu.Lock()
		_, _ = c.buf.Write(p[i : i+1])
		c.mu.Unlock()
		time.Sleep(time.Microsecond)
	}
	return len(p), nil
}
