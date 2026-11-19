// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/protocol"
)

const testImportMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest"

func TestIPCImportKeyBecomesVisibleAfterReload(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ipcServer := &IPCServer{signer: server}
	server.ipcServer = ipcServer

	recorder := &recordingIPCConn{}
	session := newBoundTestSession(ipcServer, recorder, server.productRuntime())

	msg := &protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportKey,
			ID:   "import-1",
		},
		KeyType:  "ed25519",
		Mnemonic: protocol.NewSensitiveBytes(testImportMnemonic),
	}

	session.HandleImportKey(msg)

	var result protocol.ImportResultMessage
	if err := json.Unmarshal(bytes.TrimSpace(recorder.buf.Bytes()), &result); err != nil {
		t.Fatalf("failed to decode import result: %v", err)
	}
	if !result.Success {
		t.Fatalf("import failed: %s", result.Error)
	}
	if result.Address == "" {
		t.Fatal("expected imported address")
	}

	if err := reloadKeysForTest(server); err != nil {
		t.Fatalf("reloadKeysForTest() error = %v", err)
	}

	ir := server.productRuntime()
	keyFile, err := ir.FindKeyFile(result.Address)
	if err != nil {
		t.Fatalf("imported address %s not present in key cache after reload: %v", result.Address, err)
	}
	if keyFile == "" {
		t.Fatalf("imported address %s has empty key path in cache", result.Address)
	}

	_, keyTypes := ir.KeySnapshot()
	keyType := keyTypes[result.Address]
	if keyType != "ed25519" {
		t.Fatalf("key type = %q, want %q", keyType, "ed25519")
	}
}

func TestIPCGenerateKeyBecomesVisibleImmediatelyAndAdminMutationsAreAudited(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	auditPath := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLogger() error = %v", err)
	}
	defer func() { _ = logger.Close() }()
	server.auditLog = logger

	ipcServer := &IPCServer{signer: server}
	server.ipcServer = ipcServer

	recorder := &recordingIPCConn{}
	session := newBoundTestSession(ipcServer, recorder, server.productRuntime())

	genMsg := &protocol.GenerateKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeGenerateKey,
			ID:   "generate-1",
		},
		KeyType: "ed25519",
	}
	session.HandleGenerateKey(genMsg)

	var genResult protocol.GenerateResultMessage
	if err := json.Unmarshal(bytes.TrimSpace(recorder.buf.Bytes()), &genResult); err != nil {
		t.Fatalf("failed to decode generate result: %v", err)
	}
	if !genResult.Success {
		t.Fatalf("generate failed: %s", genResult.Error)
	}
	if genResult.Address == "" {
		t.Fatal("expected generated address")
	}

	ir := server.productRuntime()
	keyFile, err := ir.FindKeyFile(genResult.Address)
	if err != nil {
		t.Fatalf("generated address %s not present in key cache without manual reload: %v", genResult.Address, err)
	}
	if keyFile == "" {
		t.Fatalf("generated address %s has empty key path in cache", genResult.Address)
	}

	recorder.buf.Reset()
	deleteMsg := &protocol.DeleteKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeDeleteKey,
			ID:   "delete-1",
		},
		Address: genResult.Address,
	}
	session.HandleDeleteKey(deleteMsg)

	var deleteResult protocol.DeleteResultMessage
	if err := json.Unmarshal(bytes.TrimSpace(recorder.buf.Bytes()), &deleteResult); err != nil {
		t.Fatalf("failed to decode delete result: %v", err)
	}
	if !deleteResult.Success {
		t.Fatalf("delete failed: %s", deleteResult.Error)
	}

	recorder.buf.Reset()
	importMsg := &protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{
			Type: protocol.MsgTypeImportKey,
			ID:   "import-1",
		},
		KeyType:  "ed25519",
		Mnemonic: protocol.NewSensitiveBytes(testImportMnemonic),
	}
	session.HandleImportKey(importMsg)

	var importResult protocol.ImportResultMessage
	if err := json.Unmarshal(bytes.TrimSpace(recorder.buf.Bytes()), &importResult); err != nil {
		t.Fatalf("failed to decode import result: %v", err)
	}
	if !importResult.Success {
		t.Fatalf("import failed: %s", importResult.Error)
	}

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("failed to read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected 6 audit entries, got %d", len(lines))
	}

	requiredEvents := map[AuditEventType]string{
		AuditKeyGenerated: genResult.Address,
		AuditKeyDeleted:   genResult.Address,
		AuditKeyImported:  importResult.Address,
	}
	reloadCount := 0
	for i, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("line %d: unmarshal error: %v", i, err)
		}
		if entry.Event == AuditKeyReload {
			reloadCount++
			continue
		}
		wantAddr, ok := requiredEvents[entry.Event]
		if !ok {
			t.Fatalf("line %d: unexpected event %q", i, entry.Event)
		}
		if entry.TxnAuth != wantAddr {
			t.Fatalf("line %d: txn_auth = %q, want %q", i, entry.TxnAuth, wantAddr)
		}
		delete(requiredEvents, entry.Event)
	}
	if reloadCount != 3 {
		t.Fatalf("expected 3 KEY_RELOAD audit entries, got %d", reloadCount)
	}
	if len(requiredEvents) != 0 {
		t.Fatalf("missing required audit events: %#v", requiredEvents)
	}
}

type recordingIPCConn struct {
	buf bytes.Buffer
}

func (c *recordingIPCConn) Read([]byte) (int, error)         { return 0, nil }
func (c *recordingIPCConn) Write(b []byte) (int, error)      { return c.buf.Write(b) }
func (c *recordingIPCConn) Close() error                     { return nil }
func (c *recordingIPCConn) LocalAddr() net.Addr              { return nil }
func (c *recordingIPCConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingIPCConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingIPCConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingIPCConn) SetWriteDeadline(time.Time) error { return nil }

// frameConn hands out admin frames and keeps them, so a test can see what the
// server left in them.
type frameConn struct {
	frames [][]byte
	next   int
}

func (c *frameConn) ReadMessage() ([]byte, error) {
	if c.next >= len(c.frames) {
		return nil, io.EOF
	}
	frame := c.frames[c.next]
	c.next++
	return frame, nil
}
func (c *frameConn) WriteMessage([]byte) error { return nil }
func (c *frameConn) RemoteAddr() string        { return "test" }
func (c *frameConn) Close() error              { return nil }

// The server zeroes each admin frame once it is handled: an import frame
// carries the recovery phrase, which the handler has decoded into its own
// zeroed buffer by then. Unknown and malformed frames are zeroed too.
func TestServeAdminMessagesZeroesHandledFrames(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()
	ipcServer := &IPCServer{signer: server}
	server.ipcServer = ipcServer
	session := newBoundTestSession(ipcServer, &recordingIPCConn{}, server.productRuntime())

	importFrame, err := protocol.MarshalAdminMessage(protocol.ImportKeyMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeImportKey, ID: "import-frame"},
		KeyType:     "ed25519",
		Mnemonic:    protocol.NewSensitiveBytes(testImportMnemonic),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn := &frameConn{frames: [][]byte{
		importFrame,
		[]byte(`{"kind":"request","type":"no_such_type","id":"unknown","secret":"x"}`),
		[]byte(`not json`),
	}}
	ipcServer.serveAdminMessages(session, conn)

	for i, frame := range conn.frames {
		if !bytes.Equal(frame, make([]byte, len(frame))) {
			t.Fatalf("frame %d left as %q after it was handled", i, frame)
		}
	}
}
