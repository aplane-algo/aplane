// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"golang.org/x/crypto/ssh"
)

// These tests intentionally use a loopback SSH listener plus the shared
// admin subsystem to verify transport-shape compatibility. They are not pure
// unit tests: they exercise real TCP bind/listen behavior, SSH framing, and
// subsystem wiring, while still staying self-contained via generated keys,
// temp files, and ephemeral localhost ports.

func TestSSHAdminSessionRejectsMissingKindDuringAuth(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	sshServer, client := setupSSHAdminTestPair(t, server)
	defer func() { _ = client.Close() }()
	defer func() { _ = sshServer.Stop() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startSSHAdminTestServer(t, sshServer, ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := client.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("ConnectWithKey() error = %v", err)
	}

	stream, err := client.OpenSubsystem(sshtunnel.AdminSubsystemName)
	if err != nil {
		t.Fatalf("OpenSubsystem() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	reader := bufio.NewReader(stream)
	authRequired := mustReadAdminEnvelope(t, reader)
	if authRequired.Type != protocol.MsgTypeAuthRequired {
		t.Fatalf("first message type = %q, want %q", authRequired.Type, protocol.MsgTypeAuthRequired)
	}
	if authRequired.Kind != string(protocol.MessageKindNotification) {
		t.Fatalf("first message kind = %q, want %q", authRequired.Kind, protocol.MessageKindNotification)
	}

	if _, err := stream.Write([]byte(`{"type":"auth","passphrase":"` + string(testPassphrase) + `","protocol_version":{"major":4,"minor":0}}` + "\n")); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}

	authResult := mustReadAdminEnvelope(t, reader)
	if authResult.Type != protocol.MsgTypeAuthResult {
		t.Fatalf("auth result type = %q, want %q", authResult.Type, protocol.MsgTypeAuthResult)
	}
	if authResult.Kind != string(protocol.MessageKindResponse) {
		t.Fatalf("auth result kind = %q, want %q", authResult.Kind, protocol.MessageKindResponse)
	}
	if success, _ := authResult.Raw["success"].(bool); success {
		t.Fatal("auth result success = true, want false")
	}
	if code, _ := authResult.Raw["code"].(string); code != protocol.ErrCodeInvalidMessageFormat {
		t.Fatalf("auth result code = %q, want %q", code, protocol.ErrCodeInvalidMessageFormat)
	}
	if errMsg, _ := authResult.Raw["error"].(string); errMsg != "invalid message format" {
		t.Fatalf("auth result error = %q, want %q", errMsg, "invalid message format")
	}
}

func TestSSHAdminSessionAuthHandshakeMatchesGenericContract(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	sshServer, client := setupSSHAdminTestPair(t, server)
	defer func() { _ = client.Close() }()
	defer func() { _ = sshServer.Stop() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startSSHAdminTestServer(t, sshServer, ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := client.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("ConnectWithKey() error = %v", err)
	}

	stream, err := client.OpenSubsystem(sshtunnel.AdminSubsystemName)
	if err != nil {
		t.Fatalf("OpenSubsystem() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	reader := bufio.NewReader(stream)
	authRequired := mustReadAdminEnvelope(t, reader)
	if authRequired.Type != protocol.MsgTypeAuthRequired || authRequired.Kind != string(protocol.MessageKindNotification) {
		t.Fatalf("first message = %#v, want auth_required notification", authRequired)
	}
	if !reflectJSONSubset(authRequired.Raw, map[string]any{
		"protocol_version": map[string]any{"major": float64(4), "minor": float64(3)},
	}) {
		t.Fatalf("auth_required protocol version missing: %#v", authRequired.Raw)
	}

	if _, err := stream.Write(mustJSONLine(t, protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: testAdminProtocolVersion(),
	})); err != nil {
		t.Fatalf("stream.Write() error = %v", err)
	}

	authResult := mustReadAdminEnvelope(t, reader)
	if authResult.Type != protocol.MsgTypeAuthResult || authResult.Kind != string(protocol.MessageKindResponse) {
		t.Fatalf("auth result = %#v, want auth_result response", authResult)
	}
	if success, _ := authResult.Raw["success"].(bool); !success {
		t.Fatalf("auth result success = %#v, want true", authResult.Raw["success"])
	}

	status := mustReadAdminEnvelope(t, reader)
	if status.Type != protocol.MsgTypeStatus || status.Kind != string(protocol.MessageKindNotification) {
		t.Fatalf("status message = %#v, want status notification", status)
	}
	if state, _ := status.Raw["state"].(string); state != SignerStateUnlocked.String() {
		t.Fatalf("status state = %q, want %q", state, SignerStateUnlocked.String())
	}
}

func TestSSHAdminSessionReturnsGenericErrorForUnknownMessageType(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	sshServer, client := setupSSHAdminTestPair(t, server)
	defer func() { _ = client.Close() }()
	defer func() { _ = sshServer.Stop() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startSSHAdminTestServer(t, sshServer, ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if err := client.ConnectWithKey(context.Background()); err != nil {
		t.Fatalf("ConnectWithKey() error = %v", err)
	}

	stream, err := client.OpenSubsystem(sshtunnel.AdminSubsystemName)
	if err != nil {
		t.Fatalf("OpenSubsystem() error = %v", err)
	}
	defer func() { _ = stream.Close() }()

	reader := bufio.NewReader(stream)
	_ = mustReadAdminEnvelope(t, reader) // auth_required

	if _, err := stream.Write(mustJSONLine(t, protocol.AuthMessage{
		BaseMessage:     protocol.BaseMessage{Type: protocol.MsgTypeAuth},
		Passphrase:      protocol.NewSensitiveBytes(string(testPassphrase)),
		ProtocolVersion: testAdminProtocolVersion(),
	})); err != nil {
		t.Fatalf("stream.Write(auth) error = %v", err)
	}

	_ = mustReadAdminEnvelope(t, reader) // auth_result
	_ = mustReadAdminEnvelope(t, reader) // status

	if _, err := stream.Write([]byte(`{"kind":"request","type":"definitely_unknown","id":"req-ssh-1"}` + "\n")); err != nil {
		t.Fatalf("stream.Write(unknown) error = %v", err)
	}

	errMsg := mustReadAdminEnvelope(t, reader)
	if errMsg.Type != protocol.MsgTypeError || errMsg.Kind != string(protocol.MessageKindResponse) {
		t.Fatalf("error message = %#v, want error response", errMsg)
	}
	if code, _ := errMsg.Raw["code"].(string); code != protocol.ErrCodeUnknownMessageType {
		t.Fatalf("error code = %q, want %q", code, protocol.ErrCodeUnknownMessageType)
	}
	if gotID, _ := errMsg.Raw["id"].(string); gotID != "req-ssh-1" {
		t.Fatalf("error id = %q, want req-ssh-1", gotID)
	}
	if msg, _ := errMsg.Raw["error"].(string); msg != "unknown message type: definitely_unknown" {
		t.Fatalf("error = %q, want %q", msg, "unknown message type: definitely_unknown")
	}
}

type adminEnvelope struct {
	Kind string
	Type string
	ID   string
	Raw  map[string]any
}

func mustReadAdminEnvelope(t *testing.T, r *bufio.Reader) adminEnvelope {
	t.Helper()
	data, err := protocol.ReadJSONLine(r)
	if err != nil {
		t.Fatalf("ReadJSONLine() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	msg := adminEnvelope{
		Raw:  raw,
		Kind: stringValue(raw["kind"]),
		Type: stringValue(raw["type"]),
		ID:   stringValue(raw["id"]),
	}
	return msg
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func setupSSHAdminTestPair(t *testing.T, server *Signer) (*sshtunnel.Server, *sshtunnel.Client) {
	t.Helper()

	tmpDir := t.TempDir()
	pub, identityPath, authorizedKeyLine := generateSSHIdentityFile(t, tmpDir)
	_ = pub
	port := reserveLocalTCPPort(t)

	hostKeyPath := filepath.Join(tmpDir, "host_key")
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, []byte(authorizedKeyLine), 0o600); err != nil {
		t.Fatalf("WriteFile(authorized_keys) error = %v", err)
	}

	sshServer, err := sshtunnel.NewServer(fmt.Sprintf("127.0.0.1:%d", port), "127.0.0.1:0", hostKeyPath, authKeysPath, "test-token")
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	sshServer.SetAdminChannelCallback(func(channel ssh.Channel, remoteAddr, identityID string) {
		serverIPC := &IPCServer{signer: server}
		serverIPC.acceptAdminSession(adminproto.NewStreamAdminConn(channel, remoteAddr), "ssh", "ssh-passphrase", identityID)
	})

	client := sshtunnel.NewClient("127.0.0.1", port, 0, 0, identityPath, filepath.Join(tmpDir, "known_hosts"))
	client.SetIdentityID(auth.CurrentProductIdentityID())
	client.SetAPIToken("test-token")
	client.SetHostKeyApprovalHandler(func(host, fingerprint string) (bool, error) {
		return true, nil
	})

	return sshServer, client
}

func reserveLocalTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipIfLoopbackUnavailable(t, err)
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = ln.Close() }()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("Sscanf(%q) error = %v", portStr, err)
	}
	return port
}

func startSSHAdminTestServer(t *testing.T, sshServer *sshtunnel.Server, ctx context.Context) error {
	t.Helper()
	if err := sshServer.Start(ctx); err != nil {
		skipIfLoopbackUnavailable(t, err)
		return err
	}
	return nil
}

func skipIfLoopbackUnavailable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}

	var netErr *net.OpError
	msg := strings.ToLower(err.Error())
	if errors.As(err, &netErr) || strings.Contains(msg, "listen tcp") {
		if strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") {
			t.Skipf("loopback listeners unavailable in this environment: %v", err)
		}
	}
}

func generateSSHIdentityFile(t *testing.T, dir string) (ssh.PublicKey, string, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		t.Fatalf("WriteFile(identity) error = %v", err)
	}
	return signer.PublicKey(), path, string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func mustJSONLine(t *testing.T, v any) []byte {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(v)
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	return append(data, '\n')
}
