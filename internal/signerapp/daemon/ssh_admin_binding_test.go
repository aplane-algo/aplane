// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	"os"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	"github.com/aplane-algo/aplane/internal/signerapp/policyruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
)

func TestSSHPreboundAdminSessionDefaultsToSSHIdentityInDaemon(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	alice := registerAdditionalAdminTestIdentity(t, server, "alice")
	authLine := `{"kind":"request","type":"auth","passphrase":"` + string(testPassphrase) + `"}` + "\n"
	conn := newIPCMockConn(authLine, "ssh:remote")
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), server.adminSessionDeps())
	session.SetAuthMethod("ssh-passphrase")
	session.SetTransportInfo(adminserver.TransportSSH, "ssh:remote")
	session.SetPreboundIdentityID("alice")

	if !session.Authenticate() {
		t.Fatal("Authenticate() = false, want true")
	}
	if session.BoundRuntime() != alice {
		t.Fatal("BoundRuntime() != prebound SSH identity runtime")
	}
	if !alice.IsUnlocked() {
		t.Fatal("prebound SSH identity was not unlocked")
	}
	if session.TargetIdentityID() != "alice" {
		t.Fatalf("TargetIdentityID() = %q, want alice", session.TargetIdentityID())
	}
	sessionCtx := session.SessionContext()
	if sessionCtx.TargetIdentityID != "alice" {
		t.Fatalf("SessionContext().TargetIdentityID = %q, want alice", sessionCtx.TargetIdentityID)
	}
	if sessionCtx.Transport != adminserver.TransportSSH {
		t.Fatalf("SessionContext().Transport = %q, want %q", sessionCtx.Transport, adminserver.TransportSSH)
	}
	if sessionCtx.AuthMethod != "ssh-passphrase" {
		t.Fatalf("SessionContext().AuthMethod = %q, want ssh-passphrase", sessionCtx.AuthMethod)
	}

	msgs := parseJSONLines(t, conn.writes.Bytes())
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}
	if !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": true,
	}) {
		t.Fatalf("auth_result shape mismatch: %#v", msgs[1])
	}
}

func TestSSHPreboundAdminSessionRejectsPayloadIdentitySwitchInDaemon(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	alice := registerAdditionalAdminTestIdentity(t, server, "alice")
	bob := registerAdditionalAdminTestIdentity(t, server, "bob")
	authLine := `{"kind":"request","type":"auth","identity_id":"bob","passphrase":"` + string(testPassphrase) + `"}` + "\n"
	conn := newIPCMockConn(authLine, "ssh:remote")
	session := adminserver.NewSession(adminproto.NewUnixAdminConn(conn, nil), server.adminSessionDeps())
	session.SetAuthMethod("ssh-passphrase")
	session.SetTransportInfo(adminserver.TransportSSH, "ssh:remote")
	session.SetPreboundIdentityID("alice")

	if session.Authenticate() {
		t.Fatal("Authenticate() = true, want false")
	}
	if alice.IsUnlocked() {
		t.Fatal("prebound identity was unlocked after payload identity mismatch")
	}
	if bob.IsUnlocked() {
		t.Fatal("payload identity was unlocked after SSH identity mismatch")
	}
	if session.BoundRuntime() != nil {
		t.Fatal("BoundRuntime() != nil after rejected SSH identity mismatch")
	}

	msgs := parseJSONLines(t, conn.writes.Bytes())
	if len(msgs) != 2 {
		t.Fatalf("message count = %d, want 2", len(msgs))
	}
	if !reflectJSONSubset(msgs[1], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeAuthResult,
		"success": false,
		"code":    protocol.ErrCodeAuthenticationFailed,
	}) {
		t.Fatalf("auth_result shape mismatch: %#v", msgs[1])
	}
}

func registerAdditionalAdminTestIdentity(t *testing.T, server *Signer, identityID string) *identity.Runtime {
	t.Helper()

	if err := os.MkdirAll(server.keyPaths.KeysDir(identityID), 0o750); err != nil {
		t.Fatalf("create keys dir for %q: %v", identityID, err)
	}
	metadataDir := server.keyPaths.KeystoreMetadataDir(identityID)
	_, masterKey, err := crypto.CreateKeystoreMetadata(metadataDir, testPassphrase)
	if err != nil {
		t.Fatalf("CreateKeystoreMetadata(%q): %v", identityID, err)
	}
	if err := policy.SaveStoredConfigWithMasterKey(server.dataDir, identityID, &policy.StoredConfig{}, masterKey, time.Now()); err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("SaveStoredConfigWithMasterKey(%q): %v", identityID, err)
	}
	roleDoc, roleBytes, err := noderole.Load(server.keyPaths)
	if err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("Load node role: %v", err)
	}
	if err := noderole.SaveIdentitySidecarWithMasterKey(server.keyPaths, identityID, roleBytes, masterKey, time.Now()); err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("SaveIdentitySidecarWithMasterKey(%q): %v", identityID, err)
	}
	initialPolicy, err := policyruntime.LoadVerified(server.dataDir, identityID, server.config, masterKey)
	if err != nil {
		crypto.ZeroBytes(masterKey)
		t.Fatalf("LoadVerified(%q): %v", identityID, err)
	}
	crypto.ZeroBytes(masterKey)
	ks := keystore.NewFileKeyStoreForPaths(server.keyPaths, identityID)
	if _, err := ks.InitializeMasterKey(testPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey(%q): %v", identityID, err)
	}

	ir := identity.New(identity.Config{
		Authenticator: auth.NewTokenAuthenticator(identityID + "-token"),
		ID:            identityID,
		KeyStore:      ks,
		KeyPaths:      server.keyPaths,
		NodeRole:      roleDoc.Role,
	})
	if err := server.registry.Register(ir); err != nil {
		t.Fatalf("registry.Register(%q): %v", identityID, err)
	}
	signerstartup.WireReloadFunc(ir, testIdentityBuildOptions(server), server.identityBuildHooks())
	signerstartup.WireApprovalCoordinator(ir, server.identityBuildHooks())
	ir.SetPolicy(initialPolicy)
	return ir
}
