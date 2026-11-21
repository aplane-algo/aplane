// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/witness"
)

func setTokenForBackupTest(t *testing.T, server *Signer, selector, token string) {
	t.Helper()
	result := server.adminServices().keyApp().SetSourceToken(adminproto.SetSourceTokenRequest{
		Selector: selector, Source: "screening", Token: []byte(token),
	})
	if !result.Success {
		t.Fatalf("SetSourceToken(%s) = %+v", selector, result)
	}
}

func backupForTokenTest(t *testing.T, server *Signer) string {
	t.Helper()
	result := server.adminServices().backupApp().BackupIdentity(adminproto.BackupIdentityRequest{
		ExportPassphrase: []byte("export-passphrase"),
	})
	if !result.Success {
		t.Fatalf("BackupIdentity() = %+v", result)
	}
	return result.ArchivePath
}

func restoreForTokenTest(server *Signer, archivePath, id string, replace bool) adminproto.RestoreBackupResult {
	return server.adminServices().backupServices().RestoreBackup(adminproto.RestoreBackupRequest{
		OperationID: id, ArchivePath: filepath.Base(archivePath),
		ExportPassphrase: []byte("export-passphrase"), ReplaceExisting: replace,
	})
}

func requireServedToken(t *testing.T, server *Signer, selector, want string) {
	t.Helper()
	got, ok := server.productRuntime().SourceTokenFor(selector, "screening")
	switch {
	case want == "" && ok:
		t.Fatalf("SourceTokenFor(%s) serves a token, want none", selector)
	case want != "" && (!ok || got != want):
		t.Fatalf("SourceTokenFor(%s) = %q, %v; want %q", selector, got, ok, want)
	}
}

// A backup carries a cosigner key's tokens to a fresh node: the preview names
// the sources and never a token, and the restore writes the key's token
// file, which the reload after it publishes in the token index. The node
// default's tokens stay behind.
func TestSourceTokensTravelWithTheirKeyToAFreshNode(t *testing.T) {
	const keyToken, defaultToken = "tok-key-backup-4d2e", "tok-default-backup-8a17"
	source, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanup()
	key := generateTestKey(t, source, witness.Falcon1024V1)
	setTokenForBackupTest(t, source, key, keyToken)
	setTokenForBackupTest(t, source, policy.DefaultKey, defaultToken)
	archivePath := backupForTokenTest(t, source)
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	destination, cleanupDestination := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanupDestination()
	backups := destination.productRuntime().KeyPaths().ProductBackupsDir()
	if err := os.MkdirAll(backups, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backups, filepath.Base(archivePath)), archive, 0o600); err != nil {
		t.Fatal(err)
	}

	recorder := &ipcJSONRecorderConn{}
	session := newBoundTestSession(&IPCServer{signer: destination}, recorder, destination.productRuntime())
	dispatchIPCMessage(t, session, protocol.PreviewRestoreMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypePreviewRestore, ID: "preview"},
		ArchivePath: filepath.Base(archivePath), ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	dispatchIPCMessage(t, session, protocol.RestoreBackupMessage{
		BaseMessage: protocol.BaseMessage{Type: protocol.MsgTypeRestoreBackup, ID: "restore"},
		ArchivePath: filepath.Base(archivePath), ExportPassphrase: protocol.NewSensitiveBytes("export-passphrase"),
	})
	recorder.mu.Lock()
	wire := bytes.Clone(recorder.buf.Bytes())
	recorder.mu.Unlock()
	if bytes.Contains(wire, []byte(keyToken)) || bytes.Contains(wire, []byte(defaultToken)) {
		t.Fatal("a preview or restore response carries a token")
	}
	msgs := recorder.messages(t)
	if len(msgs) != 2 || msgs[0]["success"] == false || msgs[1]["success"] != true {
		t.Fatalf("responses = %#v", msgs)
	}
	keys, _ := msgs[0]["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("preview keys = %#v", msgs[0]["keys"])
	}
	if names, _ := keys[0].(map[string]any)["source_tokens"].([]any); len(names) != 1 || names[0] != "screening" {
		t.Fatalf("preview source tokens = %#v, want the source name", keys[0])
	}
	if restored, _ := msgs[1]["source_tokens_restored"].([]any); !slices.Equal(restored, []any{key}) {
		t.Fatalf("source_tokens_restored = %#v", msgs[1]["source_tokens_restored"])
	}

	requireServedToken(t, destination, key, keyToken)
	requireServedToken(t, destination, policy.DefaultKey, "")
}

// Rolling back a restore brings back the parent's tokens for the keys it
// restores, sealed under the current term, after a passphrase change that
// carried the rollback capability.
func TestRollbackAcrossAPassphraseChangeRestoresTheParentsTokens(t *testing.T) {
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanup()
	key := generateTestKey(t, server, witness.Falcon1024V1)
	setTokenForBackupTest(t, server, key, "tok-archived")
	archivePath := backupForTokenTest(t, server)
	setTokenForBackupTest(t, server, key, "tok-parent")

	if refused := restoreForTokenTest(server, archivePath, "restore-conflict", false); refused.Success ||
		refused.Code != protocol.ResultCodeRestoreConflict || len(refused.Conflicts) != 1 {
		t.Fatalf("RestoreBackup(differing tokens) = %+v, want a conflict", refused)
	}
	requireServedToken(t, server, key, "tok-parent")
	if restored := restoreForTokenTest(server, archivePath, "restore-replace", true); !restored.Success {
		t.Fatalf("RestoreBackup(replace) = %+v", restored)
	}
	requireServedToken(t, server, key, "tok-archived")

	changed := server.adminServices().ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: testPassphrase, NewPassphrase: []byte("rotated-store-passphrase"),
	})
	if !changed.Success {
		t.Fatalf("ChangeStorePassphrase() = %+v", changed)
	}

	rolled := server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: "rollback"})
	if !rolled.Success {
		t.Fatalf("RollbackRestore() = %+v", rolled)
	}
	// The reload after the rollback opened every token file under the
	// current term, the only one a keyring opens a live file with.
	requireServedToken(t, server, key, "tok-parent")
}

// A token set or removed after a restore makes rollback refuse, and a
// passphrase change after it does not carry the rollback capability.
func TestATokenChangeAfterARestoreKeepsRollbackFromUndoingIt(t *testing.T) {
	server, cleanup := setupTestNode(t, noderole.RoleCosigner, cosignerDefaultWithSources(t))
	defer cleanup()
	key := generateTestKey(t, server, witness.Falcon1024V1)
	setTokenForBackupTest(t, server, key, "tok-archived")
	archivePath := backupForTokenTest(t, server)
	setTokenForBackupTest(t, server, key, "tok-before")
	if restored := restoreForTokenTest(server, archivePath, "restore", true); !restored.Success {
		t.Fatalf("RestoreBackup() = %+v", restored)
	}

	if removed := server.adminServices().keyApp().RemoveSourceToken(adminproto.RemoveSourceTokenRequest{
		Selector: key, Source: "screening",
	}); !removed.Success {
		t.Fatalf("RemoveSourceToken() = %+v", removed)
	}
	rollback := func(id string) adminproto.RollbackRestoreResult {
		return server.adminServices().backupServices().RollbackRestore(adminproto.RollbackRestoreRequest{OperationID: id})
	}
	if result := rollback("rollback-after-remove"); result.Success || result.Code != protocol.ResultCodeRestoreRollbackDiverged {
		t.Fatalf("RollbackRestore() after a token removal = %+v, want diverged", result)
	}
	requireServedToken(t, server, key, "")

	setTokenForBackupTest(t, server, key, "tok-after")
	if result := rollback("rollback-after-set"); result.Success || result.Code != protocol.ResultCodeRestoreRollbackDiverged {
		t.Fatalf("RollbackRestore() after a token set = %+v, want diverged", result)
	}
	changed := server.adminServices().ChangeStorePassphrase(context.Background(), adminproto.ChangeStorePassphraseRequest{
		CurrentPassphrase: testPassphrase, NewPassphrase: []byte("rotated-store-passphrase"),
	})
	if !changed.Success {
		t.Fatalf("ChangeStorePassphrase() = %+v", changed)
	}
	if result := rollback("rollback-after-changepass"); result.Success || result.Code != protocol.ResultCodeRestoreRollbackRefused {
		t.Fatalf("RollbackRestore() after a passphrase change = %+v, want no capability", result)
	}
	requireServedToken(t, server, key, "tok-after")
}
