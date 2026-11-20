// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"bytes"
	"testing"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// secretRequest is one admin request that carries secrets, and the secret
// fields the handler must zero.
type secretRequest struct {
	name    string
	handle  func(*Session)
	secrets []protocol.SensitiveBytes
}

// secretRequests builds every request whose message carries a SensitiveBytes
// field, each with freshly filled secrets.
func secretRequests() []secretRequest {
	secret := func() protocol.SensitiveBytes { return protocol.NewSensitiveBytes("request-secret") }
	base := func(msgType string) protocol.BaseMessage { return protocol.BaseMessage{Type: msgType, ID: "req-1"} }

	unlock := &protocol.UnlockMessage{BaseMessage: base(protocol.MsgTypeUnlock), Passphrase: secret()}
	backup := &protocol.BackupMessage{BaseMessage: base(protocol.MsgTypeBackup), ExportPassphrase: secret()}
	commit := &protocol.CommitBackupImportMessage{BaseMessage: base(protocol.MsgTypeCommitBackupImport), ExportPassphrase: secret()}
	change := &protocol.ChangeStorePassphraseMessage{
		BaseMessage: base(protocol.MsgTypeChangeStorePass), CurrentPassphrase: secret(), NewPassphrase: secret(),
	}
	preview := &protocol.PreviewRestoreMessage{BaseMessage: base(protocol.MsgTypePreviewRestore), ExportPassphrase: secret()}
	restore := &protocol.RestoreBackupMessage{BaseMessage: base(protocol.MsgTypeRestoreBackup), ExportPassphrase: secret()}
	template := &protocol.ImportInstalledTemplateMessage{BaseMessage: base(protocol.MsgTypeImportInstalledTemplate), TemplateYAML: secret()}
	export := &protocol.ExportKeyMessage{BaseMessage: base(protocol.MsgTypeExportKey), Passphrase: secret()}
	importKey := &protocol.ImportKeyMessage{BaseMessage: base(protocol.MsgTypeImportKey), Mnemonic: secret()}

	return []secretRequest{
		{"unlock", func(s *Session) { s.HandleUnlock(unlock) }, []protocol.SensitiveBytes{unlock.Passphrase}},
		{"backup", func(s *Session) { s.HandleBackup(backup) }, []protocol.SensitiveBytes{backup.ExportPassphrase}},
		{"commit backup import", func(s *Session) { s.HandleCommitBackupImport(commit) }, []protocol.SensitiveBytes{commit.ExportPassphrase}},
		{"change store passphrase", func(s *Session) { s.HandleChangeStorePassphrase(change) },
			[]protocol.SensitiveBytes{change.CurrentPassphrase, change.NewPassphrase}},
		{"preview restore", func(s *Session) { s.HandlePreviewRestore(preview) }, []protocol.SensitiveBytes{preview.ExportPassphrase}},
		{"restore backup", func(s *Session) { s.HandleRestoreBackup(restore) }, []protocol.SensitiveBytes{restore.ExportPassphrase}},
		{"import installed template", func(s *Session) { s.HandleImportInstalledTemplate(template) }, []protocol.SensitiveBytes{template.TemplateYAML}},
		{"export key", func(s *Session) { s.HandleExportKey(export) }, []protocol.SensitiveBytes{export.Passphrase}},
		{"import key", func(s *Session) { s.HandleImportKey(importKey) }, []protocol.SensitiveBytes{importKey.Mnemonic}},
	}
}

func assertSecretsZeroed(t *testing.T, request secretRequest) {
	t.Helper()
	for i, secret := range request.secrets {
		if len(secret) == 0 || !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("%s: secret %d left as %q", request.name, i, []byte(secret))
		}
	}
}

// A request refused before its work runs still has every secret it carried
// zeroed: here no runtime is bound, so each handler refuses at its first gate.
func TestRefusedSecretRequestsZeroTheirSecrets(t *testing.T) {
	for _, request := range secretRequests() {
		t.Run(request.name, func(t *testing.T) {
			conn := &queueConn{}
			session := NewSession(conn, (&stubServices{}).backupDeps(), OriginLocal)
			request.handle(session)
			if len(conn.writes) != 1 || !bytes.Contains(conn.writes[0], []byte(protocol.ErrCodeNoRuntimeBound)) {
				t.Fatalf("%s: replies = %q, want one refusal", request.name, conn.writes)
			}
			assertSecretsZeroed(t, request)
		})
	}
}
