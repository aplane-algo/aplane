// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"

	"github.com/aplane-algo/aplane/internal/protocol"
)

// dispatchFunc decodes and handles one already-validated request message.
type dispatchFunc func(s *Session, raw []byte, id string)

// typed builds a dispatchFunc that unmarshals the raw message into T and
// invokes handle, reporting "invalid <label> message" on decode failure.
func typed[T any](label string, handle func(*Session, *T)) dispatchFunc {
	return func(s *Session, raw []byte, id string) {
		var msg T
		if err := json.Unmarshal(raw, &msg); err != nil {
			_ = s.SendError(id, protocol.ErrCodeInvalidRequest, "invalid "+label+" message")
			return
		}
		handle(s, &msg)
	}
}

// dispatchTable routes request messages handled entirely within the
// transport-neutral admin protocol/session layer.
var dispatchTable = map[string]dispatchFunc{
	protocol.MsgTypeUnlock:       typed("unlock", (*Session).HandleUnlock),
	protocol.MsgTypeLockIdentity: typed("lock identity", (*Session).HandleLockIdentity),

	protocol.MsgTypeBackup:             typed("backup", (*Session).HandleBackup),
	protocol.MsgTypeListBackups:        typed("list backups", func(s *Session, m *protocol.ListBackupsMessage) { s.HandleListBackups(m.ID) }),
	protocol.MsgTypeDeleteBackup:       typed("delete backup", (*Session).HandleDeleteBackup),
	protocol.MsgTypeBeginBackupImport:  typed("begin backup import", (*Session).HandleBeginBackupImport),
	protocol.MsgTypeAppendBackupImport: typed("append backup import", (*Session).HandleAppendBackupImport),
	protocol.MsgTypeCommitBackupImport: typed("commit backup import", (*Session).HandleCommitBackupImport),
	protocol.MsgTypeAbortBackupImport:  typed("abort backup import", (*Session).HandleAbortBackupImport),
	protocol.MsgTypeReadBackupChunk:    typed("read backup chunk", (*Session).HandleReadBackupChunk),
	protocol.MsgTypeChangeStorePass:    typed("change store passphrase", (*Session).HandleChangeStorePassphrase),
	protocol.MsgTypePreviewRestore:     typed("preview restore", (*Session).HandlePreviewRestore),
	protocol.MsgTypeRestoreBackup:      typed("restore backup", (*Session).HandleRestoreBackup),
	protocol.MsgTypeRollbackRestore:    typed("rollback restore", (*Session).HandleRollbackRestore),
	protocol.MsgTypeReconcileStore: typed("reconcile store", func(s *Session, m *protocol.ReconcileStoreMessage) {
		s.HandleReconcileStore(m.ID)
	}),

	protocol.MsgTypeRevokeToken:        typed("revoke token", (*Session).HandleRevokeToken),
	protocol.MsgTypeGetAdminSettings:   typed("get admin settings", func(s *Session, m *protocol.GetAdminSettingsMessage) { s.HandleGetAdminSettings(m.ID) }),
	protocol.MsgTypeUpdateAdminSetting: typed("update admin setting", (*Session).HandleUpdateAdminSetting),

	protocol.MsgTypeGetPolicySnapshot: typed("get policy snapshot", (*Session).HandleGetPolicySnapshot),
	protocol.MsgTypeReplacePolicy:     typed("replace policy", (*Session).HandleReplacePolicy),
	protocol.MsgTypeValidatePolicy:    typed("validate policy", (*Session).HandleValidatePolicy),

	protocol.MsgTypeListSentryReferences: typed("list sentry references", func(s *Session, m *protocol.ListSentryReferencesMessage) {
		s.HandleListSentryReferences(m.ID)
	}),
	protocol.MsgTypeGetSentryReference:    typed("get sentry reference", (*Session).HandleGetSentryReference),
	protocol.MsgTypeImportSentryReference: typed("import sentry reference", (*Session).HandleImportSentryReference),
	protocol.MsgTypeRemoveSentryReference: typed("remove sentry reference", (*Session).HandleRemoveSentryReference),
	protocol.MsgTypeExportSentryPublic:    typed("export sentry public metadata", (*Session).HandleExportSentryPublic),
	protocol.MsgTypeListGenerations: typed("list generations", func(s *Session, m *protocol.ListGenerationsMessage) {
		s.HandleListGenerations(m.ID)
	}),

	protocol.MsgTypeListKeys:      typed("list keys", func(s *Session, m *protocol.ListKeysMessage) { s.HandleListKeys(m.ID) }),
	protocol.MsgTypeGetKeyDetails: typed("get key details", (*Session).HandleGetKeyDetails),
	protocol.MsgTypeGenerateKey:   typed("generate key", (*Session).HandleGenerateKey),
	protocol.MsgTypeDeleteKey:     typed("delete key", (*Session).HandleDeleteKey),
	protocol.MsgTypeExportKey:     typed("export key", (*Session).HandleExportKey),
	protocol.MsgTypeImportKey:     typed("import key", (*Session).HandleImportKey),

	protocol.MsgTypeListLibraryTemplates:    typed("list library templates", func(s *Session, m *protocol.ListLibraryTemplatesMessage) { s.HandleListLibraryTemplates(m.ID) }),
	protocol.MsgTypeInstallLibraryTemplate:  typed("install library template", (*Session).HandleInstallLibraryTemplate),
	protocol.MsgTypeListInstalledTemplates:  typed("list installed templates", func(s *Session, m *protocol.ListInstalledTemplatesMessage) { s.HandleListInstalledTemplates(m.ID) }),
	protocol.MsgTypeShowInstalledTemplate:   typed("show installed template", (*Session).HandleShowInstalledTemplate),
	protocol.MsgTypeShowLibraryTemplate:     typed("show library template", (*Session).HandleShowLibraryTemplate),
	protocol.MsgTypeImportInstalledTemplate: typed("import installed template", (*Session).HandleImportInstalledTemplate),
	protocol.MsgTypeRemoveInstalledTemplate: typed("remove installed template", (*Session).HandleRemoveInstalledTemplate),

	protocol.MsgTypeActivateKeyType:   typed("activate key type", (*Session).HandleActivateKeyType),
	protocol.MsgTypeDeactivateKeyType: typed("deactivate key type", (*Session).HandleDeactivateKeyType),
	protocol.MsgTypeListKeyTypes:      typed("list key types", func(s *Session, m *protocol.ListKeyTypesMessage) { s.HandleListKeyTypes(m.ID) }),

	protocol.MsgTypeSignResponse:              typed("sign response", (*Session).HandleSignResponse),
	protocol.MsgTypeTokenProvisioningResponse: typed("token provisioning response", (*Session).HandleTokenProvisioningResponse),
}

// Dispatch handles the subset of protocol messages that already live entirely
// within the transport-neutral admin protocol/session layer.
func (s *Session) Dispatch(raw []byte) bool {
	base, err := protocol.ParseAdminBaseMessage(raw)
	if err != nil {
		_ = s.SendError("", protocol.ErrCodeInvalidMessageFormat, "invalid message format")
		return true
	}
	if base.Kind != protocol.MessageKindRequest {
		_ = s.SendError(base.ID, protocol.ErrCodeInvalidRequest, "expected request message")
		return true
	}

	handle, ok := dispatchTable[base.Type]
	if !ok {
		return false
	}
	if s.nodeFailure != nil && s.nodeFailure() != nil {
		_ = s.SendError(base.ID, protocol.ErrCodeNodeFailClosed, "signer node is fail-closed; restart required")
		return true
	}
	handle(s, raw, base.ID)
	return true
}
