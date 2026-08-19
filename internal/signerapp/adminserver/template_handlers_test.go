// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package adminserver

import (
	"encoding/json"
	"github.com/aplane-algo/aplane/internal/adminproto"
	"testing"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapi"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
)

func TestTemplateMessagesDispatchToTemplateServices(t *testing.T) {
	ir := identity.New(identity.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})
	ir.SetUnlocked()

	svc := &stubServices{
		listLibraryResult: adminproto.ListLibraryTemplatesResult{
			Templates: []adminproto.LibraryTemplateInfo{{
				KeyType:      "test.timed-policy.v1",
				TemplateType: "generic",
				DisplayName:  "Timed Allowlist",
			}},
		},
		installResult: adminproto.InstallLibraryTemplateResult{
			Success:      true,
			KeyType:      "test.timed-policy.v1",
			TemplateType: "generic",
		},
		listInstalledResult: adminproto.ListInstalledTemplatesResult{
			Templates: []adminproto.InstalledTemplateInfo{{
				KeyType:      "escrow-v1",
				TemplateType: "generic",
				Size:         123,
				Enabled:      true,
			}},
		},
		showInstalledResult: adminproto.ShowInstalledTemplateResult{
			Success:      true,
			KeyType:      "escrow-v1",
			TemplateType: "generic",
			TemplateYAML: []byte("schema_version: 1\n"),
		},
		showLibraryResult: adminproto.ShowLibraryTemplateResult{
			Success:       true,
			KeyType:       "test.timed-policy.v1",
			TemplateType:  "generic",
			SourcePath:    "/tmp/aplane/library/templates/timed-allowlist.yaml",
			SourceSHA256:  "0123456789abcdef",
			SourceModTime: 1778600000,
			TemplateYAML:  []byte("schema_version: 1\n"),
		},
		importInstalledResult: adminproto.ImportInstalledTemplateResult{
			Success:      true,
			KeyType:      "escrow-v1",
			TemplateType: "generic",
		},
		removeInstalledResult: adminproto.RemoveInstalledTemplateResult{
			Success:      true,
			KeyType:      "escrow-v1",
			TemplateType: "generic",
			Removed:      true,
		},
		activateResult: adminproto.ActivateKeyTypeResult{
			Success: true,
			KeyType: "aplane.ed25519.v1",
		},
		deactivateResult: adminproto.DeactivateKeyTypeResult{
			Success: true,
			KeyType: "aplane.ed25519.v1",
			Removed: true,
		},
		keyTypesResult: adminproto.ListKeyTypesResult{
			KeyTypes: []signerapi.KeyTypeInfo{{
				KeyType:     "test.timed-policy.v1",
				DisplayName: "Timed Allowlist",
			}},
		},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.templateDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	dispatchAdminMessage(t, session, protocol.ListLibraryTemplatesMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeListLibraryTemplates,
			ID:   "list-templates-1",
		},
	})
	dispatchAdminMessage(t, session, protocol.InstallLibraryTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeInstallLibraryTemplate,
			ID:   "install-template-1",
		},
		KeyType:      "test.timed-policy.v1",
		TemplateType: "generic",
	})
	dispatchAdminMessage(t, session, protocol.ListInstalledTemplatesMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeListInstalledTemplates,
			ID:   "list-installed-1",
		},
	})
	dispatchAdminMessage(t, session, protocol.ShowInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeShowInstalledTemplate,
			ID:   "show-installed-1",
		},
		KeyType: "escrow-v1",
	})
	dispatchAdminMessage(t, session, protocol.ShowLibraryTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeShowLibraryTemplate,
			ID:   "show-library-1",
		},
		KeyType:      "test.timed-policy.v1",
		TemplateType: "generic",
	})
	dispatchAdminMessage(t, session, protocol.ImportInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeImportInstalledTemplate,
			ID:   "import-installed-1",
		},
		TemplateYAML: protocol.SensitiveBytes("schema_version: 1\n"),
	})
	dispatchAdminMessage(t, session, protocol.RemoveInstalledTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeRemoveInstalledTemplate,
			ID:   "remove-installed-1",
		},
		KeyType: "escrow-v1",
	})
	dispatchAdminMessage(t, session, protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeActivateKeyType,
			ID:   "activate-keytype-1",
		},
		KeyType: "aplane.ed25519.v1",
	})
	dispatchAdminMessage(t, session, protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDeactivateKeyType,
			ID:   "deactivate-keytype-1",
		},
		KeyType: "aplane.ed25519.v1",
	})
	dispatchAdminMessage(t, session, protocol.ListKeyTypesMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeListKeyTypes,
			ID:   "keytypes-1",
		},
	})

	if svc.listLibraryCalls != 1 {
		t.Fatalf("ListLibraryTemplates calls = %d, want 1", svc.listLibraryCalls)
	}
	if svc.installLibraryCalls != 1 {
		t.Fatalf("InstallLibraryTemplate calls = %d, want 1", svc.installLibraryCalls)
	}
	if svc.lastInstallTemplate.KeyType != "test.timed-policy.v1" || svc.lastInstallTemplate.TemplateType != "generic" {
		t.Fatalf("install request = %+v, want test.timed-policy.v1 generic", svc.lastInstallTemplate)
	}
	if svc.listInstalledCalls != 1 {
		t.Fatalf("ListInstalledTemplates calls = %d, want 1", svc.listInstalledCalls)
	}
	if svc.showInstalledCalls != 1 || svc.lastShowInstalled.KeyType != "escrow-v1" {
		t.Fatalf("show installed calls/request = %d %+v, want escrow-v1", svc.showInstalledCalls, svc.lastShowInstalled)
	}
	if svc.showLibraryCalls != 1 ||
		svc.lastShowLibrary.KeyType != "test.timed-policy.v1" ||
		svc.lastShowLibrary.TemplateType != "generic" {
		t.Fatalf("show library calls/request = %d %+v, want test.timed-policy.v1 generic", svc.showLibraryCalls, svc.lastShowLibrary)
	}
	if svc.importInstalledCalls != 1 || string(svc.lastImportInstalled.TemplateYAML) != "schema_version: 1\n" {
		t.Fatalf("import installed calls/request = %d %q, want template yaml", svc.importInstalledCalls, string(svc.lastImportInstalled.TemplateYAML))
	}
	if svc.removeInstalledCalls != 1 || svc.lastRemoveInstalled.KeyType != "escrow-v1" {
		t.Fatalf("remove installed calls/request = %d %+v, want escrow-v1", svc.removeInstalledCalls, svc.lastRemoveInstalled)
	}
	if svc.activateKeyTypeCalls != 1 {
		t.Fatalf("ActivateKeyType calls = %d, want 1", svc.activateKeyTypeCalls)
	}
	if svc.lastActivateKeyType.KeyType != "aplane.ed25519.v1" {
		t.Fatalf("activate request = %+v, want dual provider", svc.lastActivateKeyType)
	}
	if svc.deactivateKeyTypeCalls != 1 {
		t.Fatalf("DeactivateKeyType calls = %d, want 1", svc.deactivateKeyTypeCalls)
	}
	if svc.lastDeactivateKeyType.KeyType != "aplane.ed25519.v1" {
		t.Fatalf("deactivate request = %+v, want dual provider", svc.lastDeactivateKeyType)
	}
	if svc.listKeyTypesCalls != 1 {
		t.Fatalf("ListKeyTypes calls = %d, want 1", svc.listKeyTypesCalls)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 10 {
		t.Fatalf("write count = %d, want 10", len(msgs))
	}
	assertAdminProtoMessage(t, msgs[0], protocol.MsgTypeLibraryTemplates, "list-templates-1")
	assertAdminProtoMessage(t, msgs[1], protocol.MsgTypeInstallLibraryTemplateResult, "install-template-1")
	assertAdminProtoMessage(t, msgs[2], protocol.MsgTypeInstalledTemplates, "list-installed-1")
	assertAdminProtoMessage(t, msgs[3], protocol.MsgTypeShowInstalledTemplateResult, "show-installed-1")
	assertAdminProtoMessage(t, msgs[4], protocol.MsgTypeShowLibraryTemplateResult, "show-library-1")
	assertAdminProtoMessage(t, msgs[5], protocol.MsgTypeImportInstalledTemplateResult, "import-installed-1")
	assertAdminProtoMessage(t, msgs[6], protocol.MsgTypeRemoveInstalledTemplateResult, "remove-installed-1")
	assertAdminProtoMessage(t, msgs[7], protocol.MsgTypeActivateKeyTypeResult, "activate-keytype-1")
	assertAdminProtoMessage(t, msgs[8], protocol.MsgTypeDeactivateKeyTypeResult, "deactivate-keytype-1")
	assertAdminProtoMessage(t, msgs[9], protocol.MsgTypeKeyTypes, "keytypes-1")
}

func TestTemplateInstallAndListRequireUnlockedRuntime(t *testing.T) {
	ir := identity.New(identity.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})

	svc := &stubServices{}
	conn := &queueConn{}
	session := NewSession(conn, svc.templateDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	dispatchAdminMessage(t, session, protocol.ListLibraryTemplatesMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeListLibraryTemplates,
			ID:   "list-locked",
		},
	})
	dispatchAdminMessage(t, session, protocol.InstallLibraryTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeInstallLibraryTemplate,
			ID:   "install-locked",
		},
		KeyType:      "test.timed-policy.v1",
		TemplateType: "generic",
	})
	dispatchAdminMessage(t, session, protocol.ShowLibraryTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeShowLibraryTemplate,
			ID:   "show-library-locked",
		},
		KeyType:      "test.timed-policy.v1",
		TemplateType: "generic",
	})
	dispatchAdminMessage(t, session, protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeActivateKeyType,
			ID:   "activate-locked",
		},
		KeyType: "aplane.ed25519.v1",
	})
	dispatchAdminMessage(t, session, protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDeactivateKeyType,
			ID:   "deactivate-locked",
		},
		KeyType: "aplane.ed25519.v1",
	})

	if svc.listLibraryCalls != 0 {
		t.Fatalf("ListLibraryTemplates calls = %d, want 0 while locked", svc.listLibraryCalls)
	}
	if svc.installLibraryCalls != 0 {
		t.Fatalf("InstallLibraryTemplate calls = %d, want 0 while locked", svc.installLibraryCalls)
	}
	if svc.showLibraryCalls != 0 {
		t.Fatalf("ShowLibraryTemplate calls = %d, want 0 while locked", svc.showLibraryCalls)
	}
	if svc.activateKeyTypeCalls != 0 {
		t.Fatalf("ActivateKeyType calls = %d, want 0 while locked", svc.activateKeyTypeCalls)
	}
	if svc.deactivateKeyTypeCalls != 0 {
		t.Fatalf("DeactivateKeyType calls = %d, want 0 while locked", svc.deactivateKeyTypeCalls)
	}

	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 5 {
		t.Fatalf("write count = %d, want 5", len(msgs))
	}
	for _, msg := range msgs {
		if msg.Type != protocol.MsgTypeError || msg.Code != protocol.ErrCodeSignerLocked {
			t.Fatalf("locked response = %+v, want signer_locked error", msg)
		}
	}
}

func TestListKeyTypesOnlyRequiresBoundRuntime(t *testing.T) {
	ir := identity.New(identity.Config{

		Authenticator: auth.NewTokenAuthenticator("token"),
	})

	svc := &stubServices{
		keyTypesResult: adminproto.ListKeyTypesResult{
			KeyTypes: []signerapi.KeyTypeInfo{{KeyType: "ed25519"}},
		},
	}
	conn := &queueConn{}
	session := NewSession(conn, svc.templateDeps())
	session.Bind(auth.NewDefaultIdentity("test"), ir)

	dispatchAdminMessage(t, session, protocol.ListKeyTypesMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeListKeyTypes,
			ID:   "keytypes-locked",
		},
	})

	if svc.listKeyTypesCalls != 1 {
		t.Fatalf("ListKeyTypes calls = %d, want 1", svc.listKeyTypesCalls)
	}
	msgs := decodeAdminProtoWrites(t, conn)
	if len(msgs) != 1 {
		t.Fatalf("write count = %d, want 1", len(msgs))
	}
	if msgs[0].Type != protocol.MsgTypeKeyTypes || msgs[0].ID != "keytypes-locked" {
		t.Fatalf("response = %+v, want key_types response", msgs[0])
	}
}

func dispatchAdminMessage(t *testing.T, session *Session, msg any) {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	if !session.Dispatch(data) {
		t.Fatalf("Dispatch(%T) = false, want true", msg)
	}
}

type adminProtoWrite struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Success    bool   `json:"success,omitempty"`
	Target     string `json:"target,omitempty"`
	PolicyYAML string `json:"policy_yaml,omitempty"`
	Canonical  bool   `json:"canonical,omitempty"`
	Code       string `json:"code,omitempty"`
}

func decodeAdminProtoWrites(t *testing.T, conn *queueConn) []adminProtoWrite {
	t.Helper()
	out := make([]adminProtoWrite, len(conn.writes))
	for i, data := range conn.writes {
		if err := json.Unmarshal(data, &out[i]); err != nil {
			t.Fatalf("decode write %d: %v", i, err)
		}
	}
	return out
}

func assertAdminProtoMessage(t *testing.T, msg adminProtoWrite, msgType, id string) {
	t.Helper()
	if msg.Type != msgType || msg.ID != id {
		t.Fatalf("message = %+v, want type %s id %s", msg, msgType, id)
	}
}
