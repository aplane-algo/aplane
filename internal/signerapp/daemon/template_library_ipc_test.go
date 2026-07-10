// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/adminproto"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/templatelibrary"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

func TestIPCInstallLibraryTemplateActivatesKeyTypeWithoutRestart(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-library-install-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	if genericlsig.Get(keyType) != nil {
		t.Fatalf("test key type %q already registered", keyType)
	}
	writeLibraryTemplateForTest(t, server, "install.yaml", renderGenericTemplateYAML(family, 1, "IPC Library Install", "installed over IPC"))

	recorder := &ipcJSONRecorderConn{}
	ir := server.registry.Get(auth.CurrentProductIdentityID())
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)
	dispatchIPCMessage(t, session, protocol.InstallLibraryTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeInstallLibraryTemplate,
			ID:   "install-template",
		},
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":          string(protocol.MessageKindResponse),
		"type":          protocol.MsgTypeInstallLibraryTemplateResult,
		"id":            "install-template",
		"success":       true,
		"key_type":      keyType,
		"template_type": string(templatestore.TemplateTypeGeneric),
	}) {
		t.Fatalf("install response mismatch: %#v", msgs[0])
	}

	if genericlsig.Get(keyType) == nil {
		t.Fatalf("generic template %q not registered after IPC install", keyType)
	}
	if _, ok := findKeyTypeInfo(fetchKeyTypesForTest(t, server), keyType); !ok {
		t.Fatalf("key type %q not visible through /keytypes after IPC install", keyType)
	}
}

func TestIPCDisableAndEnableInstalledTemplateKeepsTemplateFile(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-template-disable-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	writeLibraryTemplateForTest(t, server, "disable.yaml", renderGenericTemplateYAML(family, 1, "IPC Disable", "disabled over IPC"))

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	ipcServer := &IPCServer{signer: server}
	installRecorder := &ipcJSONRecorderConn{}
	installSession := newBoundTestSession(ipcServer, installRecorder, ir)
	dispatchIPCMessage(t, installSession, protocol.InstallLibraryTemplateMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeInstallLibraryTemplate,
			ID:   "install-template",
		},
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if !reflectJSONSubset(installRecorder.messages(t)[0], map[string]any{
		"type":    protocol.MsgTypeInstallLibraryTemplateResult,
		"success": true,
	}) {
		t.Fatalf("install response mismatch: %#v", installRecorder.messages(t)[0])
	}

	disableRecorder := &ipcJSONRecorderConn{}
	disableSession := newBoundTestSession(ipcServer, disableRecorder, ir)
	dispatchIPCMessage(t, disableSession, protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDeactivateKeyType,
			ID:   "disable-template",
		},
		KeyType: keyType,
	})
	if !reflectJSONSubset(disableRecorder.messages(t)[0], map[string]any{
		"type":     protocol.MsgTypeDeactivateKeyTypeResult,
		"success":  true,
		"key_type": keyType,
		"removed":  true,
	}) {
		t.Fatalf("disable response mismatch: %#v", disableRecorder.messages(t)[0])
	}
	if !keyTypeStateDisabled(server, auth.CurrentProductIdentityID(), keyType) {
		t.Fatalf("disabled state not written for %s", keyType)
	}
	if !templatestore.TemplateExistsForPaths(server.keyPaths, auth.CurrentProductIdentityID(), keyType, templatestore.TemplateTypeGeneric) {
		t.Fatalf("installed template file was removed during disable")
	}
	if _, ok := findKeyTypeInfo(fetchKeyTypesForTest(t, server), keyType); ok {
		t.Fatalf("disabled template key type %q still visible through /keytypes", keyType)
	}

	enableRecorder := &ipcJSONRecorderConn{}
	enableSession := newBoundTestSession(ipcServer, enableRecorder, ir)
	dispatchIPCMessage(t, enableSession, protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeActivateKeyType,
			ID:   "enable-template",
		},
		KeyType: keyType,
	})
	if !reflectJSONSubset(enableRecorder.messages(t)[0], map[string]any{
		"type":     protocol.MsgTypeActivateKeyTypeResult,
		"success":  true,
		"key_type": keyType,
	}) {
		t.Fatalf("enable response mismatch: %#v", enableRecorder.messages(t)[0])
	}
	if keyTypeStateDisabled(server, auth.CurrentProductIdentityID(), keyType) {
		t.Fatalf("disabled state still present after enable")
	}
	if _, ok := findKeyTypeInfo(fetchKeyTypesForTest(t, server), keyType); !ok {
		t.Fatalf("enabled template key type %q not visible through /keytypes", keyType)
	}
}

func TestShowLibraryTemplateReturnsPlaintextYAML(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-show-library-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	yamlData := renderGenericTemplateYAML(family, 1, "Show Library", "viewed via IPC")
	writeLibraryTemplateForTest(t, server, "show.yaml", yamlData)

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	result := server.adminServices().ShowLibraryTemplate(ir, adminproto.ShowLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if !result.Success {
		t.Fatalf("ShowLibraryTemplate() = %+v, want success", result)
	}
	if string(result.TemplateYAML) != string(yamlData) {
		t.Fatalf("ShowLibraryTemplate() YAML mismatch:\ngot  %q\nwant %q", string(result.TemplateYAML), string(yamlData))
	}
	if result.SourcePath == "" {
		t.Fatalf("ShowLibraryTemplate() SourcePath empty")
	}
	sum := sha256.Sum256(yamlData)
	if result.SourceSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("ShowLibraryTemplate() SourceSHA256 = %q, want %q", result.SourceSHA256, hex.EncodeToString(sum[:]))
	}
	if result.SourceModTime == 0 {
		t.Fatalf("ShowLibraryTemplate() SourceModTime empty")
	}
}

func TestShowLibraryTemplateMissingEntryReturnsNotFound(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	result := server.adminServices().ShowLibraryTemplate(ir, adminproto.ShowLibraryTemplateRequest{
		KeyType:      "no-such-key-type-v1",
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if result.Success {
		t.Fatalf("ShowLibraryTemplate() unexpectedly succeeded: %+v", result)
	}
	if result.Code != protocol.ResultCodeLibraryEntryNotFound {
		t.Fatalf("ShowLibraryTemplate() Code = %q, want %s", result.Code, protocol.ResultCodeLibraryEntryNotFound)
	}
}

func TestShowLibraryTemplateRejectsCompiledProvider(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	result := server.adminServices().ShowLibraryTemplate(ir, adminproto.ShowLibraryTemplateRequest{
		KeyType:      "aplane.falcon1024_ed25519.v1",
		TemplateType: "compiled_provider",
	})
	if result.Success {
		t.Fatalf("ShowLibraryTemplate() unexpectedly succeeded: %+v", result)
	}
	if result.Code != protocol.ResultCodeInvalidTemplateType {
		t.Fatalf("ShowLibraryTemplate() Code = %q, want %s", result.Code, protocol.ResultCodeInvalidTemplateType)
	}
}

func TestImportInstalledTemplateRejectsMalformedYAML(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	result := server.adminServices().ImportInstalledTemplate(ir, adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: []byte("schema_version: 1\ntemplate_type: generic\nfamily:"),
	})
	if result.Success || result.Code != protocol.ResultCodeInvalidTemplate {
		t.Fatalf("ImportInstalledTemplate() = %+v, want %s failure", result, protocol.ResultCodeInvalidTemplate)
	}
	if result.Error == "" {
		t.Fatalf("ImportInstalledTemplate() error is empty, want parse context")
	}
}

func TestImportInstalledTemplateRejectsMissingTemplateMode(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	result := server.adminServices().ImportInstalledTemplate(ir, adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: []byte(`schema_version: 1
template_type: generic
publisher: test
family: legacy-template
version: 1
display_name: Legacy
teal: |
  int 1
`),
	})
	if result.Success || result.Code != protocol.ResultCodeInvalidTemplate {
		t.Fatalf("ImportInstalledTemplate() = %+v, want %s failure", result, protocol.ResultCodeInvalidTemplate)
	}
	if !strings.Contains(result.Error, "template_mode is required") {
		t.Fatalf("ImportInstalledTemplate() error = %q, want missing template_mode rejection", result.Error)
	}
}

func TestImportInstalledTemplateIdempotentAndRejectsConflictingDefinition(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-template-import-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	ir := server.registry.Get(auth.CurrentProductIdentityID())
	templateYAML := renderGenericTemplateYAML(family, 1, "IPC Import", "imported over IPC")

	initial := server.adminServices().ImportInstalledTemplate(ir, adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: templateYAML,
	})
	if !initial.Success || initial.AlreadyExists || initial.KeyType != keyType {
		t.Fatalf("initial ImportInstalledTemplate() = %+v, want fresh success for %s", initial, keyType)
	}
	again := server.adminServices().ImportInstalledTemplate(ir, adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: templateYAML,
	})
	if !again.Success || !again.AlreadyExists || again.KeyType != keyType {
		t.Fatalf("second ImportInstalledTemplate() = %+v, want idempotent already_exists", again)
	}

	conflicting := renderGenericTemplateYAMLWithTEAL(family, 1, "IPC Import Changed", "int 0")
	conflict := server.adminServices().ImportInstalledTemplate(ir, adminproto.ImportInstalledTemplateRequest{
		TemplateYAML: conflicting,
	})
	if conflict.Success || conflict.Code != "import_failed" || conflict.KeyType != keyType {
		t.Fatalf("conflicting ImportInstalledTemplate() = %+v, want import_failed for %s", conflict, keyType)
	}
	if !strings.Contains(conflict.Error, "installed template does not match incoming definition") {
		t.Fatalf("conflicting ImportInstalledTemplate() error = %q, want mismatch context", conflict.Error)
	}
}

func TestRemoveInstalledTemplateHandlesDisabledTemplate(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-template-remove-disabled-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	writeLibraryTemplateForTest(t, server, "remove-disabled.yaml", renderGenericTemplateYAML(family, 1, "IPC Remove Disabled", "removed while disabled"))

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	install := server.adminServices().InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if !install.Success {
		t.Fatalf("InstallLibraryTemplate() = %+v, want success", install)
	}

	disabled := server.adminServices().DeactivateKeyType(ir, adminproto.DeactivateKeyTypeRequest{KeyType: keyType})
	if !disabled.Success || !disabled.Removed {
		t.Fatalf("DeactivateKeyType() = %+v, want disabled template", disabled)
	}
	if !keyTypeStateDisabled(server, ir.ID(), keyType) {
		t.Fatalf("disabled state not written for %s", keyType)
	}

	removed := server.adminServices().RemoveInstalledTemplate(ir, adminproto.RemoveInstalledTemplateRequest{KeyType: keyType})
	if !removed.Success || !removed.Removed {
		t.Fatalf("RemoveInstalledTemplate() = %+v, want disabled template removal", removed)
	}
	if templatestore.TemplateExistsForPaths(server.keyPaths, ir.ID(), keyType, templatestore.TemplateTypeGeneric) {
		t.Fatalf("template %s still exists after removal", keyType)
	}
	if keyTypeStateDisabled(server, ir.ID(), keyType) {
		t.Fatalf("disabled state still exists after template removal for %s", keyType)
	}
	if _, ok := findKeyTypeInfo(fetchKeyTypesForTest(t, server), keyType); ok {
		t.Fatalf("removed template key type %q still visible through /keytypes", keyType)
	}
}

func TestIPCActivateKeyTypeEnablesCompiledProvider(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	keyType := "aplane.falcon1024_ed25519.v1"
	recorder := &ipcJSONRecorderConn{}
	ir := server.registry.Get(auth.CurrentProductIdentityID())
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)
	dispatchIPCMessage(t, session, protocol.ActivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeActivateKeyType,
			ID:   "activate-keytype",
		},
		KeyType: keyType,
	})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":     string(protocol.MessageKindResponse),
		"type":     protocol.MsgTypeActivateKeyTypeResult,
		"id":       "activate-keytype",
		"success":  true,
		"key_type": keyType,
	}) {
		t.Fatalf("activation response mismatch: %#v", msgs[0])
	}
	if !keyTypeStateEnabled(server, auth.CurrentProductIdentityID(), keyType) {
		t.Fatalf("enabled state not written for %s", keyType)
	}
	if _, ok := findKeyTypeInfo(fetchKeyTypesForTest(t, server), keyType); !ok {
		t.Fatalf("key type %q not visible through /keytypes after activation", keyType)
	}
}

func TestIPCDeactivateKeyTypeDisablesUnusedCompiledProvider(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	keyType := "aplane.ecdsak1.v1"
	ir := server.registry.Get(auth.CurrentProductIdentityID())
	if _, err := templatelibrary.ActivateCompiledProvider(server.keyPaths, ir.ID(), keyType); err != nil {
		t.Fatalf("ActivateCompiledProvider() error = %v", err)
	}

	recorder := &ipcJSONRecorderConn{}
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)
	dispatchIPCMessage(t, session, protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDeactivateKeyType,
			ID:   "deactivate-keytype",
		},
		KeyType: keyType,
	})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":     string(protocol.MessageKindResponse),
		"type":     protocol.MsgTypeDeactivateKeyTypeResult,
		"id":       "deactivate-keytype",
		"success":  true,
		"key_type": keyType,
		"removed":  true,
	}) {
		t.Fatalf("deactivation response mismatch: %#v", msgs[0])
	}
	if keyTypeStateEnabled(server, auth.CurrentProductIdentityID(), keyType) {
		t.Fatalf("enabled state still exists for %s", keyType)
	}
	if _, ok := findKeyTypeInfo(fetchKeyTypesForTest(t, server), keyType); ok {
		t.Fatalf("key type %q still visible through /keytypes after deactivation", keyType)
	}
}

func TestIPCDeactivateKeyTypeRejectsProviderInUse(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	keyType := "aplane.ecdsak1.v1"
	ir := server.registry.Get(auth.CurrentProductIdentityID())
	if _, err := templatelibrary.ActivateCompiledProvider(server.keyPaths, ir.ID(), keyType); err != nil {
		t.Fatalf("ActivateCompiledProvider() error = %v", err)
	}
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
		payload := apkeys.NewDSALSigPayload(keyType, keyType, []byte{0x01}, []byte{0x02}, nil, bytecode, 5, "", nil, "")
		defer payload.ZeroSecrets()
		_, saveErr := apkeys.SavePayload(server.keyPaths, ir.ID(), payload, masterKey)
		return saveErr
	}); err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}

	recorder := &ipcJSONRecorderConn{}
	ipcServer := &IPCServer{signer: server}
	session := newBoundTestSession(ipcServer, recorder, ir)
	dispatchIPCMessage(t, session, protocol.DeactivateKeyTypeMessage{
		BaseMessage: protocol.BaseMessage{
			Kind: protocol.MessageKindRequest,
			Type: protocol.MsgTypeDeactivateKeyType,
			ID:   "deactivate-keytype-in-use",
		},
		KeyType: keyType,
	})

	msgs := recorder.messages(t)
	if len(msgs) != 1 {
		t.Fatalf("message count = %d, want 1", len(msgs))
	}
	if !reflectJSONSubset(msgs[0], map[string]any{
		"kind":    string(protocol.MessageKindResponse),
		"type":    protocol.MsgTypeDeactivateKeyTypeResult,
		"id":      "deactivate-keytype-in-use",
		"success": false,
		"code":    protocol.ResultCodeKeyTypeInUse,
	}) {
		t.Fatalf("deactivation rejection response mismatch: %#v", msgs[0])
	}
	if errText, _ := msgs[0]["error"].(string); !strings.Contains(errText, "key(s) still use it") {
		t.Fatalf("deactivation error = %q, want in-use context", errText)
	}
	if !keyTypeStateEnabled(server, auth.CurrentProductIdentityID(), keyType) {
		t.Fatalf("enabled state was removed despite in-use rejection for %s", keyType)
	}
}

func TestInstallLibraryTemplateReloadFailureRollsBackEncryptedFile(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-library-reload-fail-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	writeLibraryTemplateForTest(t, server, "reload-fail.yaml", renderGenericTemplateYAML(family, 1, "Reload Failure", "forces reload failure"))

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("forced reload failure")
	})

	result := server.adminServices().InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if result.Success || result.Code != protocol.ResultCodeReloadFailed {
		t.Fatalf("InstallLibraryTemplate result = %+v, want %s", result, protocol.ResultCodeReloadFailed)
	}
	assertInstalledTemplateRemoved(t, server, keyType, templatestore.TemplateTypeGeneric)
}

func TestInstallLibraryTemplateReloadFailureDoesNotRemoveExistingInstall(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-library-reinstall-fail-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	writeLibraryTemplateForTest(t, server, "reinstall-fail.yaml", renderGenericTemplateYAML(family, 1, "Reinstall Failure", "existing install survives reload failure"))

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	initial := server.adminServices().InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if !initial.Success || initial.AlreadyExists {
		t.Fatalf("initial InstallLibraryTemplate result = %+v, want fresh success", initial)
	}
	installedPath := templatestore.GetTemplateFilePathForPaths(server.keyPaths, auth.CurrentProductIdentityID(), keyType, templatestore.TemplateTypeGeneric)
	if _, err := os.Stat(installedPath); err != nil {
		t.Fatalf("initial installed template stat: %v", err)
	}

	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, errors.New("forced reload failure")
	})
	again := server.adminServices().InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if again.Success || again.Code != protocol.ResultCodeReloadFailed || !again.AlreadyExists {
		t.Fatalf("second InstallLibraryTemplate result = %+v, want %s already_exists", again, protocol.ResultCodeReloadFailed)
	}
	if _, err := os.Stat(installedPath); err != nil {
		t.Fatalf("existing installed template was removed: %v", err)
	}
}

func TestInstallLibraryTemplateActivationFailureRollsBackEncryptedFile(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-library-activation-fail-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	writeLibraryTemplateForTest(t, server, "activation-fail.yaml", renderGenericTemplateYAML(family, 1, "Activation Failure", "reload does not activate provider"))

	ir := server.registry.Get(auth.CurrentProductIdentityID())
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, nil
	})

	result := server.adminServices().InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if result.Success || result.Code != protocol.ResultCodeActivationFailed {
		t.Fatalf("InstallLibraryTemplate result = %+v, want %s", result, protocol.ResultCodeActivationFailed)
	}
	assertInstalledTemplateRemoved(t, server, keyType, templatestore.TemplateTypeGeneric)
}

func TestInstallLibraryTemplateActivationVerificationUsesReloadReport(t *testing.T) {
	server, cleanup := setupTestSigner(t)
	defer cleanup()

	family := fmt.Sprintf("ipc-library-global-provider-%d", time.Now().UnixNano())
	keyType := testTemplateKeyType(family)
	yamlData := renderGenericTemplateYAML(family, 1, "Global Provider", "global provider alone must not prove identity activation")
	writeLibraryTemplateForTest(t, server, "global-provider.yaml", yamlData)

	parsed, err := templatelibrary.ParseYAML("global-provider.yaml", yamlData)
	if err != nil {
		t.Fatalf("ParseYAML() error = %v", err)
	}
	ir := server.registry.Get(auth.CurrentProductIdentityID())
	if err := ir.WithMasterKey(func(masterKey []byte) error {
		_, installErr := templatelibrary.InstallParsed(server.keyPaths, ir.ID(), parsed, masterKey)
		return installErr
	}); err != nil {
		t.Fatalf("preinstall template: %v", err)
	}
	installedPath := templatestore.GetTemplateFilePathForPaths(server.keyPaths, ir.ID(), keyType, templatestore.TemplateTypeGeneric)

	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if !genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec)) {
		t.Fatalf("template %q already registered", keyType)
	}

	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return &signertemplates.ReloadReport{}, nil
	})
	result := server.adminServices().InstallLibraryTemplate(ir, adminproto.InstallLibraryTemplateRequest{
		KeyType:      keyType,
		TemplateType: string(templatestore.TemplateTypeGeneric),
	})
	if result.Success || result.Code != protocol.ResultCodeActivationFailed || !result.AlreadyExists {
		t.Fatalf("InstallLibraryTemplate result = %+v, want %s already_exists", result, protocol.ResultCodeActivationFailed)
	}
	if _, err := os.Stat(installedPath); err != nil {
		t.Fatalf("existing installed template was removed: %v", err)
	}
}

func writeLibraryTemplateForTest(t *testing.T, server *Signer, filename string, yamlData []byte) {
	t.Helper()
	dir := server.keyPaths.TemplateLibraryDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir template library: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), yamlData, 0o640); err != nil {
		t.Fatalf("write template library file: %v", err)
	}
}

func assertInstalledTemplateRemoved(t *testing.T, server *Signer, keyType string, templateType templatestore.TemplateType) {
	t.Helper()
	path := templatestore.GetTemplateFilePathForPaths(server.keyPaths, auth.CurrentProductIdentityID(), keyType, templateType)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("installed template path stat err = %v, want not exist for %s", err, path)
	}
}

func testTemplateKeyType(family string) string {
	return "test." + family + ".v1"
}

func keyTypeStateEnabled(server *Signer, identityID, keyType string) bool {
	rec, ok, err := keytypestate.Get(server.keyPaths, identityID, keyType)
	return err == nil && ok && rec.State == keytypestate.StateEnabled
}

func keyTypeStateDisabled(server *Signer, identityID, keyType string) bool {
	rec, ok, err := keytypestate.Get(server.keyPaths, identityID, keyType)
	return err == nil && ok && rec.State == keytypestate.StateDisabled
}

func renderGenericTemplateYAMLWithTEAL(family string, version int, displayName, teal string) []byte {
	return []byte(fmt.Sprintf(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: %s
version: %d
display_name: %q
description: "test template"
teal: |
  #pragma version 8
  %s
`, family, version, displayName, teal))
}

func dispatchIPCMessage(t *testing.T, session *adminserver.Session, msg any) {
	t.Helper()
	data, err := protocol.MarshalAdminMessage(msg)
	if err != nil {
		t.Fatalf("MarshalAdminMessage() error = %v", err)
	}
	if !session.Dispatch(data) {
		t.Fatalf("Dispatch(%T) = false, want true", msg)
	}
}
