// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keyadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/genericlsig"
	internalkeygen "github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/keymgmt"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keystore"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigsalt"
	"github.com/aplane-algo/aplane/internal/noderole"
	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signertemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	ed25519 "github.com/aplane-algo/aplane/internal/signing/ed25519"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
	falconkeygen "github.com/aplane-algo/aplane/lsig/falcon1024/keygen"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
	lsigsignerreg "github.com/aplane-algo/aplane/lsig/signerreg"
)

var testPassphrase = []byte("test-passphrase-for-unit-tests!")

func init() {
	lsigsignerreg.RegisterSigner()
	ed25519.RegisterSigner()
}

type auditRecorder struct {
	generated []struct {
		identityID string
		address    string
		keyType    string
	}
	deleted []struct {
		identityID  string
		address     string
		deletedPath string
	}
	imported []struct {
		identityID string
		address    string
		keyType    string
	}
}

type recordingLock struct {
	locks   int
	unlocks int
	held    bool
}

func (l *recordingLock) Lock() {
	l.locks++
	l.held = true
}

func (l *recordingLock) Unlock() {
	l.unlocks++
	l.held = false
}

func (a *auditRecorder) LogKeyGenerated(identityID, address, keyType string) {
	a.generated = append(a.generated, struct {
		identityID string
		address    string
		keyType    string
	}{identityID: identityID, address: address, keyType: keyType})
}

func (a *auditRecorder) LogKeyDeleted(identityID, address, deletedPath string) {
	a.deleted = append(a.deleted, struct {
		identityID  string
		address     string
		deletedPath string
	}{identityID: identityID, address: address, deletedPath: deletedPath})
}

func (a *auditRecorder) LogKeyImported(identityID, address, keyType string) {
	a.imported = append(a.imported, struct {
		identityID string
		address    string
		keyType    string
	}{identityID: identityID, address: address, keyType: keyType})
}

func setupIdentityRuntime(t *testing.T) *identity.Runtime {
	return setupIdentityRuntimeWithRole(t, noderole.RoleSigner)
}

func setupIdentityRuntimeWithRole(t *testing.T, role noderole.Role) *identity.Runtime {
	t.Helper()

	tmpDir := t.TempDir()
	keyPaths := storepaths.NewPaths(tmpDir)
	userDir := filepath.Join(tmpDir, "identities", auth.DefaultIdentityID)
	keysDir := keyPaths.KeysDir(auth.DefaultIdentityID)
	if err := os.MkdirAll(keysDir, 0o750); err != nil {
		t.Fatalf("MkdirAll(keysDir): %v", err)
	}
	if _, _, err := crypto.CreateKeystoreMetadata(userDir, testPassphrase); err != nil {
		t.Fatalf("CreateKeystoreMetadata(): %v", err)
	}

	ks := keystore.NewFileKeyStoreForPaths(keyPaths, auth.DefaultIdentityID)
	if _, err := ks.InitializeMasterKey(testPassphrase); err != nil {
		t.Fatalf("InitializeMasterKey(): %v", err)
	}

	ir := identity.New(identity.Config{
		ID:            auth.DefaultIdentityID,
		KeyStore:      ks,
		KeyPaths:      keyPaths,
		Authenticator: auth.NewTokenAuthenticator("test-token"),
		NodeRole:      role,
	})
	ir.SetReloadFunc(func(identityID string, passphrase []byte, session *keystore.KeySession) (*signertemplates.ReloadReport, error) {
		return nil, reloadKeysForTest(ir, keyPaths)
	})
	ir.SetUnlocked()
	return ir
}

func reloadKeysForTest(ir *identity.Runtime, _ storepaths.Paths) error {
	ks := ir.KeyStore()
	if err := ks.Scan(nil); err != nil {
		return err
	}
	ir.PublishSnapshot(ks.GetCache(), ks.GetKeyTypes(), ks.GetLsigSizes())
	return nil
}

func TestServiceGenerateKeyEd25519(t *testing.T) {
	ir := setupIdentityRuntime(t)
	audit := &auditRecorder{}
	svc := Service{AuditLog: audit}

	result, err := svc.GenerateKey(context.Background(), ir, "ed25519", nil, nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %#v", err)
	}
	if result.Address == "" {
		t.Fatal("GenerateKey() returned empty address")
	}
	if result.KeyType != "ed25519" {
		t.Fatalf("GenerateKey() keyType = %q, want ed25519", result.KeyType)
	}
	if result.Mnemonic == "" {
		t.Fatal("GenerateKey() returned empty mnemonic")
	}
	if _, err := ir.FindKeyFile(result.Address); err != nil {
		t.Fatalf("FindKeyFile(%q) error = %v", result.Address, err)
	}
	details, svcErr := svc.GetKeyDetails(ir, result.Address)
	if svcErr != nil {
		t.Fatalf("GetKeyDetails(ed25519) error = %#v", svcErr)
	}
	if details.PublicKeyHex != "" {
		t.Fatalf("GetKeyDetails(ed25519) PublicKeyHex = %q, want hidden", details.PublicKeyHex)
	}
	if len(audit.generated) != 1 {
		t.Fatalf("generated audit count = %d, want 1", len(audit.generated))
	}
}

func TestServiceGenerateKeyAttestorComponent(t *testing.T) {
	for _, keyType := range []string{
		keytypes.SentryComponentEd25519V1,
		keytypes.SentryComponentFalcon1024V1,
	} {
		t.Run(keyType, func(t *testing.T) {
			ir := setupIdentityRuntimeWithRole(t, noderole.RoleSentry)
			audit := &auditRecorder{}
			svc := Service{AuditLog: audit}

			result, err := svc.GenerateKey(context.Background(), ir, keyType, nil, nil)
			if err != nil {
				t.Fatalf("GenerateKey(component) error = %#v", err)
			}
			if result.PublicKeyHex == "" {
				t.Fatal("GenerateKey(component) public key is empty")
			}
			if !keytypes.IsComponentKeySelector(result.Address) {
				t.Fatalf("GenerateKey(component) address = %q, want component key selector", result.Address)
			}
			if result.Address == result.PublicKeyHex {
				t.Fatal("GenerateKey(component) address unexpectedly equals public key hex")
			}
			details, svcErr := svc.GetKeyDetails(ir, result.Address)
			if svcErr != nil {
				t.Fatalf("GetKeyDetails(component) error = %#v", svcErr)
			}
			if details.PublicKeyHex != result.PublicKeyHex {
				t.Fatalf("GetKeyDetails(component) PublicKeyHex = %q, want %q", details.PublicKeyHex, result.PublicKeyHex)
			}
			if !result.IsComponentKey {
				t.Fatal("GenerateKey(component) IsComponentKey = false, want true")
			}
			if result.IsSpendingAccount == nil || *result.IsSpendingAccount {
				t.Fatalf("GenerateKey(component) IsSpendingAccount = %#v, want false pointer", result.IsSpendingAccount)
			}
			if result.Mnemonic != "" {
				t.Fatalf("GenerateKey(component) mnemonic = %q, want empty", result.Mnemonic)
			}
			if _, err := ir.FindKeyFile(result.Address); err != nil {
				t.Fatalf("FindKeyFile(%q) error = %v", result.Address, err)
			}
			if len(audit.generated) != 1 || audit.generated[0].address != result.Address {
				t.Fatalf("generated audit = %#v, want component address", audit.generated)
			}
		})
	}
}

func TestKeyDetailsParametersProjectsAttestedAttestorSelector(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0xab}, 32)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	got := keyDetailsParameters(keytypes.GuardedFalcon1024SentryEd25519V1, map[string]string{
		keytypes.ParameterSentryPublicKey: hex.EncodeToString(publicKey),
		"other":                           "kept",
	})

	if got[keyDetailsAttestorLabel] != componentKey {
		t.Fatalf("Sentry = %q, want %q", got[keyDetailsAttestorLabel], componentKey)
	}
	if _, ok := got[keytypes.ParameterSentryPublicKey]; ok {
		t.Fatalf("projected parameters exposed raw sentry public key: %#v", got)
	}
	if got["other"] != "kept" {
		t.Fatalf("other parameter = %q, want kept", got["other"])
	}
}

func TestServiceGenerateKeyRejectsKeyTypeDisallowedByNodeRole(t *testing.T) {
	ir := setupIdentityRuntime(t)
	svc := Service{}

	result, err := svc.GenerateKey(context.Background(), ir, keytypes.SentryComponentEd25519V1, nil, nil)
	if result != nil {
		t.Fatalf("GenerateKey(component in signer node) result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, `node role "signer"`) {
		t.Fatalf("GenerateKey(component in signer node) error = %#v, want node role invalid input", err)
	}

	ir = setupIdentityRuntimeWithRole(t, noderole.RoleSentry)
	result, err = svc.GenerateKey(context.Background(), ir, "ed25519", nil, nil)
	if result != nil {
		t.Fatalf("GenerateKey(ed25519 in attestor node) result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, `node role "sentry"`) {
		t.Fatalf("GenerateKey(ed25519 in attestor node) error = %#v, want node role invalid input", err)
	}
}

func TestServiceGenerateKeyUsesMutationLock(t *testing.T) {
	ir := setupIdentityRuntime(t)
	lock := &recordingLock{}
	svc := Service{
		MutationLock: func(identityID string) Locker {
			if identityID != ir.ID() {
				t.Fatalf("MutationLock identityID = %q, want %q", identityID, ir.ID())
			}
			return lock
		},
	}

	if _, err := svc.GenerateKey(context.Background(), ir, "ed25519", nil, nil); err != nil {
		t.Fatalf("GenerateKey() error = %#v", err)
	}
	if lock.locks != 1 || lock.unlocks != 1 || lock.held {
		t.Fatalf("mutation lock state = locks:%d unlocks:%d held:%v, want balanced single lock", lock.locks, lock.unlocks, lock.held)
	}
}

func TestServiceGenerateKeyRequiresKeyType(t *testing.T) {
	ir := setupIdentityRuntime(t)
	svc := Service{}

	result, err := svc.GenerateKey(context.Background(), ir, "", nil, nil)
	if result != nil {
		t.Fatalf("GenerateKey() result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorInvalidInput || err.Message != "key_type is required" {
		t.Fatalf("GenerateKey() error = %#v, want invalid key_type is required", err)
	}
}

func TestServiceGenerateKeyRejectsLibraryProviderBeforeActivation(t *testing.T) {
	ir := setupIdentityRuntime(t)
	svc := Service{}

	result, err := svc.GenerateKey(context.Background(), ir, "aplane.falcon1024_ed25519.v1", nil, nil)
	if result != nil {
		t.Fatalf("GenerateKey() result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorInvalidInput {
		t.Fatalf("GenerateKey() error = %#v, want invalid input", err)
	}
}

func TestServiceGenerateKeyRereadsActivationAfterDeactivation(t *testing.T) {
	ir := setupIdentityRuntime(t)
	svc := Service{}
	keyType := "aplane.falcon1024_ed25519.v1"

	if err := keytypestate.Put(ir.KeyPaths(), ir.ID(), keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := keytypestate.Delete(ir.KeyPaths(), ir.ID(), keyType); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	result, genErr := svc.GenerateKey(context.Background(), ir, keyType, nil, nil)
	if result != nil {
		t.Fatalf("GenerateKey() result = %#v, want nil", result)
	}
	if genErr == nil || genErr.Kind != ErrorInvalidInput {
		t.Fatalf("GenerateKey() error = %#v, want invalid input after deactivation", genErr)
	}
}

func TestServiceGenerateKeyRejectsGenericTemplateNotEnabledForIdentity(t *testing.T) {
	ir := setupIdentityRuntime(t)
	svc := Service{}
	keyType := "test.generic-keyadmin-other-identity.v1"
	yamlData := []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: generic-keyadmin-other-identity
version: 1
display_name: Generic Keyadmin Other Identity
description: Test identity-scoped generation
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec() error = %v", err)
	}
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))

	called := false
	result, genErr := svc.GenerateKey(context.Background(), ir, keyType, nil, func(context.Context, *identity.Runtime, string, map[string]string) (string, error) {
		called = true
		return "ADDR", nil
	})
	if result != nil {
		t.Fatalf("GenerateKey() result = %#v, want nil", result)
	}
	if genErr == nil || genErr.Kind != ErrorInvalidInput {
		t.Fatalf("GenerateKey() error = %#v, want invalid input", genErr)
	}
	if called {
		t.Fatal("generic generator was called for key type not enabled for identity")
	}
}

// F1 canary: a composed YAML template installed on identity A must not let
// identity B generate keys for that key type. Pre-refactor, the process-global
// LSig provider registry leaked the key type across identities; the post-
// refactor gate is per-identity through keytypestate.CanGenerate.
func TestServiceGenerateKeyRejectsComposedTemplateInstalledForOtherIdentity(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	keyType := "test.falcon1024-keyadmin-cross-identity.v1"
	yamlData := []byte(`schema_version: 1
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: falcon1024-keyadmin-cross-identity
version: 1
display_name: "Falcon Keyadmin Cross Identity"
description: "F1 canary: cross-identity composed template"
parameters: []
runtime_args: []
teal: |
  int 1
  return
`)
	spec, err := composeddsa.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if err := composeddsa.ValidateTemplateSpec(spec); err != nil {
		t.Fatalf("ValidateTemplateSpec() error = %v", err)
	}
	provider, err := composeddsa.NewProviderFromTemplateSpec(spec)
	if err != nil {
		t.Fatalf("NewProviderFromTemplateSpec() error = %v", err)
	}
	logicsigdsa.RegisterIfAbsent(provider)

	if err := keytypestate.Put(paths, "alice", keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceYAMLComposed,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put(alice) error = %v", err)
	}

	bob := identity.New(identity.Config{
		ID:            "bob",
		KeyPaths:      paths,
		Authenticator: auth.NewTokenAuthenticator("bob-token"),
	})

	called := false
	result, genErr := Service{}.GenerateKey(context.Background(), bob, keyType, nil, func(context.Context, *identity.Runtime, string, map[string]string) (string, error) {
		called = true
		return "ADDR", nil
	})
	if result != nil {
		t.Fatalf("GenerateKey(bob) result = %#v, want nil", result)
	}
	if genErr == nil || genErr.Kind != ErrorInvalidInput {
		t.Fatalf("GenerateKey(bob) error = %#v, want ErrorInvalidInput", genErr)
	}
	if called {
		t.Fatal("composed generator was called for key type not enabled for identity")
	}
}

func TestServiceDeleteKeyRemovesKeyAndAudits(t *testing.T) {
	ir := setupIdentityRuntime(t)
	audit := &auditRecorder{}
	svc := Service{AuditLog: audit}

	genResult, genErr := svc.GenerateKey(context.Background(), ir, "ed25519", nil, nil)
	if genErr != nil {
		t.Fatalf("GenerateKey() error = %#v", genErr)
	}
	keyFile, findErr := ir.FindKeyFile(genResult.Address)
	if findErr != nil {
		t.Fatalf("FindKeyFile(%q) before delete error = %v", genResult.Address, findErr)
	}

	delResult, delErr := svc.DeleteKey(ir, genResult.Address)
	if delErr != nil {
		t.Fatalf("DeleteKey() error = %#v", delErr)
	}
	if delResult.DeletedPath == "" {
		t.Fatal("DeleteKey() returned empty deleted path")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("original key file still present after delete: stat err = %v", err)
	}
	if _, err := os.Stat(delResult.DeletedPath); err != nil {
		t.Fatalf("deleted path %q stat error = %v", delResult.DeletedPath, err)
	}
	if _, err := ir.FindKeyFile(genResult.Address); err == nil {
		t.Fatalf("FindKeyFile(%q) after delete succeeded, want stale snapshot cleared", genResult.Address)
	}
	if len(audit.deleted) != 1 {
		t.Fatalf("deleted audit count = %d, want 1", len(audit.deleted))
	}
}

func TestServiceDeleteKeyRemovesAttestorComponentKey(t *testing.T) {
	ir := setupIdentityRuntimeWithRole(t, noderole.RoleSentry)
	svc := Service{}

	genResult, genErr := svc.GenerateKey(context.Background(), ir, keytypes.SentryComponentEd25519V1, nil, nil)
	if genErr != nil {
		t.Fatalf("GenerateKey(component) error = %#v", genErr)
	}
	keyFile, findErr := ir.FindKeyFile(genResult.Address)
	if findErr != nil {
		t.Fatalf("FindKeyFile(%q) before delete error = %v", genResult.Address, findErr)
	}

	delResult, delErr := svc.DeleteKey(ir, genResult.Address)
	if delErr != nil {
		t.Fatalf("DeleteKey(component) error = %#v", delErr)
	}
	if delResult.DeletedPath == "" {
		t.Fatal("DeleteKey(component) returned empty deleted path")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("component key file still present after delete: stat err = %v", err)
	}
	if _, err := os.Stat(delResult.DeletedPath); err != nil {
		t.Fatalf("deleted component key path %q stat error = %v", delResult.DeletedPath, err)
	}
	if _, err := ir.FindKeyFile(genResult.Address); err == nil {
		t.Fatalf("FindKeyFile(%q) after delete succeeded, want stale snapshot cleared", genResult.Address)
	}
}

func TestServiceDeleteKeyValidatesAddressAndNotFound(t *testing.T) {
	ir := setupIdentityRuntime(t)
	svc := Service{}

	if result, err := svc.DeleteKey(ir, "not-an-address"); result != nil || err == nil || err.Kind != ErrorInvalidInput {
		t.Fatalf("DeleteKey(invalid) = (%#v, %#v), want invalid input error", result, err)
	}

	missing := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	if result, err := svc.DeleteKey(ir, missing); result != nil || err == nil || err.Kind != ErrorNotFound {
		t.Fatalf("DeleteKey(missing) = (%#v, %#v), want not found error", result, err)
	}
}

func TestServiceKeyInventoryReportsTemplateProvenanceWarningsOnly(t *testing.T) {
	keyType := "test.keyadmin-provenance-warning.v1"
	lsigprovider.RegisterIfAbsent(keyadminFingerprintProvider{
		keyType:     keyType,
		fingerprint: "live-fingerprint",
	})

	ir := setupIdentityRuntime(t)
	bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
	address := logicSigAddressString(t, bytecode)
	keyJSON, err := json.Marshal(keys.LSigFile{
		FormatVersion:          keys.CurrentKeyFormatVersion,
		Category:               keys.CategoryGenericLsig,
		Address:                address,
		KeyType:                keyType,
		BytecodeHex:            hex.EncodeToString(bytecode),
		SaltCounter:            5,
		SigningMetadataVersion: keys.CurrentSigningMetadataVersion,
		TemplateFingerprint:    "stored-fingerprint",
	})
	if err != nil {
		t.Fatalf("json.Marshal(LSigFile) error = %v", err)
	}
	if err := ir.WithMasterKey(func(mk []byte) error {
		encrypted, encErr := crypto.EncryptWithMasterKey(keyJSON, mk)
		if encErr != nil {
			return encErr
		}
		if err := os.MkdirAll(ir.KeyPaths().KeysDir(ir.ID()), 0o750); err != nil {
			return err
		}
		return os.WriteFile(ir.KeyPaths().KeyFilePath(ir.ID(), address), encrypted, 0o600)
	}); err != nil {
		t.Fatalf("write key file error = %v", err)
	}
	if _, err := ir.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}

	list, svcErr := Service{}.ListKeys(ir)
	if svcErr != nil {
		t.Fatalf("ListKeys() error = %v", svcErr)
	}
	if len(list) != 1 {
		t.Fatalf("ListKeys() len = %d, want 1", len(list))
	}
	if list[0].Address != address || list[0].KeyType != keyType {
		t.Fatalf("ListKeys()[0] = %+v, want address %s key type %s", list[0], address, keyType)
	}
	if list[0].TemplateProvenanceStatus != keys.TemplateProvenanceStatusConflict || list[0].TemplateProvenanceNote == "" {
		t.Fatalf("ListKeys() template provenance = (%q, %q), want conflict note", list[0].TemplateProvenanceStatus, list[0].TemplateProvenanceNote)
	}

	details, svcErr := Service{}.GetKeyDetails(ir, address)
	if svcErr != nil {
		t.Fatalf("GetKeyDetails() error = %v", svcErr)
	}
	if details.TemplateProvenanceStatus != keys.TemplateProvenanceStatusConflict || details.TemplateProvenanceNote == "" {
		t.Fatalf("GetKeyDetails() template provenance = (%q, %q), want conflict note", details.TemplateProvenanceStatus, details.TemplateProvenanceNote)
	}
}

func TestServiceGenerateKeyGenericPassesThroughSuccessAndErrors(t *testing.T) {
	registerServiceGenericTemplate(t)

	ir := setupIdentityRuntime(t)
	installServiceGenericTemplate(t, ir)
	svc := Service{}

	generate := func(_ context.Context, _ *identity.Runtime, keyType string, params map[string]string) (string, error) {
		if keyType != serviceGenericKeyType {
			t.Fatalf("keyType = %q, want %s", keyType, serviceGenericKeyType)
		}
		if params["owner"] != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ" {
			t.Fatalf("params = %#v, want owner", params)
		}
		return "ADDR", nil
	}

	result, err := svc.GenerateKey(context.Background(), ir, serviceGenericKeyType, map[string]string{"owner": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}, generate)
	if err != nil {
		t.Fatalf("GenerateKey(generic) error = %#v", err)
	}
	if result.Address != "ADDR" || result.KeyType != serviceGenericKeyType {
		t.Fatalf("GenerateKey(generic) = %#v, want address ADDR keyType %s", result, serviceGenericKeyType)
	}

	badReq := func(context.Context, *identity.Runtime, string, map[string]string) (string, error) {
		return "", errors.New("boom")
	}
	if result, err := svc.GenerateKey(context.Background(), ir, serviceGenericKeyType, map[string]string{"owner": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}, badReq); result != nil || err == nil || err.Kind != ErrorInternal {
		t.Fatalf("GenerateKey(generic error) = (%#v, %#v), want internal error", result, err)
	}
}

func TestServiceImportKeyFalcon1024V1PersistsKey(t *testing.T) {
	configureFalconCompileMock(t)

	ir := setupIdentityRuntime(t)
	audit := &auditRecorder{}
	svc := Service{AuditLog: audit}
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	result, err := svc.ImportKey(ir, "aplane.falcon1024.v1", mnemonic, nil)
	if err != nil {
		t.Fatalf("ImportKey(aplane.falcon1024.v1) error = %#v", err)
	}
	if result.Address == "" {
		t.Fatal("ImportKey(aplane.falcon1024.v1) returned empty address")
	}
	if result.KeyType != "aplane.falcon1024.v1" {
		t.Fatalf("ImportKey(aplane.falcon1024.v1) keyType = %q, want aplane.falcon1024.v1", result.KeyType)
	}
	if result.KeyFile == "" {
		t.Fatal("ImportKey(aplane.falcon1024.v1) returned empty key file")
	}
	if _, statErr := os.Stat(result.KeyFile); statErr != nil {
		t.Fatalf("imported Falcon key file %q stat error = %v", result.KeyFile, statErr)
	}
	if _, findErr := ir.FindKeyFile(result.Address); findErr != nil {
		t.Fatalf("FindKeyFile(%q) after import error = %v", result.Address, findErr)
	}

	var stored *keymgmt.KeyFileInfo
	if err := ir.WithMasterKey(func(mk []byte) error {
		var detectErr error
		stored, detectErr = keymgmt.DetectKeyInfoFromFileWithMasterKey(result.KeyFile, mk)
		return detectErr
	}); err != nil {
		t.Fatalf("DetectKeyInfoFromFileWithMasterKey() error = %v", err)
	}
	if stored.Type != "aplane.falcon1024.v1" {
		t.Fatalf("stored key type = %q, want aplane.falcon1024.v1", stored.Type)
	}
	if len(audit.imported) != 1 || audit.imported[0].keyType != "aplane.falcon1024.v1" {
		t.Fatalf("import audit = %#v, want one aplane.falcon1024.v1 import", audit.imported)
	}
}

func TestServiceImportKeyRejectsKeyTypeDisallowedByNodeRole(t *testing.T) {
	configureFalconCompileMock(t)

	ir := setupIdentityRuntimeWithRole(t, noderole.RoleSentry)
	svc := Service{}
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	result, err := svc.ImportKey(ir, "aplane.falcon1024.v1", mnemonic, nil)
	if result != nil {
		t.Fatalf("ImportKey(disallowed node role) result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorInvalidInput || !strings.Contains(err.Message, `node role "sentry"`) {
		t.Fatalf("ImportKey(disallowed node role) error = %#v, want node role invalid input", err)
	}
}

func TestServiceImportKeyLockedReturnsLockedError(t *testing.T) {
	ir := setupIdentityRuntime(t)
	ir.Lock()
	svc := Service{}
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	result, err := svc.ImportKey(ir, "aplane.falcon1024.v1", mnemonic, nil)
	if result != nil {
		t.Fatalf("ImportKey(locked) result = %#v, want nil", result)
	}
	if err == nil || err.Kind != ErrorLocked {
		t.Fatalf("ImportKey(locked) error = %#v, want locked error", err)
	}
}

func TestServiceImportKeyCanonicalizesAddressListParams(t *testing.T) {
	registerAddressListImportProvider(t)

	ir := setupIdentityRuntime(t)
	svc := Service{}
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

	addr1 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	addr2 := "AEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEA5RCDXMI"
	canonicalRecipients := addr1 + "," + addr2

	first, err := svc.ImportKey(ir, addressListImportKeyType, mnemonic, map[string]string{
		"recipients": addr1 + "," + addr2,
	})
	if err != nil {
		t.Fatalf("ImportKey(first) error = %#v", err)
	}
	second, err := svc.ImportKey(ir, addressListImportKeyType, mnemonic, map[string]string{
		"recipients": addr2 + "," + addr1,
	})
	if err != nil {
		t.Fatalf("ImportKey(second) error = %#v", err)
	}
	if first.Address != second.Address {
		t.Fatalf("reordered import address = %q, want %q", second.Address, first.Address)
	}

	var storedParams map[string]string
	if err := ir.WithMasterKey(func(mk []byte) error {
		info, detectErr := keymgmt.DetectKeyInfoFromFileWithMasterKey(second.KeyFile, mk)
		if detectErr != nil {
			return detectErr
		}
		storedParams = info.Parameters
		return nil
	}); err != nil {
		t.Fatalf("DetectKeyInfoFromFileWithMasterKey() error = %v", err)
	}
	if storedParams["recipients"] != canonicalRecipients {
		t.Fatalf("stored recipients = %q, want %q", storedParams["recipients"], canonicalRecipients)
	}
}

const (
	addressListImportKeyType = "falcon1024-import-normalize-v1"
	addressListImportFamily  = "falcon1024-import-normalize"
	serviceGenericKeyType    = "test.generic-service-test.v1"
)

func registerServiceGenericTemplate(t *testing.T) {
	t.Helper()
	spec := &generictemplate.TemplateSpec{
		BaseTemplateSpec: templatestore.BaseTemplateSpec{
			Publisher:   "test",
			Family:      "generic-service-test",
			Version:     1,
			DisplayName: "Generic Service Test",
		},
		Parameters: []generictemplate.ParameterSpec{{
			Name:     "owner",
			Type:     "address",
			Required: true,
		}},
		TEAL: "#pragma version 8\nint 1\nreturn",
	}
	if err := generictemplate.ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec(service generic template) error = %v", err)
	}
	genericlsig.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec))
}

func installServiceGenericTemplate(t *testing.T, ir *identity.Runtime) {
	t.Helper()
	if err := ir.WithMasterKey(func(mk []byte) error {
		_, saveErr := templatestore.SaveTemplateForPaths(ir.KeyPaths(), ir.ID(), serviceGenericTemplateYAML(), serviceGenericKeyType, templatestore.TemplateTypeGeneric, mk)
		return saveErr
	}); err != nil {
		t.Fatalf("SaveTemplateForPaths(service generic template) error = %v", err)
	}
	if err := keytypestate.Put(ir.KeyPaths(), ir.ID(), keytypestate.Record{
		KeyType: serviceGenericKeyType,
		Source:  keytypestate.SourceYAMLGeneric,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("keytypestate.Put(service generic template) error = %v", err)
	}
}

func serviceGenericTemplateYAML() []byte {
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: generic-service-test
version: 1
display_name: Generic Service Test
description: Test generic service template
parameters:
  - name: owner
    type: address
    required: true
teal: |
  #pragma version 8
  int 1
  return
`)
}

func configureFalconCompileMock(t *testing.T) {
	t.Helper()
	client, err := algod.MakeClientWithTransport("http://mock-algod", "", nil, falconCompileMockTransport{})
	if err != nil {
		t.Fatalf("MakeClientWithTransport() error = %v", err)
	}
	lsigprovider.ConfigureAlgodClient(client)
}

type falconCompileMockTransport struct{}

func (falconCompileMockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost || req.URL.Path != "/v2/teal/compile" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"message":"unexpected request"}`))),
			Request:    req,
		}, nil
	}
	if _, err := io.ReadAll(req.Body); err != nil {
		return nil, err
	}
	bytecode := []byte{0x0c, 0x26, 0x01, 0x01, 0x00, 0x22}
	body := []byte(`{"result":"` + base64.StdEncoding.EncodeToString(bytecode) + `","hash":"TESTHASH"}`)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func registerAddressListImportProvider(t *testing.T) {
	t.Helper()
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      addressListImportKeyType,
		Family:       addressListImportFamily,
		Availability: keytypecatalog.AvailabilityDefaultEnabled,
	})
	if logicsigdsa.Get(addressListImportKeyType) == nil {
		logicsigdsa.Register(addressListImportProvider{})
	}
	if _, err := internalkeygen.GetGenerator(addressListImportKeyType); err != nil {
		ops := addressListImportProvider{}
		internalkeygen.Register(falconkeygen.NewFalconGenerator(addressListImportFamily, map[string]falconkeygen.LogicSigKeygenOps{
			addressListImportFamily:  ops,
			addressListImportKeyType: ops,
		}))
	}
}

type addressListImportProvider struct{}

func (addressListImportProvider) KeyType() string          { return addressListImportKeyType }
func (addressListImportProvider) Family() string           { return addressListImportFamily }
func (addressListImportProvider) Version() int             { return 1 }
func (addressListImportProvider) CryptoSignatureSize() int { return 0 }
func (addressListImportProvider) MnemonicScheme() string   { return "bip39" }
func (addressListImportProvider) MnemonicWordCount() int   { return 24 }
func (addressListImportProvider) SupportsMnemonicImport() bool {
	return true
}
func (addressListImportProvider) DisplayColor() string { return "" }
func (addressListImportProvider) Category() string     { return lsigprovider.CategoryDSALsig }
func (addressListImportProvider) DisplayName() string  { return "Import Normalize Test" }
func (addressListImportProvider) Description() string  { return "Test provider" }
func (addressListImportProvider) CreationParams() []lsigprovider.ParameterDef {
	return []lsigprovider.ParameterDef{{
		Name:     "recipients",
		Type:     "address[]",
		Required: true,
		MinItems: 1,
	}}
}
func (addressListImportProvider) ValidateCreationParams(map[string]string) error { return nil }
func (addressListImportProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (addressListImportProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (addressListImportProvider) GenerateKeypair([]byte) ([]byte, []byte, error) {
	return []byte("public"), []byte("private"), nil
}
func (addressListImportProvider) DeriveLsig(_ context.Context, _ []byte, params map[string]string) ([]byte, string, error) {
	result, err := addressListImportProvider{}.DeriveLsigWithSalt(context.Background(), nil, params)
	if err != nil {
		return nil, "", err
	}
	return result.Bytecode, result.Address.String(), nil
}
func (addressListImportProvider) DeriveLsigWithSalt(_ context.Context, _ []byte, params map[string]string) (lsigsalt.FindResult, error) {
	sum := sha256.Sum256([]byte(params["recipients"]))
	bytecode := []byte{0x0c, 0x26, 0x01, 0x01, sum[0], 0x81, 0x01}
	result, err := lsigsalt.FindOffCurve(bytecode, lsigsalt.BytecblockLocator)
	if err != nil {
		return lsigsalt.FindResult{}, err
	}
	return result, nil
}
func (addressListImportProvider) Sign([]byte, []byte) ([]byte, error) { return nil, nil }

func logicSigAddressString(t *testing.T, bytecode []byte) string {
	t.Helper()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	address, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address error = %v", err)
	}
	return address.String()
}

type keyadminFingerprintProvider struct {
	keyType     string
	fingerprint string
}

func (p keyadminFingerprintProvider) KeyType() string      { return p.keyType }
func (p keyadminFingerprintProvider) Family() string       { return p.keyType }
func (p keyadminFingerprintProvider) Version() int         { return 1 }
func (p keyadminFingerprintProvider) Category() string     { return lsigprovider.CategoryGenericLsig }
func (p keyadminFingerprintProvider) DisplayName() string  { return p.keyType }
func (p keyadminFingerprintProvider) Description() string  { return "provenance test provider" }
func (p keyadminFingerprintProvider) DisplayColor() string { return "" }
func (p keyadminFingerprintProvider) CreationParams() []lsigprovider.ParameterDef {
	return nil
}
func (p keyadminFingerprintProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (p keyadminFingerprintProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }
func (p keyadminFingerprintProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (p keyadminFingerprintProvider) CompatibilityFingerprint() string { return p.fingerprint }
