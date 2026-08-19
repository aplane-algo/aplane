// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatelibrary

import (
	"bytes"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	sdkcrypto "github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/types"

	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/falcon1024"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

const testIdentityID = "default"

func TestListProjectsLibraryTemplatesAndInstalledStatus(t *testing.T) {
	falcon.RegisterClient()
	paths := newLibraryTestPaths(t)
	writeLibraryFile(t, paths, "generic.yaml", testGenericTemplateYAML("library-generic", "Library Generic"))
	writeLibraryFile(t, paths, "composed.yaml", testComposedTemplateYAML("falcon1024-library", "Composed Library"))
	writeLibraryFile(t, paths, "README.md", []byte("ignored"))

	installed := mustParseYAML(t, "installed.yaml", testGenericTemplateYAML("library-generic", "Library Generic"))
	if _, err := InstallParsed(paths, installed, cryptotest.Keyring(t, testMasterKey())); err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	byKeyType := map[string]LibraryTemplate{}
	for _, item := range items {
		byKeyType[item.KeyType] = item
	}
	if got := byKeyType["test.library-generic.v1"]; !got.Installed || got.Conflict != "" || got.Invalid != "" {
		t.Fatalf("generic status = %+v, want installed only", got)
	}
	composed := byKeyType["test.falcon1024-library.v1"]
	if composed.TemplateType != string(templatestore.TemplateTypeComposed) {
		t.Fatalf("composed TemplateType = %q, want composed", composed.TemplateType)
	}
	if len(composed.Parameters) != 1 || composed.Parameters[0].Name != "recipient" {
		t.Fatalf("composed params = %#v, want recipient param", composed.Parameters)
	}
}

func TestListMarksDuplicateLibraryDeclarationsAsConflict(t *testing.T) {
	paths := newLibraryTestPaths(t)
	writeLibraryFile(t, paths, "one.yaml", testGenericTemplateYAML("duplicate-library", "Duplicate One"))
	writeLibraryFile(t, paths, "two.yaml", testGenericTemplateYAML("duplicate-library", "Duplicate Two"))

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	duplicates := 0
	for _, item := range items {
		if item.KeyType != "test.duplicate-library.v1" {
			continue
		}
		duplicates++
		if item.Conflict == "" || !strings.Contains(item.Conflict, "multiple library files") {
			t.Fatalf("item conflict = %q, want duplicate conflict", item.Conflict)
		}
	}
	if duplicates != 2 {
		t.Fatalf("duplicate item count = %d, want 2", duplicates)
	}
}

func TestParseYAMLRejectsMissingTemplateMode(t *testing.T) {
	_, err := ParseYAML("legacy.yaml", []byte(`schema_version: 1
template_type: generic
publisher: test
family: legacy
version: 1
display_name: Legacy
teal: |
  int 1
`))
	if err == nil {
		t.Fatal("ParseYAML() error = nil, want missing template_mode rejection")
	}
	if !strings.Contains(err.Error(), "template_mode is required") {
		t.Fatalf("ParseYAML() error = %q, want missing template_mode rejection", err.Error())
	}
}

func TestValidateImportableSchemaDefaultsMissingOpcodeCeiling(t *testing.T) {
	err := ValidateImportableSchema([]byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: missing-opcode-ceiling
version: 1
display_name: Missing Opcode Ceiling
teal: |
  int 1
`))
	if err != nil {
		t.Fatalf("ValidateImportableSchema() error = %v, want omitted ceiling accepted", err)
	}
}

func TestValidateImportableSchemaRejectsExplicitZeroOpcodeCeiling(t *testing.T) {
	err := ValidateImportableSchema([]byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: zero-opcode-ceiling
version: 1
display_name: Zero Opcode Ceiling
max_opcode_cost: 0
teal: |
  int 1
`))
	if err == nil || !strings.Contains(err.Error(), "max_opcode_cost must be greater than zero") {
		t.Fatalf("ValidateImportableSchema() error = %v, want explicit-zero rejection", err)
	}
}

func TestInstallComposedSchemaV2BoundedTemplate(t *testing.T) {
	falcon.RegisterClient()
	paths := newLibraryTestPaths(t)
	data := []byte(`schema_version: 2
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: strict
publisher: test
family: bounded-library
version: 1
display_name: Bounded Library
description: Test bounded template
derivation_version: 3
max_opcode_cost: 20000
bounded:
  contract: bounded1
  spend_effects: [pay, axfer]
  max_fee: 2000
  admin_operations: []
teal: |
  int 1
  return
`)
	parsed, err := ParseYAML("bounded.yaml", data)
	if err != nil {
		t.Fatalf("ParseYAML() error = %v", err)
	}
	if parsed.KeyType != "test.bounded-library.v1" || parsed.TemplateType != templatestore.TemplateTypeComposed {
		t.Fatalf("ParseYAML() = %#v", parsed)
	}
	installed, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	stored, err := templatestore.LoadTemplateFromPath(installed.OutputPath, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("LoadTemplateFromPath() error = %v", err)
	}
	reparsed, err := ParseYAML(installed.OutputPath, stored)
	if err != nil {
		t.Fatalf("ParseYAML(stored) error = %v", err)
	}
	if reparsed.KeyType != parsed.KeyType {
		t.Fatalf("stored key type = %q, want %q", reparsed.KeyType, parsed.KeyType)
	}
}

func TestListInvalidPrecedenceSkipsConflictDetection(t *testing.T) {
	paths := newLibraryTestPaths(t)
	writeLibraryFile(t, paths, "invalid.yaml", []byte("not: valid: yaml: ["))

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	var invalid *LibraryTemplate
	for i := range items {
		if items[i].FileName == "invalid.yaml" {
			invalid = &items[i]
			break
		}
	}
	if invalid == nil {
		t.Fatal("invalid.yaml not listed")
		return
	}
	if invalid.Invalid == "" {
		t.Fatal("Invalid is empty, want parse error")
	}
	if invalid.Conflict != "" || invalid.Installed {
		t.Fatalf("invalid item status = %+v, want no conflict/installed", *invalid)
	}
}

func TestListIncludesInstalledTemplateWithoutLibrarySource(t *testing.T) {
	paths := newLibraryTestPaths(t)
	keyType := "falcon1024-installed-only-v2"
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), testComposedTemplateYAML("falcon1024-installed-only", "Installed Only"), keyType, templatestore.TemplateTypeComposed, cryptotest.Keyring(t, testMasterKey())); err != nil {
		t.Fatalf("SaveTemplateActive() error = %v", err)
	}
	writeTemplateStateForTest(t, paths, keyType, templatestore.TemplateTypeComposed, keytypestate.StateDisabled)

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}

	item := findLibraryItem(items, keyType)
	if item == nil {
		t.Fatalf("installed-only template %q not listed", keyType)
		return
	}
	if item.TemplateType != string(templatestore.TemplateTypeComposed) || !item.Installed || item.Enabled {
		t.Fatalf("installed-only item = %+v, want installed disabled composed", *item)
	}
	if item.FileName != keyType+".template" {
		t.Fatalf("installed-only FileName = %q, want template filename", item.FileName)
	}
}

func TestInstallFromLibraryRejectsAmbiguousTemplateRef(t *testing.T) {
	paths := newLibraryTestPaths(t)
	writeLibraryFile(t, paths, "one.yaml", testGenericTemplateYAML("ambiguous-library", "Ambiguous One"))
	writeLibraryFile(t, paths, "two.yaml", testGenericTemplateYAML("ambiguous-library", "Ambiguous Two"))

	_, err := InstallFromLibrary(paths, TemplateRef{
		KeyType:      "test.ambiguous-library.v1",
		TemplateType: templatestore.TemplateTypeGeneric,
	}, cryptotest.Keyring(t, testMasterKey()))
	if err == nil || !strings.Contains(err.Error(), "multiple library files") {
		t.Fatalf("InstallFromLibrary() error = %v, want ambiguity error", err)
	}
}

func TestInstallParsedWritesEncryptedTemplateAndDoesNotUseLibraryDir(t *testing.T) {
	paths := newLibraryTestPaths(t)
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("install-library", "Install Library"))

	result, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	if result.AlreadyExists {
		t.Fatal("InstallParsed().AlreadyExists = true, want false on first install")
	}
	if !strings.Contains(result.OutputPath, filepath.Join("identities", testIdentityID)) ||
		!strings.Contains(result.OutputPath, string(filepath.Separator)+"keytypes"+string(filepath.Separator)) {
		t.Fatalf("OutputPath = %q, want the identity's active key type directory", result.OutputPath)
	}
	if strings.Contains(result.OutputPath, "library/templates") {
		t.Fatalf("OutputPath = %q, must not write into plaintext library", result.OutputPath)
	}
	if _, err := os.Stat(result.OutputPath); err != nil {
		t.Fatalf("installed template stat error = %v", err)
	}

	again, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed(second) error = %v", err)
	}
	if !again.AlreadyExists {
		t.Fatal("InstallParsed(second).AlreadyExists = false, want true")
	}
}

func TestInstallParsedExistingTemplateCanRollbackStateChange(t *testing.T) {
	paths := newLibraryTestPaths(t)
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("install-disabled-existing", "Install Disabled Existing"))

	if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey())); err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	rec, ok, err := keytypestate.Get(paths, parsed.KeyType)
	if err != nil || !ok {
		t.Fatalf("Get(installed state) = (%+v, %v, %v), want record", rec, ok, err)
	}
	rec.State = keytypestate.StateDisabled
	if err := keytypestate.Put(paths, rec); err != nil {
		t.Fatalf("Put(disabled state) error = %v", err)
	}

	again, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed(second) error = %v", err)
	}
	if !again.AlreadyExists {
		t.Fatal("InstallParsed(second).AlreadyExists = false, want true")
	}
	if !again.StateChanged {
		t.Fatal("InstallParsed(second).StateChanged = false, want true")
	}
	if !testKeyTypeEnabled(paths, parsed.KeyType) {
		t.Fatalf("key type %q was not enabled by reinstall", parsed.KeyType)
	}

	if err := RollbackTemplateStateChange(paths, again); err != nil {
		t.Fatalf("RollbackTemplateStateChange() error = %v", err)
	}
	if !testKeyTypeDisabled(paths, parsed.KeyType) {
		t.Fatalf("key type %q = enabled, want disabled restored", parsed.KeyType)
	}
}

func TestInstallParsedRollsBackTemplateWhenStateWriteFails(t *testing.T) {
	paths := newLibraryTestPaths(t)
	parsed := ParsedTemplate{
		TemplateRef: TemplateRef{
			KeyType:      "test.install-rollback.v1",
			TemplateType: templatestore.TemplateTypeGeneric,
		},
		YAMLData: []byte("template_type: generic\nteal: ["),
	}

	_, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err == nil {
		t.Fatal("InstallParsed() error = nil, want fingerprint/state failure")
	}
	templatePath, pathErr := templatestore.GetTemplateFilePathForPaths(paths, parsed.KeyType, parsed.TemplateType)
	if pathErr != nil {
		t.Fatalf("GetTemplateFilePathForPaths() error = %v", pathErr)
	}
	if _, statErr := os.Stat(templatePath); !os.IsNotExist(statErr) {
		t.Fatalf("installed template stat error = %v, want removed rollback file", statErr)
	}
	if _, ok, stateErr := keytypestate.Get(paths, parsed.KeyType); stateErr != nil || ok {
		t.Fatalf("key type state exists=%v err=%v, want rollback to remove state", ok, stateErr)
	}
}

func TestInstallParsedRejectsExistingTemplateDefinitionMismatch(t *testing.T) {
	paths := newLibraryTestPaths(t)
	original := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("install-conflict", "Install Conflict"))
	if _, err := InstallParsed(paths, original, cryptotest.Keyring(t, testMasterKey())); err != nil {
		t.Fatalf("InstallParsed(original) error = %v", err)
	}

	conflictingYAML := []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: install-conflict
version: 1
display_name: "Install Conflict Changed"
description: "changed same-key-type template"
max_opcode_cost: 20000
teal: |
  #pragma version 8
  int 0
`)
	conflicting := mustParseYAML(t, "conflict.yaml", conflictingYAML)
	_, err := InstallParsed(paths, conflicting, cryptotest.Keyring(t, testMasterKey()))
	if err == nil {
		t.Fatal("InstallParsed(conflicting) error = nil, want template conflict")
	}
	if !strings.Contains(err.Error(), "installed template does not match incoming definition") {
		t.Fatalf("InstallParsed(conflicting) error = %v, want mismatch context", err)
	}
}

func TestInstallParsedRejectsOtherTemplateTypeAndBuiltInConflicts(t *testing.T) {
	t.Run("other template type", func(t *testing.T) {
		falcon.RegisterClient()
		paths := newLibraryTestPaths(t)
		generic := mustParseYAML(t, "generic.yaml", testGenericTemplateYAML("cross-type", "Cross Type"))
		if _, err := InstallParsed(paths, generic, cryptotest.Keyring(t, testMasterKey())); err != nil {
			t.Fatalf("InstallParsed(generic) error = %v", err)
		}
		composed := mustParseYAML(t, "composed.yaml", testComposedTemplateYAML("cross-type", "Cross Type Composed"))
		_, err := InstallParsed(paths, composed, cryptotest.Keyring(t, testMasterKey()))
		if err == nil || !strings.Contains(err.Error(), "already exists as a generic template") {
			t.Fatalf("InstallParsed(composed) error = %v, want other-type conflict", err)
		}
	})

	t.Run("registered provider", func(t *testing.T) {
		keyType := "test.templatelibrary-built-in-conflict.v1"
		lsigprovider.Register(stubProvider{keyType: keyType})
		t.Cleanup(func() { lsigprovider.Unregister(keyType) })

		paths := newLibraryTestPaths(t)
		parsed := mustParseYAML(t, "conflict.yaml", testGenericTemplateYAML("templatelibrary-built-in-conflict", "Built In Conflict"))
		_, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
		if err == nil || !strings.Contains(err.Error(), "built-in provider") {
			t.Fatalf("InstallParsed() error = %v, want built-in conflict", err)
		}
	})
}

func TestInstallParsedAllowsGloballyRegisteredMatchingTemplate(t *testing.T) {
	paths := newLibraryTestPaths(t)
	yamlData := testGenericTemplateYAML("templatelibrary-matching-global", "Matching Global")
	writeLibraryFile(t, paths, "matching.yaml", yamlData)
	parsed := mustParseYAML(t, "matching.yaml", yamlData)

	spec, err := generictemplate.ParseTemplateSpec(yamlData)
	if err != nil {
		t.Fatalf("ParseTemplateSpec() error = %v", err)
	}
	if !lsigprovider.RegisterIfAbsent(generictemplate.NewYAMLTemplate(spec)) {
		t.Fatalf("provider %q already registered", parsed.KeyType)
	}
	t.Cleanup(func() { lsigprovider.Unregister(parsed.KeyType) })

	result, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v, want matching global provider to be allowed", err)
	}
	if result.AlreadyExists {
		t.Fatal("InstallParsed().AlreadyExists = true, want fresh install")
	}

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	var matching *LibraryTemplate
	for i := range items {
		if items[i].KeyType == parsed.KeyType {
			matching = &items[i]
			break
		}
	}
	if matching == nil {
		t.Fatalf("List() missing %s", parsed.KeyType)
		return
	}
	if matching.Conflict != "" || !matching.Installed {
		t.Fatalf("List() status = %+v, want installed without global-provider conflict", *matching)
	}
}

func TestListAndActivateCompiledProvider(t *testing.T) {
	keyType := "compiled-library-test-v1"
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      keyType,
		Family:       "compiled-library-test",
		Availability: keytypecatalog.AvailabilityLibrary,
	})
	if !lsigprovider.Has(keyType) {
		lsigprovider.Register(stubProvider{keyType: keyType})
		t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	}

	paths := newLibraryTestPaths(t)
	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	item := findLibraryItem(items, keyType)
	if item == nil {
		t.Fatalf("List() missing compiled provider %s", keyType)
		return
	}
	if item.TemplateType != TemplateTypeCompiledProvider {
		t.Fatalf("TemplateType = %q, want %q", item.TemplateType, TemplateTypeCompiledProvider)
	}
	if item.Installed {
		t.Fatal("compiled provider starts installed")
	}

	result, err := ActivateCompiledProvider(paths, keyType)
	if err != nil {
		t.Fatalf("ActivateCompiledProvider() error = %v", err)
	}
	if result.AlreadyExists {
		t.Fatal("ActivateCompiledProvider().AlreadyExists = true, want false")
	}
	if !testKeyTypeEnabled(paths, keyType) {
		t.Fatal("enabled state was not written")
	}
	if rec, ok, err := keytypestate.Get(paths, keyType); err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	} else if !ok || rec.Source != keytypestate.SourceCompiled {
		t.Fatalf("compiled provider state = %#v, exists=%v; want SourceCompiled", rec, ok)
	}

	items, err = List(paths)
	if err != nil {
		t.Fatalf("List(after activate) error = %v", err)
	}
	item = findLibraryItem(items, keyType)
	if item == nil || !item.Installed {
		t.Fatalf("compiled provider after activation = %+v, want installed", item)
	}

	removed, err := DeactivateCompiledProvider(paths, keyType, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("DeactivateCompiledProvider() error = %v", err)
	}
	if !removed.Removed {
		t.Fatal("DeactivateCompiledProvider().Removed = false, want true")
	}
	if testKeyTypeEnabled(paths, keyType) {
		t.Fatal("enabled state still exists after deactivate")
	}

	items, err = List(paths)
	if err != nil {
		t.Fatalf("List(after deactivate) error = %v", err)
	}
	item = findLibraryItem(items, keyType)
	if item == nil || item.Installed {
		t.Fatalf("compiled provider after deactivation = %+v, want not installed", item)
	}
}

func TestDeactivateCompiledProviderRejectsKeyTypeInUse(t *testing.T) {
	keyType := "compiled-library-in-use-v1"
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      keyType,
		Family:       "compiled-library-in-use",
		Availability: keytypecatalog.AvailabilityLibrary,
	})
	if !lsigprovider.Has(keyType) {
		lsigprovider.Register(stubProvider{keyType: keyType})
		t.Cleanup(func() { lsigprovider.Unregister(keyType) })
	}

	paths := newLibraryTestPaths(t)
	masterKey := testMasterKey()
	if _, err := ActivateCompiledProvider(paths, keyType); err != nil {
		t.Fatalf("ActivateCompiledProvider() error = %v", err)
	}
	bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
	payload := apkeys.NewDSALSigPayload(keyType, keyType, []byte{0x01}, []byte{0x02}, nil, bytecode, 5, "", nil, "")
	if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
		t.Fatal(err)
	}
	defer payload.ZeroSecrets()
	if _, err := apkeys.SavePayload(paths, payload, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}

	_, err := DeactivateCompiledProvider(paths, keyType, cryptotest.Keyring(t, masterKey))
	if err == nil {
		t.Fatal("DeactivateCompiledProvider() error = nil, want in-use rejection")
	}
	if !strings.Contains(err.Error(), "key(s) still use it") {
		t.Fatalf("DeactivateCompiledProvider() error = %v, want in-use context", err)
	}
	if !testKeyTypeEnabled(paths, keyType) {
		t.Fatal("enabled state was removed despite in-use rejection")
	}
}

func TestRemoveInstalledTemplateMovesUnusedTemplateToDeletedArchive(t *testing.T) {
	paths := newLibraryTestPaths(t)
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("remove-unused", "Remove Unused"))

	installed, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}

	removed, err := RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("RemoveInstalledTemplate() error = %v", err)
	}
	if !removed.Removed {
		t.Fatal("RemoveInstalledTemplate().Removed = false, want true")
	}
	wantArchive := paths.DeletedKeyTypeTemplate(parsed.KeyType)
	if removed.OutputPath != wantArchive {
		t.Fatalf("RemoveInstalledTemplate().OutputPath = %q, want %q", removed.OutputPath, wantArchive)
	}
	if _, err := os.Stat(installed.OutputPath); !os.IsNotExist(err) {
		t.Fatalf("template still exists after removal, stat err=%v", err)
	}
	if _, err := os.Stat(removed.OutputPath); err != nil {
		t.Fatalf("archived template missing after removal: %v", err)
	}
	if _, err := os.Stat(paths.DeletedKeysDir()); err != nil {
		t.Fatalf("deleted keys dir missing after template removal: %v", err)
	}

	again, err := RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("RemoveInstalledTemplate(second) error = %v", err)
	}
	if again.Removed {
		t.Fatal("RemoveInstalledTemplate(second).Removed = true, want idempotent false")
	}
}

func TestRemoveInstalledTemplateRestoresStateWhenArchiveFails(t *testing.T) {
	paths := newLibraryTestPaths(t)
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("remove-archive-fails", "Remove Archive Fails"))

	installed, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey()))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	blockingPath := filepath.Join(paths.DeletedDir(), "keytypes")
	if err := os.MkdirAll(filepath.Dir(blockingPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(blockingPath, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile(blocking archive dir) error = %v", err)
	}

	_, err = RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, testMasterKey()))
	if err == nil {
		t.Fatal("RemoveInstalledTemplate() error = nil, want archive failure")
	}
	if !testKeyTypeEnabled(paths, parsed.KeyType) {
		t.Fatalf("key type state for %q was not restored", parsed.KeyType)
	}
	if _, statErr := os.Stat(installed.OutputPath); statErr != nil {
		t.Fatalf("installed template stat error = %v, want source template preserved", statErr)
	}
}

func TestDisableAndEnableInstalledTemplateKeepsTemplateFile(t *testing.T) {
	paths := newLibraryTestPaths(t)
	masterKey := testMasterKey()
	yamlData := testGenericTemplateYAML("disable-template", "Disable Template")
	writeLibraryFile(t, paths, "disable-template.yaml", yamlData)
	parsed := mustParseYAML(t, "source.yaml", yamlData)

	installed, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}

	disabled, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("DisableInstalledTemplate() error = %v", err)
	}
	if !disabled.Removed {
		t.Fatal("DisableInstalledTemplate().Removed = false, want true for first disable")
	}
	if _, err := os.Stat(installed.OutputPath); err != nil {
		t.Fatalf("template file missing after disable: %v", err)
	}
	if !testKeyTypeDisabled(paths, parsed.KeyType) {
		t.Fatal("disabled state was not written")
	}

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List(disabled) error = %v", err)
	}
	item := findLibraryItem(items, parsed.KeyType)
	if item == nil || !item.Installed || item.Enabled {
		t.Fatalf("disabled template list item = %+v, want installed but not enabled", item)
	}

	enabled, err := EnableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType)
	if err != nil {
		t.Fatalf("EnableInstalledTemplate() error = %v", err)
	}
	if enabled.AlreadyExists {
		t.Fatal("EnableInstalledTemplate().AlreadyExists = true, want false after state change")
	}
	if testKeyTypeDisabled(paths, parsed.KeyType) {
		t.Fatal("disabled state still exists after enable")
	}
}

func TestRemoveInstalledTemplateClearsDisabledMarker(t *testing.T) {
	paths := newLibraryTestPaths(t)
	masterKey := testMasterKey()
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("remove-disabled", "Remove Disabled"))

	if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	if _, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("DisableInstalledTemplate() error = %v", err)
	}
	if !testKeyTypeDisabled(paths, parsed.KeyType) {
		t.Fatal("disabled state was not written")
	}

	removed, err := RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RemoveInstalledTemplate() error = %v", err)
	}
	if !removed.Removed {
		t.Fatal("RemoveInstalledTemplate().Removed = false, want true")
	}
	if testKeyTypeDisabled(paths, parsed.KeyType) {
		t.Fatal("disabled state still exists after template removal")
	}
	if templatestore.TemplateExistsForPaths(paths, parsed.KeyType, parsed.TemplateType) {
		t.Fatal("template still exists after removal")
	}
}

func TestRemoveInstalledTemplateRejectsKeyTypeInUse(t *testing.T) {
	paths := newLibraryTestPaths(t)
	masterKey := testMasterKey()
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("remove-in-use", "Remove In Use"))

	installed, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	writeTemplateKeyInUse(t, paths, parsed.KeyType, masterKey)

	_, err = RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey))
	if err == nil {
		t.Fatal("RemoveInstalledTemplate() error = nil, want in-use rejection")
	}
	if !strings.Contains(err.Error(), "key(s) still use it") {
		t.Fatalf("RemoveInstalledTemplate() error = %v, want in-use context", err)
	}
	if _, err := os.Stat(installed.OutputPath); err != nil {
		t.Fatalf("template was removed despite in-use rejection: %v", err)
	}
}

func TestDisableInstalledTemplateRejectsKeyTypeInUse(t *testing.T) {
	paths := newLibraryTestPaths(t)
	masterKey := testMasterKey()
	parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML("disable-in-use", "Disable In Use"))

	if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	writeTemplateKeyInUse(t, paths, parsed.KeyType, masterKey)

	_, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey))
	if err == nil {
		t.Fatal("DisableInstalledTemplate() error = nil, want in-use rejection")
	}
	if !strings.Contains(err.Error(), "key(s) still use it") {
		t.Fatalf("DisableInstalledTemplate() error = %v, want in-use context", err)
	}
	if !testKeyTypeEnabled(paths, parsed.KeyType) {
		t.Fatal("enabled state was removed despite in-use rejection")
	}
	if !templatestore.TemplateExistsForPaths(paths, parsed.KeyType, parsed.TemplateType) {
		t.Fatal("template file was removed by disable")
	}
}

func TestInstalledTemplateLifecycleMatrix(t *testing.T) {
	type wantProjection struct {
		templateExists bool
		archiveExists  bool
		state          keytypestate.State
		stateExists    bool
		libraryItem    bool
		installed      bool
		enabled        bool
	}

	tests := []struct {
		name string
		run  func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte)
		want wantProjection
	}{
		{
			name: "install creates enabled identity-local state",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
			},
			want: wantProjection{
				templateExists: true,
				stateExists:    true,
				state:          keytypestate.StateEnabled,
				libraryItem:    true,
				installed:      true,
				enabled:        true,
			},
		},
		{
			name: "disable keeps template but hides enabled projection",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
				if _, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("DisableInstalledTemplate() error = %v", err)
				}
			},
			want: wantProjection{
				templateExists: true,
				stateExists:    true,
				state:          keytypestate.StateDisabled,
				libraryItem:    true,
				installed:      true,
				enabled:        false,
			},
		},
		{
			name: "enable restores enabled projection",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
				if _, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("DisableInstalledTemplate() error = %v", err)
				}
				if _, err := EnableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType); err != nil {
					t.Fatalf("EnableInstalledTemplate() error = %v", err)
				}
			},
			want: wantProjection{
				templateExists: true,
				stateExists:    true,
				state:          keytypestate.StateEnabled,
				libraryItem:    true,
				installed:      true,
				enabled:        true,
			},
		},
		{
			name: "remove enabled archives template and clears state",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
				if _, err := RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("RemoveInstalledTemplate() error = %v", err)
				}
			},
			want: wantProjection{
				archiveExists: true,
			},
		},
		{
			name: "remove disabled archives template and clears state",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
				if _, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("DisableInstalledTemplate() error = %v", err)
				}
				if _, err := RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("RemoveInstalledTemplate() error = %v", err)
				}
			},
			want: wantProjection{
				archiveExists: true,
			},
		},
		{
			name: "disable in use rejects without mutating file or state",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
				writeTemplateKeyInUse(t, paths, parsed.KeyType, masterKey)
				if _, err := DisableInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err == nil {
					t.Fatal("DisableInstalledTemplate() error = nil, want in-use rejection")
				}
			},
			want: wantProjection{
				templateExists: true,
				stateExists:    true,
				state:          keytypestate.StateEnabled,
				libraryItem:    true,
				installed:      true,
				enabled:        true,
			},
		},
		{
			name: "remove in use rejects without mutating file or state",
			run: func(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, masterKey []byte) {
				t.Helper()
				if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, masterKey)); err != nil {
					t.Fatalf("InstallParsed() error = %v", err)
				}
				writeTemplateKeyInUse(t, paths, parsed.KeyType, masterKey)
				if _, err := RemoveInstalledTemplate(paths, parsed.KeyType, parsed.TemplateType, cryptotest.Keyring(t, masterKey)); err == nil {
					t.Fatal("RemoveInstalledTemplate() error = nil, want in-use rejection")
				}
			},
			want: wantProjection{
				templateExists: true,
				stateExists:    true,
				state:          keytypestate.StateEnabled,
				libraryItem:    true,
				installed:      true,
				enabled:        true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := newLibraryTestPaths(t)
			masterKey := testMasterKey()
			family := "lifecycle-" + strings.ReplaceAll(tt.name, " ", "-")
			parsed := mustParseYAML(t, "source.yaml", testGenericTemplateYAML(family, "Lifecycle Matrix"))

			tt.run(t, paths, parsed, masterKey)

			assertInstalledTemplateProjection(t, paths, parsed, tt.want)
		})
	}
}

func TestParseFileAsRejectsMismatchedDeclaredTemplateType(t *testing.T) {
	falcon.RegisterClient()
	paths := newLibraryTestPaths(t)
	path := writeLibraryFile(t, paths, "composed.yaml", testComposedTemplateYAML("parse-mismatch", "Parse Mismatch"))

	_, err := ParseFileAs(path, templatestore.TemplateTypeGeneric)
	if err == nil || !strings.Contains(err.Error(), "does not match requested type") {
		t.Fatalf("ParseFileAs() error = %v, want mismatch error", err)
	}
}

func newLibraryTestPaths(t *testing.T) storepaths.Paths {
	t.Helper()
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths)
	if err := EnsureLibraryDir(paths); err != nil {
		t.Fatalf("EnsureLibraryDir() error = %v", err)
	}
	return paths
}

func writeLibraryFile(t *testing.T, paths storepaths.Paths, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(paths.TemplateLibraryDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write library file: %v", err)
	}
	return path
}

func mustParseYAML(t *testing.T, path string, data []byte) ParsedTemplate {
	t.Helper()
	parsed, err := ParseYAML(path, data)
	if err != nil {
		t.Fatalf("ParseYAML() error = %v", err)
	}
	return parsed
}

func findLibraryItem(items []LibraryTemplate, keyType string) *LibraryTemplate {
	for i := range items {
		if items[i].KeyType == keyType {
			return &items[i]
		}
	}
	return nil
}

func testKeyTypeEnabled(paths storepaths.Paths, keyType string) bool {
	rec, ok, err := keytypestate.Get(paths, keyType)
	return err == nil && ok && rec.State == keytypestate.StateEnabled
}

func writeTemplateStateForTest(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, state keytypestate.State) {
	t.Helper()
	source, err := stateSourceForTemplateType(templateType)
	if err != nil {
		t.Fatalf("stateSourceForTemplateType() error = %v", err)
	}
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  source,
		State:   state,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

func testKeyTypeDisabled(paths storepaths.Paths, keyType string) bool {
	rec, ok, err := keytypestate.Get(paths, keyType)
	return err == nil && ok && rec.State == keytypestate.StateDisabled
}

func writeTemplateKeyInUse(t *testing.T, paths storepaths.Paths, keyType string, masterKey []byte) {
	t.Helper()
	bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
	address := logicSigAddressForTemplateTest(t, bytecode)
	payload := apkeys.NewGenericLSigPayload(keyType, map[string]string{"recipient": address}, bytecode, 5, "", nil, "")
	if err := payload.SetLogicSigOpcodeProfile(lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling), false); err != nil {
		t.Fatal(err)
	}
	if _, err := apkeys.SavePayload(paths, payload, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}
}

func logicSigAddressForTemplateTest(t *testing.T, bytecode []byte) string {
	t.Helper()
	lsig := sdkcrypto.LogicSigAccount{Lsig: types.LogicSig{Logic: bytecode}}
	addr, err := lsig.Address()
	if err != nil {
		t.Fatalf("LogicSig address error = %v", err)
	}
	return addr.String()
}

func assertInstalledTemplateProjection(t *testing.T, paths storepaths.Paths, parsed ParsedTemplate, want struct {
	templateExists bool
	archiveExists  bool
	state          keytypestate.State
	stateExists    bool
	libraryItem    bool
	installed      bool
	enabled        bool
}) {
	t.Helper()
	if got := templatestore.TemplateExistsForPaths(paths, parsed.KeyType, parsed.TemplateType); got != want.templateExists {
		t.Fatalf("template exists = %v, want %v", got, want.templateExists)
	}
	if _, err := os.Stat(paths.DeletedKeyTypeTemplate(parsed.KeyType)); (err == nil) != want.archiveExists {
		t.Fatalf("archive exists = %v, want %v (stat err=%v)", err == nil, want.archiveExists, err)
	}

	rec, ok, err := keytypestate.Get(paths, parsed.KeyType)
	if err != nil {
		t.Fatalf("Get(state) error = %v", err)
	}
	if ok != want.stateExists {
		t.Fatalf("state exists = %v, want %v", ok, want.stateExists)
	}
	if ok && rec.State != want.state {
		t.Fatalf("state = %q, want %q", rec.State, want.state)
	}

	items, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	item := findLibraryItem(items, parsed.KeyType)
	if (item != nil) != want.libraryItem {
		t.Fatalf("library item exists = %v, want %v", item != nil, want.libraryItem)
	}
	if item != nil && (item.Installed != want.installed || item.Enabled != want.enabled) {
		t.Fatalf("library projection = installed %v enabled %v, want installed %v enabled %v", item.Installed, item.Enabled, want.installed, want.enabled)
	}
}

func testMasterKey() []byte {
	return bytes.Repeat([]byte{7}, 32)
}

func testGenericTemplateYAML(family, displayName string) []byte {
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "` + displayName + `"
description: "Test generic template"
max_opcode_cost: 20000
parameters:
  - name: recipient
    label: "Recipient"
    type: address
    required: true
teal: |
  #pragma version 10
  txn Receiver
  addr @recipient
  ==
  return
`)
}

func testComposedTemplateYAML(family, displayName string) []byte {
	return []byte(`schema_version: 1
template_type: composed
base_key_type: aplane.falcon1024.v1
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "` + displayName + `"
description: "Test composed template"
max_opcode_cost: 20000
parameters:
  - name: recipient
    label: "Recipient"
    type: address
    required: true
teal: |
  txn Receiver
  addr @recipient
  ==
  assert
`)
}

type stubProvider struct {
	keyType string
}

func (s stubProvider) KeyType() string                             { return s.keyType }
func (s stubProvider) RoutingFamily() string                       { return strings.TrimSuffix(s.keyType, "-v1") }
func (s stubProvider) Version() int                                { return 1 }
func (s stubProvider) DisplayName() string                         { return s.keyType }
func (s stubProvider) Description() string                         { return "" }
func (s stubProvider) DisplayColor() string                        { return "" }
func (s stubProvider) Category() string                            { return lsigprovider.CategoryGenericLsig }
func (s stubProvider) CreationParams() []lsigprovider.ParameterDef { return nil }
func (s stubProvider) ValidateCreationParams(map[string]string) error {
	return nil
}
func (s stubProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef { return nil }
func (s stubProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (s stubProvider) SetAlgodClient(*algod.Client) {}
