// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatestore

import (
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigresource"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

// testMasterKey is a 32-byte key for testing
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

func TestValidateBaseKeyType(t *testing.T) {
	tests := []struct {
		name        string
		templateTyp TemplateType
		baseKeyType string
		wantErr     string
	}{
		{
			name:        "generic without base",
			templateTyp: TemplateTypeGeneric,
		},
		{
			name:        "generic with base",
			templateTyp: TemplateTypeGeneric,
			baseKeyType: "aplane.falcon1024.v1",
			wantErr:     "base_key_type must not be set for generic templates",
		},
		{
			name:        "composed with base",
			templateTyp: TemplateTypeComposed,
			baseKeyType: "aplane.falcon1024.v1",
		},
		{
			name:        "composed without base",
			templateTyp: TemplateTypeComposed,
			wantErr:     "base_key_type is required for composed templates",
		},
		{
			name:        "unknown template type",
			templateTyp: "custom",
			wantErr:     `unsupported template_type "custom"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBaseKeyType(tt.templateTyp, tt.baseKeyType)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateBaseKeyType() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateBaseKeyType() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestActiveTemplateTypes(t *testing.T) {
	got := ActiveTemplateTypes()
	want := []TemplateType{TemplateTypeGeneric, TemplateTypeComposed}
	if len(got) != len(want) {
		t.Fatalf("ActiveTemplateTypes() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ActiveTemplateTypes()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSaveAndLoadTemplate(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "templatestore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	paths := utilkeys.NewPaths(tmpDir)
	paths = genstoretest.MintFirst(t, paths)

	yamlData := []byte(`
schema_version: 1
family: test-template
version: 1
display_name: "Test Template"
description: "A test template"
teal: |
  #pragma version 10
  int 1
`)

	keyType := "test.test-template.v1"

	// Save template
	outputPath, err := SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, TemplateTypeGeneric, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("Template file was not created at %s", outputPath)
	}
	assertTemplateFileMode(t, outputPath, fsutil.StoreFilePerm)
	assertTemplateDirMode(t, filepath.Dir(outputPath))

	// Load template back
	templatePath, pathErr := GetTemplateFilePathForPaths(paths, keyType, TemplateTypeGeneric)
	if pathErr != nil {
		t.Fatalf("GetTemplateFilePathForPaths() error = %v", pathErr)
	}
	loadedData, err := LoadTemplateFromPath(templatePath, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("LoadTemplateFromPath failed: %v", err)
	}

	// Verify content matches
	if string(loadedData) != string(yamlData) {
		t.Errorf("Loaded data doesn't match original.\nExpected: %s\nGot: %s", yamlData, loadedData)
	}
}

func TestSaveAndLoadComposedTemplate(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "templatestore-composed-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	paths := utilkeys.NewPaths(tmpDir)
	paths = genstoretest.MintFirst(t, paths)

	yamlData := []byte(`
schema_version: 1
family: falcon1024-test
version: 1
display_name: "Falcon Test"
description: "A test falcon template"
parameters:
  - name: hash
    type: bytes
    required: true
    max_length: 64
    label: "Hash"
teal: |
  txn RekeyTo
  global ZeroAddress
  ==
  assert
  arg 1
  sha256
  byte @hash
  ==
  assert
`)

	keyType := "test.falcon1024-test.v1"

	// Save template
	outputPath, err := SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, TemplateTypeComposed, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	// Verify file was created in the product-store key type records directory.
	expectedDir := mustActiveTS(t, paths).KeyTypeRecordsDir()
	if !strings.HasPrefix(outputPath, expectedDir) {
		t.Errorf("Template saved to wrong directory. Expected prefix %s, got %s", expectedDir, outputPath)
	}

	// Load template back
	templatePath, pathErr := GetTemplateFilePathForPaths(paths, keyType, TemplateTypeComposed)
	if pathErr != nil {
		t.Fatalf("GetTemplateFilePathForPaths() error = %v", pathErr)
	}
	loadedData, err := LoadTemplateFromPath(templatePath, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("LoadTemplateFromPath failed: %v", err)
	}

	// Verify content matches
	if string(loadedData) != string(yamlData) {
		t.Errorf("Loaded data doesn't match original")
	}
}

func assertTemplateFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode() & os.ModePerm; got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}

func assertTemplateDirMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", path)
	}
	if got := info.Mode() & os.ModePerm; got != 0o700 {
		t.Fatalf("mode(%s) = %o, want 0700", path, got)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		t.Fatalf("mode(%s) unexpectedly has setgid bit: %v", path, info.Mode())
	}
}

func TestTemplateExists(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "templatestore-exists-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Set keystore path
	paths := utilkeys.NewPaths(tmpDir)
	paths = genstoretest.MintFirst(t, paths)

	keyType := "test.exists-test.v1"

	// Should not exist initially
	if TemplateExistsForPaths(paths, keyType, TemplateTypeGeneric) {
		t.Error("Template should not exist before saving")
	}

	// Save template
	yamlData := []byte("test: data")
	_, err = SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, TemplateTypeGeneric, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	if TemplateExistsForPaths(paths, keyType, TemplateTypeGeneric) {
		t.Error("Template should not exist before key type state is written")
	}
	markTemplateState(t, paths, keyType, TemplateTypeGeneric, keytypestate.StateEnabled)

	// Should exist now
	if !TemplateExistsForPaths(paths, keyType, TemplateTypeGeneric) {
		t.Error("Template should exist after saving and state write")
	}

	// Should not exist in composed directory
	if TemplateExistsForPaths(paths, keyType, TemplateTypeComposed) {
		t.Error("Template should not exist in composed directory")
	}
}

func TestTemplateStoreRejectsUnknownTemplateType(t *testing.T) {
	paths := utilkeys.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	keyType := "test.unknown-template-type.v1"
	unknownType := TemplateType("compiled_provider")

	if _, err := SaveTemplateActive(genstoretest.Active(t, paths), []byte("test: data"), keyType, unknownType, cryptotest.Keyring(t, testMasterKey)); err == nil {
		t.Fatal("SaveTemplateActive() error = nil, want unsupported template_type")
	}
	if TemplateExistsForPaths(paths, keyType, unknownType) {
		t.Fatal("TemplateExistsForPaths() = true for unsupported template_type")
	}
	if _, err := ScanTemplateDirectoryForPaths(paths, unknownType); err == nil {
		t.Fatal("ScanTemplateDirectoryForPaths() error = nil, want unsupported template_type")
	}
	if _, err := LoadAllTemplatesForPaths(paths, unknownType, cryptotest.Keyring(t, testMasterKey)); err == nil {
		t.Fatal("LoadAllTemplatesForPaths() error = nil, want unsupported template_type")
	}
	if _, ok, err := keytypestate.Get(paths, keyType); err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	} else if ok {
		t.Fatal("SaveTemplateActive() wrote state for unsupported template_type")
	}
}

func TestLoadAllTemplates(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "templatestore-loadall-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Set keystore path
	paths := utilkeys.NewPaths(tmpDir)
	paths = genstoretest.MintFirst(t, paths)

	// Save multiple templates
	templates := map[string][]byte{
		"test.template-a.v1": []byte("template A"),
		"test.template-b.v1": []byte("template B"),
		"test.template-c.v1": []byte("template C"),
	}

	for keyType, data := range templates {
		_, err := SaveTemplateActive(genstoretest.Active(t, paths), data, keyType, TemplateTypeGeneric, cryptotest.Keyring(t, testMasterKey))
		if err != nil {
			t.Fatalf("SaveTemplate failed for %s: %v", keyType, err)
		}
		markTemplateState(t, paths, keyType, TemplateTypeGeneric, keytypestate.StateEnabled)
	}

	// Load all templates
	loaded, err := LoadAllTemplatesForPaths(paths, TemplateTypeGeneric, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("LoadAllTemplates failed: %v", err)
	}

	if len(loaded) != len(templates) {
		t.Errorf("Expected %d templates, got %d", len(templates), len(loaded))
	}

	for keyType, expectedData := range templates {
		loadedData, ok := loaded[keyType]
		if !ok {
			t.Errorf("Template %s not found in loaded templates", keyType)
			continue
		}
		if string(loadedData) != string(expectedData) {
			t.Errorf("Template %s data mismatch", keyType)
		}
	}
}

func TestBaseTemplateSpec_KeyType(t *testing.T) {
	spec := BaseTemplateSpec{
		Publisher: "APlane",
		Family:    "My-Template",
		Version:   3,
	}

	expected := "aplane.my-template.v3"
	if spec.KeyType() != expected {
		t.Errorf("Expected %s, got %s", expected, spec.KeyType())
	}
}

func markTemplateState(t *testing.T, paths utilkeys.Paths, keyType string, templateType TemplateType, state keytypestate.State) {
	t.Helper()
	source, ok := sourceForTemplateType(templateType)
	if !ok {
		t.Fatalf("unsupported template type in test: %q", templateType)
	}
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  source,
		State:   state,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

func TestBaseTemplateSpec_ValidateBase(t *testing.T) {
	derivationVersion1 := DerivationVersionPushbytes
	derivationVersion2 := DerivationVersionTrailingBytecblock
	derivationVersion3 := DerivationVersionAlgodAutoSalt
	derivationVersion99 := 99
	tests := []struct {
		name    string
		spec    BaseTemplateSpec
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid spec",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: false,
		},
		{
			name: "retired derivation version 1",
			spec: BaseTemplateSpec{
				SchemaVersion:     1,
				DerivationVersion: &derivationVersion1,
				Publisher:         "test",
				Family:            "test",
				Version:           1,
				DisplayName:       "Test",
			},
			wantErr: true,
			errMsg:  "derivation_version 1 is retired",
		},
		{
			name: "retired derivation version 2",
			spec: BaseTemplateSpec{
				SchemaVersion:     1,
				DerivationVersion: &derivationVersion2,
				Publisher:         "test",
				Family:            "test",
				Version:           1,
				DisplayName:       "Test",
			},
			wantErr: true,
			errMsg:  "derivation_version 2 is retired",
		},
		{
			name: "supported derivation version 3",
			spec: BaseTemplateSpec{
				SchemaVersion:     1,
				DerivationVersion: &derivationVersion3,
				Publisher:         "test",
				Family:            "test",
				Version:           1,
				DisplayName:       "Test",
			},
			wantErr: false,
		},
		{
			name: "unsupported derivation version",
			spec: BaseTemplateSpec{
				SchemaVersion:     1,
				DerivationVersion: &derivationVersion99,
				Publisher:         "test",
				Family:            "test",
				Version:           1,
				DisplayName:       "Test",
			},
			wantErr: true,
			errMsg:  "derivation_version 99 is not supported",
		},
		{
			name: "opcode ceiling above group maximum",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
				MaxOpcodeCost: testUint64Ptr(lsigresource.MaximumDeclaredOpcodeCost + 1),
			},
			wantErr: true,
			errMsg:  "max_opcode_cost",
		},
		{
			name: "missing family",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "family is required",
		},
		{
			name: "invalid version",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       0,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "version must be >= 1",
		},
		{
			name: "missing display name",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
			},
			wantErr: true,
			errMsg:  "display_name is required",
		},
		{
			name: "schema version too new",
			spec: BaseTemplateSpec{
				SchemaVersion: 99,
				Publisher:     "test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "schema_version 99 is newer than supported",
		},
		{
			name: "missing publisher",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "publisher is required",
		},
		{
			name: "unsafe publisher",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "../test",
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "publisher contains unsafe characters",
		},
		{
			name: "unsafe family",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "test",
				Family:        "bad..test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "family contains unsafe characters",
		},
		{
			name: "family with single dot rejected",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "aplane",
				Family:        "white.list",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "family contains unsafe characters",
		},
		{
			name: "publisher with single dot rejected",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
				Publisher:     "ap.lane",
				Family:        "allowlist",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "publisher contains unsafe characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.ValidateBase(1) // max schema version = 1
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLogicSigOpcodeProfileDefaultsAndOverrides(t *testing.T) {
	t.Run("omitted uses one member", func(t *testing.T) {
		spec := BaseTemplateSpec{}
		if got := spec.LogicSigOpcodeProfile(false); got != lsigresource.DefaultOpcodeProfile(lsigresource.SingleTransactionOpcodeCeiling) {
			t.Fatalf("LogicSigOpcodeProfile() = %#v, want one-member default", got)
		}
	})

	t.Run("explicit override is preserved", func(t *testing.T) {
		value := uint64(45_000)
		spec := BaseTemplateSpec{MaxOpcodeCost: &value}
		if got := spec.LogicSigOpcodeProfile(false); got != lsigresource.DefaultOpcodeProfile(value) {
			t.Fatalf("LogicSigOpcodeProfile() = %#v, want absolute override %d", got, value)
		}
	})

	t.Run("bounded omission applies to every path", func(t *testing.T) {
		spec := BaseTemplateSpec{}
		want := lsigresource.BoundedOpcodeProfile(
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
			lsigresource.SingleTransactionOpcodeCeiling,
		)
		if got := spec.LogicSigOpcodeProfile(true); got != want {
			t.Fatalf("LogicSigOpcodeProfile() = %#v, want %#v", got, want)
		}
	})
}

func testUint64Ptr(value uint64) *uint64 {
	return &value
}

func mustActiveTS(t *testing.T, paths utilkeys.Paths) utilkeys.ActivePaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active
}
