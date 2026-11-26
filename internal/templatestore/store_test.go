// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatestore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"github.com/aplane-algo/aplane/internal/templatespec"

	"github.com/aplane-algo/aplane/internal/fsutil"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
)

// testMasterKey is a 32-byte key for testing
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

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

template_mode: generated
family: test-template
version: 1
display_name: "Test Template"
valid_rekey_target: false
description: "A test template"
teal: |
  #pragma version 10
  int 1
`)

	keyType := "test.test-template.v1"

	// Save template
	outputPath, err := SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, templatespec.TemplateTypeGeneric, cryptotest.Keyring(t, testMasterKey))
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
	templatePath, pathErr := GetTemplateFilePathForPaths(paths, keyType)
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

template_mode: generated
family: falcon1024-test
version: 1
display_name: "Falcon Test"
valid_rekey_target: false
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
	outputPath, err := SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, templatespec.TemplateTypeComposed, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	// Verify file was created in the product-store key type records directory.
	expectedDir := mustActiveTS(t, paths).KeyTypeRecordsDir()
	if !strings.HasPrefix(outputPath, expectedDir) {
		t.Errorf("Template saved to wrong directory. Expected prefix %s, got %s", expectedDir, outputPath)
	}

	// Load template back
	templatePath, pathErr := GetTemplateFilePathForPaths(paths, keyType)
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
	if TemplateExistsForPaths(paths, keyType, templatespec.TemplateTypeGeneric) {
		t.Error("Template should not exist before saving")
	}

	// Save template
	yamlData := []byte("test: data")
	_, err = SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, templatespec.TemplateTypeGeneric, cryptotest.Keyring(t, testMasterKey))
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	if TemplateExistsForPaths(paths, keyType, templatespec.TemplateTypeGeneric) {
		t.Error("Template should not exist before key type state is written")
	}
	markTemplateState(t, paths, keyType, templatespec.TemplateTypeGeneric, keytypestate.StateEnabled)

	// Should exist now
	if !TemplateExistsForPaths(paths, keyType, templatespec.TemplateTypeGeneric) {
		t.Error("Template should exist after saving and state write")
	}

	// Should not exist in composed directory
	if TemplateExistsForPaths(paths, keyType, templatespec.TemplateTypeComposed) {
		t.Error("Template should not exist in composed directory")
	}
}

func TestTemplateStoreRejectsUnknownTemplateType(t *testing.T) {
	paths := utilkeys.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	keyType := "test.unknown-template-type.v1"
	unknownType := templatespec.TemplateType("compiled_provider")

	if _, err := SaveTemplateActive(genstoretest.Active(t, paths), []byte("test: data"), keyType, unknownType, cryptotest.Keyring(t, testMasterKey)); err == nil {
		t.Fatal("SaveTemplateActive() error = nil, want unsupported template_type")
	}
	if TemplateExistsForPaths(paths, keyType, unknownType) {
		t.Fatal("TemplateExistsForPaths() = true for unsupported template_type")
	}
	if _, err := ScanTemplateDirectoryForPaths(paths, unknownType); err == nil {
		t.Fatal("ScanTemplateDirectoryForPaths() error = nil, want unsupported template_type")
	}
	if _, ok, err := keytypestate.Get(paths, keyType); err != nil {
		t.Fatalf("keytypestate.Get() error = %v", err)
	} else if ok {
		t.Fatal("SaveTemplateActive() wrote state for unsupported template_type")
	}
}

func markTemplateState(t *testing.T, paths utilkeys.Paths, keyType string, templateType templatespec.TemplateType, state keytypestate.State) {
	t.Helper()
	source, ok := SourceForTemplateType(templateType)
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

func mustActiveTS(t *testing.T, paths utilkeys.Paths) utilkeys.GenPaths {
	t.Helper()
	active, err := genstore.Resolve(paths)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return active
}
