// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package templatestore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// testMasterKey is a 32-byte key for testing
var testMasterKey = []byte("test-master-key-32-bytes-long!!!")

const testIdentityID = "default"

func TestSaveAndLoadTemplate(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "templatestore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Set keystore path
	utilkeys.SetKeystorePath(tmpDir)

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

	keyType := "test-template-v1"

	// Save template
	outputPath, err := SaveTemplate(testIdentityID, yamlData, keyType, TemplateTypeGeneric, testMasterKey)
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Errorf("Template file was not created at %s", outputPath)
	}

	// Load template back
	loadedData, err := LoadTemplateFromPath(GetTemplateFilePath(testIdentityID, keyType, TemplateTypeGeneric), testMasterKey)
	if err != nil {
		t.Fatalf("LoadTemplateFromPath failed: %v", err)
	}

	// Verify content matches
	if string(loadedData) != string(yamlData) {
		t.Errorf("Loaded data doesn't match original.\nExpected: %s\nGot: %s", yamlData, loadedData)
	}
}

func TestSaveAndLoadFalconTemplate(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "templatestore-falcon-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })

	// Set keystore path
	utilkeys.SetKeystorePath(tmpDir)

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

	keyType := "falcon1024-test-v1"

	// Save template
	outputPath, err := SaveTemplate(testIdentityID, yamlData, keyType, TemplateTypeFalcon, testMasterKey)
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	// Verify file was created in users/default/templates/falcon directory
	expectedDir := filepath.Join(tmpDir, "users", "default", "templates", "falcon")
	if !strings.HasPrefix(outputPath, expectedDir) {
		t.Errorf("Template saved to wrong directory. Expected prefix %s, got %s", expectedDir, outputPath)
	}

	// Load template back
	loadedData, err := LoadTemplateFromPath(GetTemplateFilePath(testIdentityID, keyType, TemplateTypeFalcon), testMasterKey)
	if err != nil {
		t.Fatalf("LoadTemplateFromPath failed: %v", err)
	}

	// Verify content matches
	if string(loadedData) != string(yamlData) {
		t.Errorf("Loaded data doesn't match original")
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
	utilkeys.SetKeystorePath(tmpDir)

	keyType := "exists-test-v1"

	// Should not exist initially
	if TemplateExists(testIdentityID, keyType, TemplateTypeGeneric) {
		t.Error("Template should not exist before saving")
	}

	// Save template
	yamlData := []byte("test: data")
	_, err = SaveTemplate(testIdentityID, yamlData, keyType, TemplateTypeGeneric, testMasterKey)
	if err != nil {
		t.Fatalf("SaveTemplate failed: %v", err)
	}

	// Should exist now
	if !TemplateExists(testIdentityID, keyType, TemplateTypeGeneric) {
		t.Error("Template should exist after saving")
	}

	// Should not exist in falcon directory
	if TemplateExists(testIdentityID, keyType, TemplateTypeFalcon) {
		t.Error("Template should not exist in falcon directory")
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
	utilkeys.SetKeystorePath(tmpDir)

	// Save multiple templates
	templates := map[string][]byte{
		"template-a-v1": []byte("template A"),
		"template-b-v1": []byte("template B"),
		"template-c-v1": []byte("template C"),
	}

	for keyType, data := range templates {
		_, err := SaveTemplate(testIdentityID, data, keyType, TemplateTypeGeneric, testMasterKey)
		if err != nil {
			t.Fatalf("SaveTemplate failed for %s: %v", keyType, err)
		}
	}

	// Load all templates
	loaded, err := LoadAllTemplates(testIdentityID, TemplateTypeGeneric, testMasterKey)
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
		Family:  "my-template",
		Version: 3,
	}

	expected := "my-template-v3"
	if spec.KeyType() != expected {
		t.Errorf("Expected %s, got %s", expected, spec.KeyType())
	}
}

func TestBaseTemplateSpec_ValidateBase(t *testing.T) {
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
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: false,
		},
		{
			name: "missing family",
			spec: BaseTemplateSpec{
				SchemaVersion: 1,
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
				Family:        "test",
				Version:       1,
				DisplayName:   "Test",
			},
			wantErr: true,
			errMsg:  "schema_version 99 is newer than supported",
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
