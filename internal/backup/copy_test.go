// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

var testExportMasterKey = []byte("0123456789abcdef0123456789abcdef")

func testKeyJSON(t *testing.T, keyType string) []byte {
	t.Helper()
	return keystest.GenericLSigKeyJSON(t, keyType, saltedLogicSigBytecodeForTest(), saltCounterForTest, nil, "")
}

func writeTemplateStateForBackupTest(t *testing.T, paths storepaths.Paths, identityID, keyType string, templateType templatestore.TemplateType, state keytypestate.State) {
	t.Helper()
	var source keytypestate.Source
	switch templateType {
	case templatestore.TemplateTypeGeneric:
		source = keytypestate.SourceYAMLGeneric
	case templatestore.TemplateTypeComposed:
		source = keytypestate.SourceYAMLComposed
	default:
		t.Fatalf("unsupported template type in test: %q", templateType)
	}
	if err := keytypestate.Put(paths, identityID, keytypestate.Record{
		KeyType: keyType,
		Source:  source,
		State:   state,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

func TestBuildExportPayloadBundlesKeystoreTemplate(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "custom.whitelist.v1"
	)

	paths := storepaths.NewPaths(t.TempDir())
	keyJSON := testKeyJSON(t, keyType)
	wantTemplate := []byte("schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: custom\nfamily: whitelist\nversion: 1\ndisplay_name: Override\nteal: |\n  int 1\n")

	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeGeneric, testExportMasterKey); err != nil {
		t.Fatalf("SaveTemplateForPaths() error = %v", err)
	}
	writeTemplateStateForBackupTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	payload, err := buildExportPayload(paths, identityID, keyJSON, testExportMasterKey)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}
	var bundle BackupBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("json.Unmarshal(BackupBundle) error = %v", err)
	}
	if bundle.BackupBundle != BackupBundleSentinel || bundle.PayloadVersion != CurrentBackupBundlePayloadVersion {
		t.Fatalf("bundle version fields = (%d, %d), want (%d, %d)", bundle.BackupBundle, bundle.PayloadVersion, BackupBundleSentinel, CurrentBackupBundlePayloadVersion)
	}

	gotKeyJSON, gotTemplate, gotType, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if string(gotKeyJSON) != string(keyJSON) {
		if !jsonEqualForBackupTest(t, gotKeyJSON, keyJSON) {
			t.Fatalf("embedded key JSON mismatch\n got: %s\nwant: %s", gotKeyJSON, keyJSON)
		}
	}
	if gotType != string(templatestore.TemplateTypeGeneric) {
		t.Fatalf("template_type = %q, want %q", gotType, templatestore.TemplateTypeGeneric)
	}
	if string(gotTemplate) != string(wantTemplate) {
		t.Fatalf("template YAML mismatch\n got: %s\nwant: %s", gotTemplate, wantTemplate)
	}
}

func TestParseBackupRejectsUnknownBundleVersions(t *testing.T) {
	keyJSON := testKeyJSON(t, "custom.versioned.v1")
	tests := []struct {
		name string
		in   BackupBundle
		raw  string
	}{
		{
			name: "unknown sentinel",
			in: BackupBundle{
				BackupBundle:   2,
				PayloadVersion: CurrentBackupBundlePayloadVersion,
				Key:            json.RawMessage(keyJSON),
			},
		},
		{
			name: "unknown payload version",
			in: BackupBundle{
				BackupBundle:   BackupBundleSentinel,
				PayloadVersion: CurrentBackupBundlePayloadVersion + 1,
				Key:            json.RawMessage(keyJSON),
			},
		},
		{
			name: "explicit zero payload version",
			raw:  `{"backup_bundle":1,"payload_version":0,"key":{}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(tt.raw)
			if tt.raw == "" {
				var err error
				data, err = json.Marshal(tt.in)
				if err != nil {
					t.Fatalf("json.Marshal() error = %v", err)
				}
			}
			if _, _, _, err := ParseBackup(data); err == nil {
				t.Fatal("ParseBackup() error = nil, want version rejection")
			}
		})
	}
}

func TestParseBackupAcceptsLegacyBundleWithoutPayloadVersion(t *testing.T) {
	keyJSON := testKeyJSON(t, "custom.legacy.v1")
	data, err := json.Marshal(BackupBundle{
		BackupBundle: BackupBundleSentinel,
		Key:          json.RawMessage(keyJSON),
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	gotKey, _, _, err := ParseBackup(data)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if string(gotKey) != string(keyJSON) {
		if !jsonEqualForBackupTest(t, gotKey, keyJSON) {
			t.Fatalf("key JSON = %s, want %s", gotKey, keyJSON)
		}
	}
}

func jsonEqualForBackupTest(t *testing.T, left, right []byte) bool {
	t.Helper()
	var leftValue any
	var rightValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		t.Fatalf("json.Unmarshal(left) error = %v", err)
	}
	if err := json.Unmarshal(right, &rightValue); err != nil {
		t.Fatalf("json.Unmarshal(right) error = %v", err)
	}
	return jsonObjectsEqual(leftValue, rightValue)
}

func jsonObjectsEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func TestBuildExportPayloadDoesNotBundleLibraryGenericTemplateWithoutKeystoreCopy(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "aplane.whitelist.v1"
	)

	payload, err := buildExportPayload(storepaths.NewPaths(t.TempDir()), identityID, testKeyJSON(t, keyType), testExportMasterKey)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}

	_, gotTemplate, gotType, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if gotType != "" {
		t.Fatalf("template_type = %q, want empty", gotType)
	}
	if gotTemplate != nil {
		t.Fatalf("template YAML = %q, want nil", gotTemplate)
	}
}

func TestBuildExportPayloadBundlesLibraryGenericTemplateFromKeystore(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "aplane.whitelist.v1"
	)

	wantTemplate, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.whitelist.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.whitelist.v1.yaml) error = %v", err)
	}

	paths := storepaths.NewPaths(t.TempDir())
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeGeneric, testExportMasterKey); err != nil {
		t.Fatalf("SaveTemplateForPaths() error = %v", err)
	}
	writeTemplateStateForBackupTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	payload, err := buildExportPayload(paths, identityID, testKeyJSON(t, keyType), testExportMasterKey)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}

	_, gotTemplate, gotType, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if gotType != string(templatestore.TemplateTypeGeneric) {
		t.Fatalf("template_type = %q, want %q", gotType, templatestore.TemplateTypeGeneric)
	}
	if string(gotTemplate) != string(wantTemplate) {
		t.Fatalf("template YAML mismatch\n got: %s\nwant: %s", gotTemplate, wantTemplate)
	}
}

func TestBuildExportPayloadDoesNotBundleLibraryComposedTemplateWithoutKeystoreCopy(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "aplane.falcon1024-whitelist.v1"
	)

	payload, err := buildExportPayload(storepaths.NewPaths(t.TempDir()), identityID, testKeyJSON(t, keyType), testExportMasterKey)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}

	_, gotTemplate, gotType, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if gotType != "" {
		t.Fatalf("template_type = %q, want empty", gotType)
	}
	if gotTemplate != nil {
		t.Fatalf("template YAML = %q, want nil", gotTemplate)
	}
}

func TestBuildExportPayloadBundlesLibraryComposedTemplateFromKeystore(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "aplane.falcon1024-whitelist.v1"
	)

	wantTemplate, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.falcon1024-whitelist.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.falcon1024-whitelist.v1.yaml) error = %v", err)
	}

	paths := storepaths.NewPaths(t.TempDir())
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeComposed, testExportMasterKey); err != nil {
		t.Fatalf("SaveTemplateForPaths() error = %v", err)
	}
	writeTemplateStateForBackupTest(t, paths, identityID, keyType, templatestore.TemplateTypeComposed, keytypestate.StateEnabled)

	payload, err := buildExportPayload(paths, identityID, testKeyJSON(t, keyType), testExportMasterKey)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}

	_, gotTemplate, gotType, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if gotType != string(templatestore.TemplateTypeComposed) {
		t.Fatalf("template_type = %q, want %q", gotType, templatestore.TemplateTypeComposed)
	}
	if string(gotTemplate) != string(wantTemplate) {
		t.Fatalf("template YAML mismatch\n got: %s\nwant: %s", gotTemplate, wantTemplate)
	}
}

func TestBuildExportPayloadBundlesKeystoreTemplateEvenWhenProviderRegistered(t *testing.T) {
	const (
		identityID = "default"
		keyType    = "test.backup-registered-template.v1"
	)

	lsigprovider.RegisterIfAbsent(backupRegisteredTemplateProvider{keyType: keyType})

	wantTemplate := []byte("schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: test\nfamily: backup-registered-template\nversion: 1\ndisplay_name: Backup Registered Template\nteal: |\n  int 1\n")
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeGeneric, testExportMasterKey); err != nil {
		t.Fatalf("SaveTemplateForPaths() error = %v", err)
	}
	writeTemplateStateForBackupTest(t, paths, identityID, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateEnabled)

	payload, err := buildExportPayload(paths, identityID, testKeyJSON(t, keyType), testExportMasterKey)
	if err != nil {
		t.Fatalf("buildExportPayload() error = %v", err)
	}

	_, gotTemplate, gotType, err := ParseBackup(payload)
	if err != nil {
		t.Fatalf("ParseBackup() error = %v", err)
	}
	if gotType != string(templatestore.TemplateTypeGeneric) {
		t.Fatalf("template_type = %q, want %q", gotType, templatestore.TemplateTypeGeneric)
	}
	if string(gotTemplate) != string(wantTemplate) {
		t.Fatalf("template YAML mismatch\n got: %s\nwant: %s", gotTemplate, wantTemplate)
	}
}

type backupRegisteredTemplateProvider struct {
	keyType string
}

func (p backupRegisteredTemplateProvider) KeyType() string                                { return p.keyType }
func (p backupRegisteredTemplateProvider) RoutingFamily() string                          { return "backup-registered-template" }
func (p backupRegisteredTemplateProvider) Version() int                                   { return 1 }
func (p backupRegisteredTemplateProvider) Category() string                               { return lsigprovider.CategoryGenericLsig }
func (p backupRegisteredTemplateProvider) DisplayName() string                            { return "Backup Registered Template" }
func (p backupRegisteredTemplateProvider) Description() string                            { return "test provider" }
func (p backupRegisteredTemplateProvider) DisplayColor() string                           { return "33" }
func (p backupRegisteredTemplateProvider) CreationParams() []lsigprovider.ParameterDef    { return nil }
func (p backupRegisteredTemplateProvider) ValidateCreationParams(map[string]string) error { return nil }
func (p backupRegisteredTemplateProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (p backupRegisteredTemplateProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
