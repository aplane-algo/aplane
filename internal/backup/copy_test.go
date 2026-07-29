// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package backup

import (
	"encoding/json"
	"fmt"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keys/keystest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
)

var testExportMasterKey = []byte("0123456789abcdef0123456789abcdef")

func TestExportKeyUsesSentryCredentialSource(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	identityID := "default"
	selector, keyJSON := testSentryComponentBackupKeyJSON(t)
	encrypted, err := crypto.EncryptWithTermKey(
		keyJSON, testExportMasterKey, crypto.FirstTerm, crypto.SentryCredentialContext(selector),
	)
	if err != nil {
		t.Fatal(err)
	}
	source := keys.SentryCredentialFilePath(paths, identityID, selector)
	if err := os.WriteFile(source, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	active, err := genstore.ResolveActive(paths, identityID)
	if err != nil {
		t.Fatalf("ResolveActive() error = %v", err)
	}
	if _, _, err := ExportKey(paths, identityID, active.KeysDir(), destination, selector, testExportMasterKey, []byte("export-passphrase")); err != nil {
		t.Fatalf("ExportKey() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(destination, selector+".apb")); err != nil {
		t.Fatalf("witness .apb missing: %v", err)
	}
}

func TestExportKeyRejectsAmbiguousManagedCredentialClasses(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	identityID := "default"
	selector, keyJSON := testSentryComponentBackupKeyJSON(t)
	encrypted, err := crypto.EncryptWithTermKey(
		keyJSON, testExportMasterKey, crypto.FirstTerm, crypto.SentryCredentialContext(selector),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.KeysDir(identityID), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, extension := range []string{keys.AccountKeyExtension, keys.SentryCredentialExtension} {
		if err := os.WriteFile(filepath.Join(paths.KeysDir(identityID), selector+extension), encrypted, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err = ExportKey(paths, identityID, paths.KeysDir(identityID), t.TempDir(), selector, testExportMasterKey, []byte("export-passphrase"))
	if err == nil || !strings.Contains(err.Error(), "ambiguous managed credential") {
		t.Fatalf("ExportKey() error = %v, want ambiguity rejection", err)
	}
}

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
		keyType    = "custom.allowlist.v1"
	)

	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	keyJSON := testKeyJSON(t, keyType)
	wantTemplate := []byte("schema_version: 1\ntemplate_type: generic\ntemplate_mode: generated\npublisher: custom\nfamily: allowlist\nversion: 1\ndisplay_name: Override\nteal: |\n  int 1\n")

	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, testExportMasterKey)); err != nil {
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
		keyType    = "aplane.htlc.v1"
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
		keyType    = "aplane.htlc.v1"
	)

	wantTemplate, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.htlc.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.htlc.v1.yaml) error = %v", err)
	}

	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, testExportMasterKey)); err != nil {
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
		keyType    = "aplane.falcon1024-allowlist.v1"
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
		keyType    = "aplane.falcon1024-allowlist.v1"
	)

	wantTemplate, err := os.ReadFile(filepath.Join("..", "..", "library", "templates", "aplane.falcon1024-allowlist.v1.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(aplane.falcon1024-allowlist.v1.yaml) error = %v", err)
	}

	paths := storepaths.NewPaths(t.TempDir())
	mintFirstGenerationForBackupTest(t, paths)
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeComposed, cryptotest.Keyring(t, testExportMasterKey)); err != nil {
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
	mintFirstGenerationForBackupTest(t, paths)
	if _, err := templatestore.SaveTemplateForPaths(paths, identityID, wantTemplate, keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, testExportMasterKey)); err != nil {
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

// TestIsCanonicalPayloadRejectionCoversEverySentinel pins the contract that
// ExportAllKeys relies on: an ExportKey failure caused by canonical payload
// validation is skippable (one bad key does not abort the all-keys backup),
// while an infrastructure failure (read/decrypt/template/IO) must abort. Both
// branches of the classifier are asserted, including the bare
// ErrMissingLogicSigSaltCounter sentinel, which no end-to-end backup test
// exercises. If a future validation adds a new bare sentinel that should be
// skippable, it must be added here and to isCanonicalPayloadRejection.
func TestIsCanonicalPayloadRejectionCoversEverySentinel(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"incompatible_format_bare", keys.ErrIncompatibleKeyFormat, true},
		{"incompatible_format_wrapped", fmt.Errorf("failed to build export payload for X: %w", keys.ErrIncompatibleKeyFormat), true},
		{"missing_salt_counter_bare", keys.ErrMissingLogicSigSaltCounter, true},
		{"missing_salt_counter_wrapped", fmt.Errorf("failed to export X: %w", keys.ErrMissingLogicSigSaltCounter), true},
		{"infra_io_error", io.ErrUnexpectedEOF, false},
		{"infra_wrapped_decrypt", fmt.Errorf("failed to decrypt key: %w", io.ErrUnexpectedEOF), false},
		{"nil_error", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCanonicalPayloadRejection(tc.err); got != tc.want {
				t.Fatalf("isCanonicalPayloadRejection(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func mintFirstGenerationForBackupTest(t *testing.T, paths storepaths.Paths) {
	t.Helper()
	generationID, err := genstore.NewGenerationID(time.Unix(1_785_200_000, 0))
	if err != nil {
		t.Fatalf("NewGenerationID: %v", err)
	}
	if _, err := genstore.Mint(paths, "default", genstore.MintRequest{
		GenerationID:    generationID,
		FirstGeneration: true,
		Operation:       "store-initialize",
		OperationID:     "init-" + generationID,
		CreatedAt:       time.Unix(1_785_200_000, 0),
	}); err != nil {
		t.Fatalf("Mint(first): %v", err)
	}
}
