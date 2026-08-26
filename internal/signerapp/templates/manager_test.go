// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"bytes"
	"errors"
	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/addressderive"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatepolicy"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/composeddsa"
)

func TestRegisterKeystoreTemplatesReportsActivatedAndConflictingKeyTypes(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	saveTemplateRecord(t, paths, "new-generic", templatestore.TemplateTypeGeneric, masterKey)
	saveTemplateRecord(t, paths, "conflicting-generic", templatestore.TemplateTypeGeneric, masterKey)
	saveTemplateRecord(t, paths, "invalid-composed", templatestore.TemplateTypeComposed, masterKey)
	lsigprovider.RegisterIfAbsent(templatesTestProvider{
		keyType:     "conflicting-generic",
		fingerprint: "registered-fingerprint",
	})

	manager := &Manager{
		Paths: paths,
		Registrars: []TemplateRegistrar{
			{
				Name:         "generic",
				Source:       keytypestate.SourceYAMLGeneric,
				TemplateType: templatestore.TemplateTypeGeneric,
				Prepare: func(keyType string, _ []byte) (templatepolicy.PreparedTemplateRegistration, error) {
					return templatepolicy.PreparedTemplateRegistration{
						Fingerprint: "incoming-" + keyType,
						Register:    func() bool { return true },
					}, nil
				},
			},
			{
				Name:         "composed",
				Source:       keytypestate.SourceYAMLComposed,
				TemplateType: templatestore.TemplateTypeComposed,
				Prepare: func(string, []byte) (templatepolicy.PreparedTemplateRegistration, error) {
					return templatepolicy.PreparedTemplateRegistration{}, errors.New("invalid composed")
				},
			},
		},
	}

	report, err := manager.RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}

	if !reflect.DeepEqual(report.GenericActivatedKeyTypes, []string{"new-generic"}) {
		t.Fatalf("GenericActivatedKeyTypes = %#v", report.GenericActivatedKeyTypes)
	}
	if !reflect.DeepEqual(report.GenericConflictingKeyTypes, []string{"conflicting-generic"}) {
		t.Fatalf("GenericConflictingKeyTypes = %#v", report.GenericConflictingKeyTypes)
	}
	if !reflect.DeepEqual(report.ComposedInvalidKeyTypes, []string{"invalid-composed"}) {
		t.Fatalf("ComposedInvalidKeyTypes = %#v", report.ComposedInvalidKeyTypes)
	}

	if !reflect.DeepEqual(report.Notices(), []string{
		"new generic template key types activated on reload: [new-generic]",
	}) {
		t.Fatalf("Notices() = %#v", report.Notices())
	}

	if !reflect.DeepEqual(report.Warnings(), []string{
		"conflicting generic templates ignored on reload: [conflicting-generic] (restart apsigner to redefine)",
		"invalid composed templates ignored on reload: [invalid-composed]",
	}) {
		t.Fatalf("Warnings() = %#v", report.Warnings())
	}
}

func TestRegisterKeystoreTemplatesReportsCompiledFingerprintConflict(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	keyType := "templates-compiled-conflict-v1"
	lsigprovider.RegisterIfAbsent(templatesTestProvider{
		keyType:     keyType,
		fingerprint: "1:" + strings.Repeat("a", 64),
	})
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
		// Same fingerprint version, different (valid 64-hex) hash → a real
		// same-version conflict.
		Fingerprint: "1:" + strings.Repeat("b", 64),
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	manager := &Manager{
		Paths:      paths,
		Registrars: nil,
	}

	report, err := manager.RegisterKeystoreTemplates(nil)
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if !reflect.DeepEqual(report.CompiledConflictingKeyTypes, []string{keyType}) {
		t.Fatalf("CompiledConflictingKeyTypes = %#v, want %s", report.CompiledConflictingKeyTypes, keyType)
	}
	if !reflect.DeepEqual(report.Warnings(), []string{
		"conflicting compiled key type records ignored on reload: [templates-compiled-conflict-v1] (restart apsigner to redefine)",
	}) {
		t.Fatalf("Warnings() = %#v", report.Warnings())
	}
}

func TestRegisterKeystoreTemplatesReturnsStateListError(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	stateDir := mustResolveActiveForTemplatesTest(t, paths).KeyTypeRecordsDir()
	if err := os.RemoveAll(stateDir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}
	if err := os.WriteFile(stateDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	report, err := NewManager(paths).RegisterKeystoreTemplates(cryptotest.Keyring(t, testTemplateMasterKey()))
	if err == nil || !strings.Contains(err.Error(), "failed to load keystore templates") {
		t.Fatalf("RegisterKeystoreTemplates() error = %v, want state list failure", err)
	}
	if len(report.CompiledInvalidKeyTypes) != 0 {
		t.Fatalf("CompiledInvalidKeyTypes = %#v, want empty on scan failure", report.CompiledInvalidKeyTypes)
	}
}

func TestRegisterKeystoreTemplatesRegistersGenericAndComposedProviders(t *testing.T) {
	registerManagerTestBase("test.manager-base.v1")
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	genericKeyType := "test.manager-generic.v1"
	composedKeyType := "test.manager-composed.v1"
	t.Cleanup(func() {
		UnregisterProductProvider(genericKeyType)
		UnregisterProductProvider(composedKeyType)
	})
	saveTemplateYAML(t, paths, genericKeyType, templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("manager-generic"), masterKey)
	saveTemplateYAML(t, paths, composedKeyType, templatestore.TemplateTypeComposed, managerComposedTemplateYAML("manager-base", "manager-composed"), masterKey)

	report, err := NewManager(paths).RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if !containsString(report.GenericActivatedKeyTypes, genericKeyType) {
		t.Fatalf("GenericActivatedKeyTypes = %#v, want %s", report.GenericActivatedKeyTypes, genericKeyType)
	}
	if !containsString(report.ComposedActivatedKeyTypes, composedKeyType) {
		t.Fatalf("ComposedActivatedKeyTypes = %#v, want %s", report.ComposedActivatedKeyTypes, composedKeyType)
	}
	if lsigprovider.Get(genericKeyType) == nil {
		t.Fatalf("generic provider %s was not registered", genericKeyType)
	}
	if lsigprovider.Get(composedKeyType) == nil {
		t.Fatalf("composed provider %s was not registered", composedKeyType)
	}
	if _, err := addressderive.Get(composedKeyType); err != nil {
		t.Fatalf("composed address deriver was not registered: %v", err)
	}
}

func TestProductTemplateProviderRegistersAndUnregisters(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.manager-product-provider.v1"
	fingerprint := "1:" + strings.Repeat("a", 64)
	lsigprovider.Unregister(keyType)
	t.Cleanup(func() {
		lsigprovider.Unregister(keyType)
	})

	saveTemplateRecord(t, paths, keyType, templatestore.TemplateTypeGeneric, masterKey)
	manager := &Manager{
		Paths: paths,
		Registrars: []TemplateRegistrar{
			{
				Name:         "generic",
				Source:       keytypestate.SourceYAMLGeneric,
				TemplateType: templatestore.TemplateTypeGeneric,
				Prepare: func(keyType string, _ []byte) (templatepolicy.PreparedTemplateRegistration, error) {
					return templatepolicy.PreparedTemplateRegistration{
						Fingerprint: fingerprint,
						Register: func() bool {
							return lsigprovider.RegisterIfAbsent(templatesTestProvider{
								keyType:     keyType,
								fingerprint: fingerprint,
							})
						},
					}, nil
				},
			},
		},
	}

	report, err := manager.RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates(default) error = %v", err)
	}
	if !containsString(report.GenericActivatedKeyTypes, keyType) {
		t.Fatalf("GenericActivatedKeyTypes = %#v, want %s", report.GenericActivatedKeyTypes, keyType)
	}

	idempotent, err := manager.RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("second RegisterKeystoreTemplates(default) error = %v", err)
	}
	if !containsString(idempotent.GenericIdempotentKeyTypes, keyType) {
		t.Fatalf("GenericIdempotentKeyTypes = %#v, want %s", idempotent.GenericIdempotentKeyTypes, keyType)
	}

	if unregistered := UnregisterProductProvider(keyType); !unregistered {
		t.Fatalf("UnregisterProductProvider() did not unregister provider")
	}
	if lsigprovider.Get(keyType) != nil {
		t.Fatalf("provider %s remained registered after product deactivation", keyType)
	}
}

func TestRegisterKeystoreTemplatesSkipsDisabledComposedTemplate(t *testing.T) {
	registerManagerTestBase("test.manager-disabled-base.v1")
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.manager-disabled.v1"
	saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeComposed, managerComposedTemplateYAML("manager-disabled-base", "manager-disabled"), masterKey)
	writeTemplateStateForTest(t, paths, keyType, templatestore.TemplateTypeComposed, keytypestate.StateDisabled)

	report, err := NewManager(paths).RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if !containsString(report.ComposedDisabledKeyTypes, keyType) {
		t.Fatalf("ComposedDisabledKeyTypes = %#v, want %s", report.ComposedDisabledKeyTypes, keyType)
	}
	if lsigprovider.Get(keyType) != nil {
		t.Fatalf("provider %s was registered despite disabled state", keyType)
	}
}

func TestRegisterKeystoreTemplatesLifecycleMatrix(t *testing.T) {
	type wantBucket string
	const (
		wantGenericActivated  wantBucket = "generic activated"
		wantComposedActivated wantBucket = "composed activated"
		wantGenericDisabled   wantBucket = "generic disabled"
		wantComposedDisabled  wantBucket = "composed disabled"
		wantGenericOrphaned   wantBucket = "generic orphaned"
		wantComposedOrphaned  wantBucket = "composed orphaned"
		wantInvalidState      wantBucket = "invalid state"
		wantNoReport          wantBucket = "no report"
		wantNamespaceDefect   wantBucket = "namespace defect"
	)

	tests := []struct {
		name         string
		keyType      string
		templateType templatestore.TemplateType
		setup        func(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, masterKey []byte)
		want         wantBucket
		wantRegister bool
	}{
		{
			name:         "enabled generic registers",
			keyType:      "test.manager-matrix-enabled-generic.v1",
			templateType: templatestore.TemplateTypeGeneric,
			setup:        saveTemplateRecord,
			want:         wantGenericActivated,
			wantRegister: true,
		},
		{
			name:         "enabled composed registers",
			keyType:      "test.manager-matrix-enabled-composed.v1",
			templateType: templatestore.TemplateTypeComposed,
			setup:        saveTemplateRecord,
			want:         wantComposedActivated,
			wantRegister: true,
		},
		{
			name:         "disabled generic skips registration",
			keyType:      "test.manager-matrix-disabled-generic.v1",
			templateType: templatestore.TemplateTypeGeneric,
			setup: func(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, masterKey []byte) {
				t.Helper()
				saveTemplateRecord(t, paths, keyType, templateType, masterKey)
				writeTemplateStateForTest(t, paths, keyType, templateType, keytypestate.StateDisabled)
			},
			want: wantGenericDisabled,
		},
		{
			name:         "disabled composed skips registration",
			keyType:      "test.manager-matrix-disabled-composed.v1",
			templateType: templatestore.TemplateTypeComposed,
			setup: func(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, masterKey []byte) {
				t.Helper()
				saveTemplateRecord(t, paths, keyType, templateType, masterKey)
				writeTemplateStateForTest(t, paths, keyType, templateType, keytypestate.StateDisabled)
			},
			want: wantComposedDisabled,
		},
		{
			name:         "generic record without file reports orphan",
			keyType:      "test.manager-matrix-orphan-generic.v1",
			templateType: templatestore.TemplateTypeGeneric,
			setup: func(t *testing.T, paths storepaths.Paths, keyType string, _ templatestore.TemplateType, _ []byte) {
				t.Helper()
				if err := keytypestate.Put(paths, keytypestate.Record{
					KeyType: keyType,
					Source:  keytypestate.SourceYAMLGeneric,
					State:   keytypestate.StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
			want: wantGenericOrphaned,
		},
		{
			name:         "composed record without file reports orphan",
			keyType:      "test.manager-matrix-orphan-composed.v1",
			templateType: templatestore.TemplateTypeComposed,
			setup: func(t *testing.T, paths storepaths.Paths, keyType string, _ templatestore.TemplateType, _ []byte) {
				t.Helper()
				if err := keytypestate.Put(paths, keytypestate.Record{
					KeyType: keyType,
					Source:  keytypestate.SourceYAMLComposed,
					State:   keytypestate.StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
			want: wantComposedOrphaned,
		},
		{
			name:         "template file without state record is a namespace defect",
			keyType:      "test.manager-matrix-stray-file.v1",
			templateType: templatestore.TemplateTypeGeneric,
			setup: func(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, masterKey []byte) {
				t.Helper()
				saveTemplateRecord(t, paths, keyType, templateType, masterKey)
				if err := keytypestate.Delete(paths, keyType); err != nil {
					t.Fatalf("Delete() error = %v", err)
				}
			},
			want: wantNamespaceDefect,
		},
		{
			name:         "invalid state record reports without registration",
			keyType:      "test.manager-matrix-invalid-state.v1",
			templateType: templatestore.TemplateTypeGeneric,
			setup: func(t *testing.T, paths storepaths.Paths, keyType string, _ templatestore.TemplateType, _ []byte) {
				t.Helper()
				path := mustResolveActiveForTemplatesTest(t, paths).KeyTypeRecord(keyType)
				if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			},
			want: wantInvalidState,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			paths = genstoretest.MintFirst(t, paths)
			masterKey := testTemplateMasterKey()
			registered := make(map[string]bool)
			tt.setup(t, paths, tt.keyType, tt.templateType, masterKey)

			report, err := lifecycleMatrixManager(paths, registered).RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
			if err != nil {
				t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
			}

			assertLifecycleReportBucket(t, report, tt.keyType, string(tt.want))
			if registered[tt.keyType] != tt.wantRegister {
				t.Fatalf("registered[%s] = %v, want %v", tt.keyType, registered[tt.keyType], tt.wantRegister)
			}
		})
	}
}

func TestRegisterKeystoreTemplatesReportsOrphanedTemplateRecords(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	genericKeyType := "test.manager-orphan-generic.v1"
	composedKeyType := "test.manager-orphan-composed.v1"
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: genericKeyType,
		Source:  keytypestate.SourceYAMLGeneric,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put(generic orphan) error = %v", err)
	}
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: composedKeyType,
		Source:  keytypestate.SourceYAMLComposed,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put(composed orphan) error = %v", err)
	}

	report, err := NewManager(paths).RegisterKeystoreTemplates(cryptotest.Keyring(t, testTemplateMasterKey()))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if !containsString(report.GenericOrphanedKeyTypes, genericKeyType) {
		t.Fatalf("GenericOrphanedKeyTypes = %#v, want %s", report.GenericOrphanedKeyTypes, genericKeyType)
	}
	if !containsString(report.ComposedOrphanedKeyTypes, composedKeyType) {
		t.Fatalf("ComposedOrphanedKeyTypes = %#v, want %s", report.ComposedOrphanedKeyTypes, composedKeyType)
	}
}

func TestRegisterKeystoreTemplatesReportsInvalidStateRecord(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.manager-invalid-record.v1"
	saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("manager-invalid-record"), masterKey)
	if err := os.WriteFile(mustResolveActiveForTemplatesTest(t, paths).KeyTypeRecord(keyType), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt record) error = %v", err)
	}

	report, err := NewManager(paths).RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if !containsString(report.InvalidStateRecordKeyTypes, keyType) {
		t.Fatalf("InvalidStateRecordKeyTypes = %#v, want %s", report.InvalidStateRecordKeyTypes, keyType)
	}
	if !reflect.DeepEqual(report.Warnings(), []string{
		"invalid key type state records ignored on reload: [test.manager-invalid-record.v1]",
	}) {
		t.Fatalf("Warnings() = %#v", report.Warnings())
	}
	if lsigprovider.Get(keyType) != nil {
		t.Fatalf("provider %s was registered despite corrupt state record", keyType)
	}
}

func TestRegisterKeystoreTemplatesReportsUnreadableTemplateAsInvalid(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.manager-unreadable-template.v1"
	templatePath, pathErr := templatestore.GetTemplateFilePathForPaths(paths, keyType, templatestore.TemplateTypeGeneric)
	if pathErr != nil {
		t.Fatalf("GetTemplateFilePathForPaths() error = %v", pathErr)
	}
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o750); err != nil {
		t.Fatalf("MkdirAll(template dir) error = %v", err)
	}
	if err := os.WriteFile(templatePath, []byte("not an encrypted template"), 0o600); err != nil {
		t.Fatalf("WriteFile(template) error = %v", err)
	}
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceYAMLGeneric,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("Put(state record) error = %v", err)
	}

	report, err := NewManager(paths).RegisterKeystoreTemplates(cryptotest.Keyring(t, masterKey))
	if err != nil {
		t.Fatalf("RegisterKeystoreTemplates() error = %v", err)
	}
	if !containsString(report.GenericInvalidKeyTypes, keyType) {
		t.Fatalf("GenericInvalidKeyTypes = %#v, want %s", report.GenericInvalidKeyTypes, keyType)
	}
	if !reflect.DeepEqual(report.Warnings(), []string{
		"invalid generic templates ignored on reload: [test.manager-unreadable-template.v1]",
	}) {
		t.Fatalf("Warnings() = %#v", report.Warnings())
	}
	if lsigprovider.Get(keyType) != nil {
		t.Fatalf("provider %s was registered despite unreadable template file", keyType)
	}
}

func testTemplateMasterKey() []byte {
	return bytes.Repeat([]byte{9}, 32)
}

func saveTemplateRecord(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, masterKey []byte) {
	t.Helper()
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), []byte("ignored"), keyType, templateType, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SaveTemplateActive(%s) error = %v", keyType, err)
	}
	writeTemplateStateForTest(t, paths, keyType, templateType, keytypestate.StateEnabled)
}

func saveTemplateYAML(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, yamlData []byte, masterKey []byte) {
	t.Helper()
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), yamlData, keyType, templateType, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SaveTemplateActive(%s) error = %v", keyType, err)
	}
	writeTemplateStateForTest(t, paths, keyType, templateType, keytypestate.StateEnabled)
}

func writeTemplateStateForTest(t *testing.T, paths storepaths.Paths, keyType string, templateType templatestore.TemplateType, state keytypestate.State) {
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
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  source,
		State:   state,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

func lifecycleMatrixManager(paths storepaths.Paths, registered map[string]bool) *Manager {
	registrars := []TemplateRegistrar{
		{
			Name:         "generic",
			Source:       keytypestate.SourceYAMLGeneric,
			TemplateType: templatestore.TemplateTypeGeneric,
		},
		{
			Name:         "composed",
			Source:       keytypestate.SourceYAMLComposed,
			TemplateType: templatestore.TemplateTypeComposed,
		},
	}
	for i := range registrars {
		registrars[i].Prepare = func(keyType string, _ []byte) (templatepolicy.PreparedTemplateRegistration, error) {
			return templatepolicy.PreparedTemplateRegistration{
				Fingerprint: "fp-" + keyType,
				Register: func() bool {
					registered[keyType] = true
					return true
				},
			}, nil
		}
	}
	return &Manager{Paths: paths, Registrars: registrars}
}

func assertLifecycleReportBucket(t *testing.T, report RegistrationReport, keyType string, want string) {
	t.Helper()
	buckets := map[string][]string{
		"generic activated":  report.GenericActivatedKeyTypes,
		"composed activated": report.ComposedActivatedKeyTypes,
		"generic disabled":   report.GenericDisabledKeyTypes,
		"composed disabled":  report.ComposedDisabledKeyTypes,
		"generic orphaned":   report.GenericOrphanedKeyTypes,
		"composed orphaned":  report.ComposedOrphanedKeyTypes,
		"invalid state":      report.InvalidStateRecordKeyTypes,
	}
	if want == "namespace defect" {
		found := false
		for _, defect := range report.NamespaceDefects {
			if strings.Contains(defect, keyType) {
				found = true
			}
		}
		if !found {
			t.Fatalf("NamespaceDefects = %v, want an entry for %s", report.NamespaceDefects, keyType)
		}
	}
	for name, keyTypes := range buckets {
		got := containsString(keyTypes, keyType)
		wantHere := name == want
		if got != wantHere {
			t.Fatalf("%s contains %s = %v, want %v; report = %+v", name, keyType, got, wantHere, report)
		}
	}
	if want == "no report" {
		if len(report.Warnings()) != 0 || len(report.Notices()) != 0 {
			t.Fatalf("report for %s = %+v, want no warnings or notices", keyType, report)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func registerManagerTestBase(keyType string) {
	familyName := strings.TrimSuffix(keyType, "-v1")
	if dot := strings.Index(familyName, "."); dot >= 0 {
		familyName = familyName[dot+1:]
	}
	familyName = strings.TrimSuffix(familyName, ".v1")
	composeddsa.RegisterBase(composeddsa.BaseRegistration{
		BaseKeyType:       keyType,
		FamilyName:        familyName,
		Version:           1,
		Ops:               managerTestOps{},
		NewAddressDeriver: func(string) addressderive.Deriver { return managerTestDeriver{} },
	})
}

func managerGenericTemplateYAML(family string) []byte {
	return []byte(`schema_version: 1
template_type: generic
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "Manager Generic"
description: "Manager generic template"
max_opcode_cost: 20000
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
}

func managerComposedTemplateYAML(baseFamily, family string) []byte {
	return []byte(`schema_version: 1
template_type: composed
base_key_type: test.` + baseFamily + `.v1
template_mode: generated
publisher: test
family: ` + family + `
version: 1
display_name: "Manager Composed"
description: "Manager composed template"
max_opcode_cost: 20000
parameters: []
runtime_args: []
teal: |
  #pragma version 8
  int 1
  return
`)
}

type managerTestOps struct{}

func (managerTestOps) PublicKeySize() int                          { return 1 }
func (managerTestOps) CryptoSignatureSize() int                    { return 1 }
func (managerTestOps) MnemonicScheme() string                      { return "" }
func (managerTestOps) MnemonicWordCount() int                      { return 0 }
func (managerTestOps) DisplayColor() string                        { return "" }
func (managerTestOps) TEALVersion() int                            { return 12 }
func (managerTestOps) BuildSignatureArgs([]byte) ([][]byte, error) { return nil, nil }
func (managerTestOps) BuildVerifyTEAL([]byte) (string, error)      { return "int 1\nreturn\n", nil }

type managerTestDeriver struct{}

func (managerTestDeriver) DeriveAddress(string, map[string]string) (string, error) {
	return "addr", nil
}

type templatesTestProvider struct {
	keyType     string
	fingerprint string
}

func (p templatesTestProvider) KeyType() string                                { return p.keyType }
func (p templatesTestProvider) RoutingFamily() string                          { return p.keyType }
func (p templatesTestProvider) Version() int                                   { return 1 }
func (p templatesTestProvider) Category() string                               { return lsigprovider.CategoryDSALsig }
func (p templatesTestProvider) DisplayName() string                            { return "Templates Test Provider" }
func (p templatesTestProvider) Description() string                            { return "Test provider" }
func (p templatesTestProvider) DisplayColor() string                           { return "" }
func (p templatesTestProvider) CreationParams() []lsigprovider.ParameterDef    { return nil }
func (p templatesTestProvider) ValidateCreationParams(map[string]string) error { return nil }
func (p templatesTestProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (p templatesTestProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}
func (p templatesTestProvider) CompatibilityFingerprint() string { return p.fingerprint }

// sweepActiveForTest resolves the flat legacy layout and lists its records;
// sweepKeyTypeNamespace itself is layout-agnostic (the generational gate
// lives in RegisterKeystoreTemplates), so unit tests exercise it directly.
func sweepForTest(t *testing.T, paths storepaths.Paths, masterKey []byte) []string {
	t.Helper()
	active := mustResolveActiveForTemplatesTest(t, paths)
	records, err := keytypestate.ListActive(active)
	if err != nil {
		t.Fatalf("ListActive() error = %v", err)
	}
	registrars, err := NewManager(paths).templateRegistrars()
	if err != nil {
		t.Fatalf("templateRegistrars() error = %v", err)
	}
	registrarsBySource := make(map[keytypestate.Source]TemplateRegistrar, len(registrars))
	for _, registrar := range registrars {
		registrarsBySource[registrar.Source] = registrar
	}
	return sweepKeyTypeNamespace(active, cryptotest.Keyring(t, masterKey), records, registrarsBySource)
}

func TestSweepKeyTypeNamespaceCleanStore(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	saveTemplateYAML(t, paths, "test.sweep-clean.v1", templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("sweep-clean"), masterKey)

	if defects := sweepForTest(t, paths, masterKey); len(defects) != 0 {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want none for a clean store", defects)
	}
}

func TestSweepKeyTypeNamespaceFlagsTemplateWithoutRecord(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.sweep-stray.v1"
	saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("sweep-stray"), masterKey)
	if err := keytypestate.Delete(paths, keyType); err != nil {
		t.Fatalf("Delete(state record) error = %v", err)
	}

	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 1 || !strings.Contains(defects[0], "no state record") {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want one no-state-record defect", defects)
	}
}

func TestSweepKeyTypeNamespaceFlagsUnexpectedEntries(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	saveTemplateYAML(t, paths, "test.sweep-unexpected.v1", templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("sweep-unexpected"), masterKey)
	dir := mustResolveActiveForTemplatesTest(t, paths).KeyTypeRecordsDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0750); err != nil {
		t.Fatalf("Mkdir error = %v", err)
	}

	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 2 {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want unexpected-entry and unexpected-directory defects", defects)
	}
}

func TestSweepKeyTypeNamespaceValidatesDisabledTemplates(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.sweep-disabled.v1"
	saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("sweep-disabled"), masterKey)
	writeTemplateStateForTest(t, paths, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateDisabled)

	if defects := sweepForTest(t, paths, masterKey); len(defects) != 0 {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want none for a healthy disabled template", defects)
	}

	dir := mustResolveActiveForTemplatesTest(t, paths).KeyTypeRecordsDir()
	if err := os.WriteFile(filepath.Join(dir, keyType+".template"), []byte("plaintext garbage"), 0600); err != nil {
		t.Fatalf("WriteFile(corrupt template) error = %v", err)
	}
	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 1 || !strings.Contains(defects[0], "disabled template") {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want one disabled-template validation defect", defects)
	}
}

func TestSweepKeyTypeNamespaceValidatesDisabledTemplateContent(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.sweep-disabled-yaml.v1"
	// Validly encrypted but semantically malformed template: decryption
	// succeeds, Prepare must reject it.
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), []byte("not a template"), keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SaveTemplateActive() error = %v", err)
	}
	writeTemplateStateForTest(t, paths, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateDisabled)

	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 1 || !strings.Contains(defects[0], "disabled template") {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want one disabled-template validation defect for malformed YAML", defects)
	}
}

func TestSweepKeyTypeNamespaceFlagsDisabledRecordMissingTemplate(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.sweep-disabled-missing.v1"
	saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("sweep-disabled-missing"), masterKey)
	writeTemplateStateForTest(t, paths, keyType, templatestore.TemplateTypeGeneric, keytypestate.StateDisabled)
	active := mustResolveActiveForTemplatesTest(t, paths)
	if err := os.Remove(active.KeyTypeTemplate(keyType)); err != nil {
		t.Fatalf("remove template file: %v", err)
	}

	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 1 || !strings.Contains(defects[0], "no template file") {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want one disabled-record-missing-template defect", defects)
	}
}

func TestSweepKeyTypeNamespaceFlagsTemplatePairedWithCompiledRecord(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.sweep-compiled.v1"
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType: keyType,
		Source:  keytypestate.SourceCompiled,
		State:   keytypestate.StateEnabled,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
	// Compiled providers own no template files; a stray one is unaccounted
	// encrypted content.
	if _, err := templatestore.SaveTemplateActive(genstoretest.Active(t, paths), []byte("stray"), keyType, templatestore.TemplateTypeGeneric, cryptotest.Keyring(t, masterKey)); err != nil {
		t.Fatalf("SaveTemplateActive() error = %v", err)
	}

	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 1 || !strings.Contains(defects[0], "compiled-provider record") {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want one compiled-pairing defect", defects)
	}
}

func TestSweepKeyTypeNamespaceFlagsNoncanonicalFilenames(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	paths = genstoretest.MintFirst(t, paths)
	masterKey := testTemplateMasterKey()
	keyType := "test.sweep-canonical.v1"
	saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, managerGenericTemplateYAML("sweep-canonical"), masterKey)
	dir := mustResolveActiveForTemplatesTest(t, paths).KeyTypeRecordsDir()
	// Noncanonical copies: the lookup APIs normalize before reading, so
	// these files are invisible to registration and ListInvalidActive.
	recordJSON, err := os.ReadFile(filepath.Join(dir, keyType+".json"))
	if err != nil {
		t.Fatalf("read canonical record: %v", err)
	}
	templateBytes, err := os.ReadFile(filepath.Join(dir, keyType+".template"))
	if err != nil {
		t.Fatalf("read canonical template: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Test.Sweep-Canonical.V1.json"), recordJSON, 0600); err != nil {
		t.Fatalf("write noncanonical record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Test.Sweep-Canonical.V1.template"), templateBytes, 0600); err != nil {
		t.Fatalf("write noncanonical template: %v", err)
	}

	defects := sweepForTest(t, paths, masterKey)
	if len(defects) != 2 {
		t.Fatalf("sweepKeyTypeNamespace() = %#v, want canonical-filename defects for record and template", defects)
	}
	for _, defect := range defects {
		if !strings.Contains(defect, "canonical key type filename") {
			t.Fatalf("defect %q, want canonical-filename rejection", defect)
		}
	}
}

func mustResolveActiveForTemplatesTest(t *testing.T, paths storepaths.Paths) storepaths.ActivePaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths)
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active
}
