// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"reflect"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	utilkeys "github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/templatestore"
	"github.com/aplane-algo/aplane/lsig/generictemplate"
)

// recordedFingerprintNames name the values a key-type record can carry, in
// test order.
var recordedFingerprintNames = []string{
	"matching", "nothing recorded", "mismatching", "unversioned", "version 0", "noncanonical prefix", "cross-version", "malformed hash",
}

// recordedFingerprint is the value named, built from the fingerprint the
// current code computes for the record's definition.
func recordedFingerprint(name, live string) string {
	hash := strings.TrimPrefix(live, "1:")
	return map[string]string{
		"matching":            live,
		"nothing recorded":    "",
		"mismatching":         "1:" + strings.Repeat("b", 64),
		"unversioned":         hash,
		"version 0":           "0:" + hash,
		"noncanonical prefix": "01:" + hash,
		"cross-version":       "2:" + hash,
		"malformed hash":      "1:" + hash[:63],
	}[name]
}

func putRecordedFingerprint(t *testing.T, paths utilkeys.Paths, keyType string, source keytypestate.Source, recorded string) {
	t.Helper()
	if err := keytypestate.Put(paths, keytypestate.Record{
		KeyType:     keyType,
		Source:      source,
		State:       keytypestate.StateEnabled,
		Fingerprint: recorded,
	}); err != nil {
		t.Fatalf("keytypestate.Put() error = %v", err)
	}
}

// reloadTemplatesForTest runs the reload's template step as a build and its
// publish do: every template is prepared, and when the preparation found no
// content defect the ones to activate are registered. A build that found a
// defect is not published, and registers nothing; the defects are returned
// with the preparation's report.
func reloadTemplatesForTest(t *testing.T, paths utilkeys.Paths) (RegistrationReport, []string) {
	t.Helper()
	manager := NewManager(paths, lsigprovider.ProcessRegistry{})
	prepared, err := manager.PrepareKeystoreTemplates(cryptotest.Keyring(t, testTemplateMasterKey()))
	if err != nil {
		t.Fatalf("PrepareKeystoreTemplates() error = %v", err)
	}
	if defects := prepared.Report().ContentDefectKeyTypes(); len(defects) > 0 {
		return prepared.Report(), defects
	}
	return prepared.Register(manager.Registry), nil
}

// A reload accepts a template's record only when its fingerprint is the one
// the current code computes for the template, byte for byte. Any other
// recorded value is an external edit, and the reload fails closed, whether or
// not the definition is registered yet.
func TestReloadRequiresTheRecordedTemplateFingerprintExactly(t *testing.T) {
	const (
		accepted     = "accepted"
		externalEdit = "external edit"
	)
	cases := map[string]struct{ unregistered, registered string }{
		"matching":            {accepted, accepted},
		"nothing recorded":    {accepted, accepted},
		"mismatching":         {externalEdit, externalEdit},
		"unversioned":         {externalEdit, externalEdit},
		"version 0":           {externalEdit, externalEdit},
		"noncanonical prefix": {externalEdit, externalEdit},
		"cross-version":       {externalEdit, externalEdit},
		"malformed hash":      {externalEdit, externalEdit},
	}
	for index, recordedName := range recordedFingerprintNames {
		want, ok := cases[recordedName]
		if !ok {
			t.Fatalf("no expectation for %q", recordedName)
		}
		for _, registered := range []bool{false, true} {
			name := recordedName + "/unregistered"
			wantOutcome := want.unregistered
			if registered {
				name, wantOutcome = recordedName+"/registered", want.registered
			}
			t.Run(name, func(t *testing.T) {
				family := "fingerprint-reload-" + string(rune('a'+index))
				if registered {
					family += "-registered"
				}
				data := managerGenericTemplateYAML(family)
				keyType := "test." + family + ".v1"
				live, err := generictemplate.SemanticFingerprint(data)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { lsigprovider.Unregister(keyType) })
				paths := mintedPathsForReloadTest(t)
				masterKey := testTemplateMasterKey()
				saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, data, masterKey)
				if registered {
					putRecordedFingerprint(t, paths, keyType, keytypestate.SourceYAMLGeneric, live)
					if _, defects := reloadTemplatesForTest(t, paths); len(defects) != 0 {
						t.Fatalf("the registering reload found defects %v", defects)
					}
				}
				putRecordedFingerprint(t, paths, keyType, keytypestate.SourceYAMLGeneric, recordedFingerprint(recordedName, live))

				report, defects := reloadTemplatesForTest(t, paths)
				switch wantOutcome {
				case accepted:
					if len(defects) != 0 {
						t.Fatalf("the reload found defects %v, want the record accepted", defects)
					}
					bucket := report.GenericActivatedKeyTypes
					if registered {
						bucket = report.GenericIdempotentKeyTypes
					}
					if !reflect.DeepEqual(bucket, []string{keyType}) {
						t.Fatalf("report = %+v, want %s accepted", report, keyType)
					}
					if lsigprovider.Get(keyType) == nil {
						t.Fatalf("%s is not registered", keyType)
					}
				case externalEdit:
					// A content defect: the build fails the generation, so the
					// reload publishes and registers nothing.
					if !reflect.DeepEqual(defects, []string{keyType}) {
						t.Fatalf("the reload found defects %v, want %s", defects, keyType)
					}
					if !registered && lsigprovider.Get(keyType) != nil {
						t.Fatalf("%s was registered by a reload that found it defective", keyType)
					}
					report, err := NewManager(paths, lsigprovider.ProcessRegistry{}).ValidateKeystoreTemplates(cryptotest.Keyring(t, masterKey))
					if err != nil {
						t.Fatalf("ValidateKeystoreTemplates() error = %v", err)
					}
					if !reflect.DeepEqual(report.GenericExternalEditKeyTypes, []string{keyType}) {
						t.Fatalf("GenericExternalEditKeyTypes = %v, want %s", report.GenericExternalEditKeyTypes, keyType)
					}
					wantWarning := "externally edited generic templates ignored on reload: [" + keyType + "] (stop apsigner and repair with `apstore template repair`; see docs/USER_KEYTYPES.md)"
					if !reflect.DeepEqual(report.Warnings(), []string{wantWarning}) {
						t.Fatalf("Warnings() = %q, want %q", report.Warnings(), wantWarning)
					}
					if registered != (lsigprovider.Get(keyType) != nil) {
						t.Fatalf("%s registered = %v, want %v", keyType, lsigprovider.Get(keyType) != nil, registered)
					}
				}
			})
		}
	}
}

// noFingerprintTestProvider is a compiled provider with no fingerprint, as the
// plain hosts are.
type noFingerprintTestProvider struct{ keyType string }

func (p noFingerprintTestProvider) KeyType() string                                { return p.keyType }
func (p noFingerprintTestProvider) RoutingFamily() string                          { return p.keyType }
func (p noFingerprintTestProvider) Version() int                                   { return 1 }
func (p noFingerprintTestProvider) Category() string                               { return lsigprovider.CategoryDSALsig }
func (p noFingerprintTestProvider) DisplayName() string                            { return "No Fingerprint" }
func (p noFingerprintTestProvider) Description() string                            { return "Test provider" }
func (p noFingerprintTestProvider) DisplayColor() string                           { return "" }
func (p noFingerprintTestProvider) CreationParams() []lsigprovider.ParameterDef    { return nil }
func (p noFingerprintTestProvider) ValidateCreationParams(map[string]string) error { return nil }
func (p noFingerprintTestProvider) RuntimeArgs() []lsigprovider.RuntimeArgDef      { return nil }
func (p noFingerprintTestProvider) BuildArgs([]byte, map[string][]byte) ([][]byte, error) {
	return nil, nil
}

// A compiled key type's record is consistent only when its fingerprint is the
// registered provider's, byte for byte; a record that recorded nothing is
// consistent too. Any other value is a conflict, which reload reports and does
// not fail on.
func TestReloadRequiresTheRecordedCompiledFingerprintExactly(t *testing.T) {
	live := "1:" + strings.Repeat("a", 64)
	// Whether the record conflicts, with a provider whose fingerprint is live
	// and with one that has none, which only a record of none matches.
	cases := map[string]struct{ fingerprinted, none bool }{
		"matching":            {false, true},
		"nothing recorded":    {false, false},
		"mismatching":         {true, true},
		"unversioned":         {true, true},
		"version 0":           {true, true},
		"noncanonical prefix": {true, true},
		"cross-version":       {true, true},
		"malformed hash":      {true, true},
	}
	for index, recordedName := range recordedFingerprintNames {
		want, ok := cases[recordedName]
		if !ok {
			t.Fatalf("no expectation for %q", recordedName)
		}
		for _, fingerprinted := range []bool{true, false} {
			name, wantConflict := recordedName+"/fingerprinted provider", want.fingerprinted
			if !fingerprinted {
				name, wantConflict = recordedName+"/provider without a fingerprint", want.none
			}
			t.Run(name, func(t *testing.T) {
				keyType := "test.fingerprint-compiled-" + string(rune('a'+index)) + ".v1"
				if !fingerprinted {
					keyType = "test.fingerprint-compiled-none-" + string(rune('a'+index)) + ".v1"
				}
				var provider lsigprovider.LSigProvider = templatesTestProvider{keyType: keyType, fingerprint: live}
				if !fingerprinted {
					provider = noFingerprintTestProvider{keyType: keyType}
				}
				if !lsigprovider.RegisterIfAbsent(provider) {
					t.Fatalf("%s already registered", keyType)
				}
				t.Cleanup(func() { lsigprovider.Unregister(keyType) })
				paths := mintedPathsForReloadTest(t)
				putRecordedFingerprint(t, paths, keyType, keytypestate.SourceCompiled, recordedFingerprint(recordedName, live))

				report, defects := reloadTemplatesForTest(t, paths)
				if len(defects) != 0 {
					t.Fatalf("the reload found defects %v, want a compiled conflict not to fail it", defects)
				}
				if wantConflict {
					if !reflect.DeepEqual(report.CompiledConflictingKeyTypes, []string{keyType}) || len(report.CompiledIdempotentKeyTypes) != 0 {
						t.Fatalf("report = %+v, want %s conflicting", report, keyType)
					}
					wantWarning := "conflicting compiled key type records ignored on reload: [" + keyType + "] (re-pin each with `apadmin keytype enable <key_type>`)"
					if !reflect.DeepEqual(report.Warnings(), []string{wantWarning}) {
						t.Fatalf("TemplateWarnings = %q, want %q", report.Warnings(), wantWarning)
					}
					return
				}
				if !reflect.DeepEqual(report.CompiledIdempotentKeyTypes, []string{keyType}) || len(report.CompiledConflictingKeyTypes) != 0 {
					t.Fatalf("report = %+v, want %s consistent", report, keyType)
				}
				if len(report.Warnings()) != 0 {
					t.Fatalf("TemplateWarnings = %q, want none", report.Warnings())
				}
			})
		}
	}
}

// A template record defect is repaired offline by apstore, whether reload
// found it at unlock or while the signer was unlocked; the warning names it.
func TestRegistrationReportWarningsNameTheRepair(t *testing.T) {
	report := RegistrationReport{
		GenericExternalEditKeyTypes:  []string{"test.edited-generic.v1"},
		ComposedExternalEditKeyTypes: []string{"test.edited-composed.v1"},
		GenericOrphanedKeyTypes:      []string{"test.orphan-generic.v1"},
		ComposedOrphanedKeyTypes:     []string{"test.orphan-composed.v1"},
		DisabledOrphanedKeyTypes:     []string{"test.orphan-disabled.v1"},
	}
	const hint = "(stop apsigner and repair with `apstore template repair`; see docs/USER_KEYTYPES.md)"
	want := []string{
		"externally edited generic templates ignored on reload: [test.edited-generic.v1] " + hint,
		"externally edited composed templates ignored on reload: [test.edited-composed.v1] " + hint,
		"generic template state records without template files ignored on reload: [test.orphan-generic.v1] " + hint,
		"composed template state records without template files ignored on reload: [test.orphan-composed.v1] " + hint,
		"disabled template state records without template files: [test.orphan-disabled.v1] " + hint,
	}
	if got := report.Warnings(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Warnings() = %q, want %q", got, want)
	}
}

// A template repair takes its defects from RecordDefects, and the gate that
// refuses a store for any other damage excludes those defects of the key
// types it repairs and nothing else.
func TestRegistrationReportRecordDefects(t *testing.T) {
	report := RegistrationReport{
		GenericInvalidKeyTypes:       []string{"test.invalid.v1"},
		GenericExternalEditKeyTypes:  []string{"test.edited-generic.v1"},
		ComposedExternalEditKeyTypes: []string{"test.edited-composed.v1"},
		GenericOrphanedKeyTypes:      []string{"test.orphan-generic.v1"},
		ComposedOrphanedKeyTypes:     []string{"test.orphan-composed.v1"},
		DisabledOrphanedKeyTypes:     []string{"test.orphan-disabled.v1"},
		NamespaceDefects:             []NamespaceDefect{{Text: `unexpected entry "notes.txt"`, Entry: "notes.txt"}},
		// Registration-semantics outcomes are not content defects.
		GenericConflictingKeyTypes: []string{"test.conflict.v1"},
		GenericDisabledKeyTypes:    []string{"test.disabled.v1"},
	}
	wantDefects := []RecordDefect{
		{KeyType: "test.orphan-generic.v1", Kind: RecordOrphaned, TemplateType: templatestore.TemplateTypeGeneric},
		{KeyType: "test.orphan-composed.v1", Kind: RecordOrphaned, TemplateType: templatestore.TemplateTypeComposed},
		{KeyType: "test.edited-generic.v1", Kind: RecordExternalEdit, TemplateType: templatestore.TemplateTypeGeneric},
		{KeyType: "test.edited-composed.v1", Kind: RecordExternalEdit, TemplateType: templatestore.TemplateTypeComposed},
		{KeyType: "test.orphan-disabled.v1", Kind: RecordDisabledOrphaned},
	}
	if got := report.RecordDefects(); !reflect.DeepEqual(got, wantDefects) {
		t.Fatalf("RecordDefects() = %+v, want %+v", got, wantDefects)
	}
	all := []string{
		"test.invalid.v1",
		"test.orphan-generic.v1", "test.orphan-composed.v1",
		"test.edited-generic.v1", "test.edited-composed.v1",
		"test.orphan-disabled.v1",
		`unexpected entry "notes.txt"`,
	}
	if got := report.ContentDefectKeyTypes(); !reflect.DeepEqual(got, all) {
		t.Fatalf("ContentDefectKeyTypes() = %q, want %q", got, all)
	}
	repaired := map[string]bool{
		"test.edited-generic.v1": true, "test.orphan-disabled.v1": true,
		// A key type whose defect is not a record defect keeps it.
		"test.invalid.v1": true,
	}
	want := []ContentDefect{
		{Text: "test.invalid.v1"},
		{Text: "test.orphan-generic.v1"}, {Text: "test.orphan-composed.v1"},
		{Text: "test.edited-composed.v1"},
		{Text: `unexpected entry "notes.txt"`, Entry: "notes.txt"},
	}
	if got := report.ContentDefectsExcept(repaired); !reflect.DeepEqual(got, want) {
		t.Fatalf("ContentDefectsExcept() = %+v, want %+v", got, want)
	}
}
