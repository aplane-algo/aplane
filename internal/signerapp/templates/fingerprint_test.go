// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templates

import (
	"errors"
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

func reloadServiceForFingerprintTest(paths utilkeys.Paths) *ReloadService {
	return &ReloadService{
		KeyStore:        &fakeKeyStore{cache: map[string]string{}, keyTypes: map[string]string{}},
		Session:         &fakeSession{},
		TemplateManager: NewManager(paths),
		PublishSnapshot: func(map[string]string, map[string]string) {},
		AuditLog:        &fakeAuditLog{},
		Info:            func(string) {},
		Warn:            func(string) {},
	}
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
		"unversioned":         {accepted, accepted},
		"version 0":           {accepted, accepted},
		"noncanonical prefix": {accepted, accepted},
		"cross-version":       {accepted, accepted},
		"malformed hash":      {accepted, accepted},
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
				t.Cleanup(func() { UnregisterProductProvider(keyType) })
				paths := mintedPathsForReloadTest(t)
				masterKey := testTemplateMasterKey()
				saveTemplateYAML(t, paths, keyType, templatestore.TemplateTypeGeneric, data, masterKey)
				if registered {
					putRecordedFingerprint(t, paths, keyType, keytypestate.SourceYAMLGeneric, live)
					if _, err := reloadServiceForFingerprintTest(paths).Reload(nil); err != nil {
						t.Fatalf("registering Reload() error = %v", err)
					}
				}
				putRecordedFingerprint(t, paths, keyType, keytypestate.SourceYAMLGeneric, recordedFingerprint(recordedName, live))

				report, err := reloadServiceForFingerprintTest(paths).Reload(nil)
				switch wantOutcome {
				case accepted:
					if err != nil {
						t.Fatalf("Reload() error = %v, want the record accepted", err)
					}
					bucket := report.GenericActivatedKeyTypes
					if registered {
						bucket = report.GenericIdempotentKeyTypes
					}
					if !reflect.DeepEqual(bucket, []string{keyType}) {
						t.Fatalf("report = %+v, want %s accepted", report.RegistrationReport, keyType)
					}
					if lsigprovider.Get(keyType) == nil {
						t.Fatalf("%s is not registered", keyType)
					}
				case externalEdit:
					if !errors.Is(err, ErrGenerationValidation) {
						t.Fatalf("Reload() error = %v, want ErrGenerationValidation", err)
					}
					wantErr := "generation validation failed: 0 malformed key file(s) and 1 template/key-type defect(s) in the selected generation: key type " + keyType
					if err.Error() != wantErr {
						t.Fatalf("Reload() error = %q, want %q", err, wantErr)
					}
					if report != nil {
						t.Fatalf("Reload() report = %+v, want none", report)
					}
					report, err := NewManager(paths).ValidateKeystoreTemplates(cryptotest.Keyring(t, masterKey))
					if err != nil {
						t.Fatalf("ValidateKeystoreTemplates() error = %v", err)
					}
					if !reflect.DeepEqual(report.GenericExternalEditKeyTypes, []string{keyType}) {
						t.Fatalf("GenericExternalEditKeyTypes = %v, want %s", report.GenericExternalEditKeyTypes, keyType)
					}
					wantWarning := "externally edited generic templates ignored on reload: [" + keyType + "] (reinstall via `apadmin template import`)"
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
	// Whether the record conflicts, with a provider that has a fingerprint and
	// with one that has none.
	cases := map[string]struct{ fingerprinted, none bool }{
		"matching":            {false, false},
		"nothing recorded":    {false, false},
		"mismatching":         {true, false},
		"unversioned":         {false, false},
		"version 0":           {false, false},
		"noncanonical prefix": {false, false},
		"cross-version":       {false, false},
		"malformed hash":      {false, false},
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

				report, err := reloadServiceForFingerprintTest(paths).Reload(nil)
				if err != nil {
					t.Fatalf("Reload() error = %v, want a compiled conflict not to fail reload", err)
				}
				if wantConflict {
					if !reflect.DeepEqual(report.CompiledConflictingKeyTypes, []string{keyType}) || len(report.CompiledIdempotentKeyTypes) != 0 {
						t.Fatalf("report = %+v, want %s conflicting", report.RegistrationReport, keyType)
					}
					wantWarning := "conflicting compiled key type records ignored on reload: [" + keyType + "] (restart apsigner to redefine)"
					if !reflect.DeepEqual(report.TemplateWarnings, []string{wantWarning}) {
						t.Fatalf("TemplateWarnings = %q, want %q", report.TemplateWarnings, wantWarning)
					}
					return
				}
				if !reflect.DeepEqual(report.CompiledIdempotentKeyTypes, []string{keyType}) || len(report.CompiledConflictingKeyTypes) != 0 {
					t.Fatalf("report = %+v, want %s consistent", report.RegistrationReport, keyType)
				}
				if len(report.TemplateWarnings) != 0 {
					t.Fatalf("TemplateWarnings = %q, want none", report.TemplateWarnings)
				}
			})
		}
	}
}
