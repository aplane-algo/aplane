// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package templatelibrary

import (
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/crypto/cryptotest"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/keytypestate"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

const editedFingerprintForTest = "1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// installForRepairTest installs yaml and returns the generation it is in and
// the fingerprint the install recorded.
func installForRepairTest(t *testing.T, paths storepaths.Paths, yaml []byte) (storepaths.GenPaths, ParsedTemplate, string) {
	t.Helper()
	parsed := mustParseYAML(t, "source.yaml", yaml)
	if _, err := InstallParsed(paths, parsed, cryptotest.Keyring(t, testMasterKey())); err != nil {
		t.Fatalf("InstallParsed() error = %v", err)
	}
	active, err := genstore.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok, err := keytypestate.GetActive(active, parsed.KeyType)
	if err != nil || !ok {
		t.Fatalf("GetActive() = %v, %v", ok, err)
	}
	return active, parsed, rec.Fingerprint
}

func putRecordForRepairTest(t *testing.T, active storepaths.GenPaths, rec keytypestate.Record) {
	t.Helper()
	if err := keytypestate.PutActive(active, rec); err != nil {
		t.Fatal(err)
	}
}

// A re-pin rewrites the fingerprint to the one the stored template computes,
// which is the one an install records, and keeps the rest of the record.
func TestRepinTemplateRecordRewritesOnlyTheFingerprint(t *testing.T) {
	for _, tc := range []struct {
		name  string
		yaml  []byte
		state keytypestate.State
	}{
		{"generic", testGenericTemplateYAML("repin-generic", "Repin Generic"), keytypestate.StateEnabled},
		{"composed", testComposedTemplateYAML("repin-composed", "Repin Composed"), keytypestate.StateEnabled},
		{"disabled generic", testGenericTemplateYAML("repin-disabled", "Repin Disabled"), keytypestate.StateDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths := newLibraryTestPaths(t)
			kr := cryptotest.Keyring(t, testMasterKey())
			active, parsed, installed := installForRepairTest(t, paths, tc.yaml)
			rec, _, err := keytypestate.GetActive(active, parsed.KeyType)
			if err != nil {
				t.Fatal(err)
			}
			rec.Fingerprint = editedFingerprintForTest
			rec.State = tc.state
			rec.ActivatedAt = "2026-01-02T03:04:05Z"
			putRecordForRepairTest(t, active, rec)

			stored, err := StoredTemplateFingerprintActive(active, parsed.KeyType, parsed.TemplateType, kr)
			if err != nil || stored != installed {
				t.Fatalf("StoredTemplateFingerprintActive() = %q, %v; want the installed %q", stored, err, installed)
			}
			repinned, err := RepinTemplateRecordActive(active, parsed.KeyType, kr)
			if err != nil {
				t.Fatalf("RepinTemplateRecordActive() error = %v", err)
			}
			want := rec
			want.Fingerprint = installed
			if repinned != want {
				t.Fatalf("RepinTemplateRecordActive() = %+v, want %+v", repinned, want)
			}
			if got, _, err := keytypestate.GetActive(active, parsed.KeyType); err != nil || got != want {
				t.Fatalf("record after re-pin = %+v, %v; want %+v", got, err, want)
			}
		})
	}
}

// The trust a re-pin places in the stored template rests on its envelope:
// it is sealed for one key type, so another key type's template, copied into
// its place, does not open.
func TestStoredTemplateFingerprintIsBoundToItsKeyType(t *testing.T) {
	paths := newLibraryTestPaths(t)
	kr := cryptotest.Keyring(t, testMasterKey())
	active, first, _ := installForRepairTest(t, paths, testGenericTemplateYAML("repin-bound-a", "Repin Bound A"))
	_, second, _ := installForRepairTest(t, paths, testGenericTemplateYAML("repin-bound-b", "Repin Bound B"))
	data, err := os.ReadFile(active.KeyTypeTemplate(first.KeyType))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active.KeyTypeTemplate(second.KeyType), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StoredTemplateFingerprintActive(active, second.KeyType, second.TemplateType, kr); err == nil {
		t.Fatal("StoredTemplateFingerprintActive() opened another key type's template")
	}
	before, _, err := keytypestate.GetActive(active, second.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RepinTemplateRecordActive(active, second.KeyType, kr); err == nil {
		t.Fatal("RepinTemplateRecordActive() pinned another key type's template")
	}
	if after, _, err := keytypestate.GetActive(active, second.KeyType); err != nil || after != before {
		t.Fatalf("record after a refused re-pin = %+v, %v; want %+v", after, err, before)
	}
}

func TestRepinTemplateRecordRefusesWhatItCannotPin(t *testing.T) {
	paths := newLibraryTestPaths(t)
	kr := cryptotest.Keyring(t, testMasterKey())
	active, err := genstore.Resolve(paths)
	if err != nil {
		t.Fatal(err)
	}
	putRecordForRepairTest(t, active, keytypestate.Record{
		KeyType: "test.repin-orphan.v1", Source: keytypestate.SourceYAMLGeneric, State: keytypestate.StateEnabled,
	})
	putRecordForRepairTest(t, active, keytypestate.Record{
		KeyType: "test.repin-compiled.v1", Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled,
	})
	for keyType, want := range map[string]string{
		"test.repin-orphan.v1":   "fingerprint the installed template",
		"test.repin-compiled.v1": "not a YAML template record",
		"test.repin-absent.v1":   "has no state record",
	} {
		if _, err := RepinTemplateRecordActive(active, keyType, kr); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("RepinTemplateRecordActive(%s) error = %v, want %q", keyType, err, want)
		}
	}
}

// A drop removes the record. A template file it finds goes to the deleted
// archive, as a template removal moves it; with none, only the record goes.
func TestDropTemplateRecord(t *testing.T) {
	t.Run("with its template", func(t *testing.T) {
		paths := newLibraryTestPaths(t)
		active, parsed, _ := installForRepairTest(t, paths, testComposedTemplateYAML("drop-edited", "Drop Edited"))
		archived, err := DropTemplateRecordActive(active, parsed.KeyType)
		if err != nil {
			t.Fatalf("DropTemplateRecordActive() error = %v", err)
		}
		if archived != active.DeletedKeyTypeTemplate(parsed.KeyType) {
			t.Fatalf("DropTemplateRecordActive() = %q, want %q", archived, active.DeletedKeyTypeTemplate(parsed.KeyType))
		}
		if _, err := os.Stat(archived); err != nil {
			t.Fatalf("archived template: %v", err)
		}
		if _, err := os.Stat(active.KeyTypeTemplate(parsed.KeyType)); !os.IsNotExist(err) {
			t.Fatalf("installed template after drop: %v, want gone", err)
		}
		if _, ok, err := keytypestate.GetActive(active, parsed.KeyType); ok || err != nil {
			t.Fatalf("record after drop = %v, %v; want gone", ok, err)
		}
	})
	t.Run("without a template file", func(t *testing.T) {
		paths := newLibraryTestPaths(t)
		active, err := genstore.Resolve(paths)
		if err != nil {
			t.Fatal(err)
		}
		const keyType = "test.drop-orphan.v1"
		putRecordForRepairTest(t, active, keytypestate.Record{
			KeyType: keyType, Source: keytypestate.SourceYAMLComposed, State: keytypestate.StateDisabled,
		})
		archived, err := DropTemplateRecordActive(active, keyType)
		if err != nil || archived != "" {
			t.Fatalf("DropTemplateRecordActive() = %q, %v; want no archive", archived, err)
		}
		if _, ok, err := keytypestate.GetActive(active, keyType); ok || err != nil {
			t.Fatalf("record after drop = %v, %v; want gone", ok, err)
		}
		entries, err := os.ReadDir(active.DeletedKeyTypeRecordsDir())
		if err != nil || len(entries) != 0 {
			t.Fatalf("deleted key type archive = %v, %v; want empty", entries, err)
		}
	})
	t.Run("refuses a compiled record", func(t *testing.T) {
		paths := newLibraryTestPaths(t)
		active, err := genstore.Resolve(paths)
		if err != nil {
			t.Fatal(err)
		}
		const keyType = "test.drop-compiled.v1"
		putRecordForRepairTest(t, active, keytypestate.Record{
			KeyType: keyType, Source: keytypestate.SourceCompiled, State: keytypestate.StateEnabled,
		})
		if _, err := DropTemplateRecordActive(active, keyType); err == nil || !strings.Contains(err.Error(), "not a YAML template record") {
			t.Fatalf("DropTemplateRecordActive() error = %v, want a refusal", err)
		}
		if _, ok, err := keytypestate.GetActive(active, keyType); !ok || err != nil {
			t.Fatalf("compiled record after a refused drop = %v, %v; want kept", ok, err)
		}
	})
}
