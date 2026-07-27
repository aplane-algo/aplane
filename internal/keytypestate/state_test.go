// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package keytypestate

import (
	"errors"
	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/genstore/genstoretest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/keytypecatalog"
	"github.com/aplane-algo/aplane/internal/storepaths"
)

func TestPutGetListAndListEnabled(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")

	if err := Put(paths, "default", Record{
		KeyType:     "APlane.Falcon1024_Allowlist.v1",
		Source:      SourceYAMLComposed,
		State:       StateEnabled,
		Fingerprint: "fp1",
	}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := Put(paths, "default", Record{
		KeyType: "Hidden-v1",
		Source:  SourceYAMLGeneric,
		State:   StateDisabled,
	}); err != nil {
		t.Fatalf("Put(disabled) error = %v", err)
	}

	rec, ok, err := Get(paths, "default", "aplane.falcon1024_allowlist.v1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() ok = false, want true")
	}
	if rec.KeyType != "aplane.falcon1024_allowlist.v1" || rec.Source != SourceYAMLComposed || rec.State != StateEnabled || rec.Fingerprint != "fp1" {
		t.Fatalf("Get() = %+v, want normalized enabled composed record", rec)
	}
	if rec.ActivatedAt == "" {
		t.Fatal("ActivatedAt = empty, want auto-populated timestamp")
	}

	records, err := List(paths, "default")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got := keyTypesOf(records); strings.Join(got, ",") != "aplane.falcon1024_allowlist.v1,hidden-v1" {
		t.Fatalf("List() key types = %v, want sorted records", got)
	}

	enabled, err := ListEnabled(paths, "default")
	if err != nil {
		t.Fatalf("ListEnabled() error = %v", err)
	}
	if len(enabled) != 1 || enabled[0] != "aplane.falcon1024_allowlist.v1" {
		t.Fatalf("ListEnabled() = %v, want only enabled key type", enabled)
	}
}

func TestSetStatePreservesOtherFields(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	rec := Record{
		KeyType:     "custom-v1",
		Source:      SourceYAMLGeneric,
		State:       StateEnabled,
		Fingerprint: "fp1",
		ActivatedAt: "2026-05-09T12:34:56Z",
	}
	if err := Put(paths, "default", rec); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := SetState(paths, "default", "custom-v1", StateDisabled); err != nil {
		t.Fatalf("SetState() error = %v", err)
	}
	got, ok, err := Get(paths, "default", "custom-v1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok {
		t.Fatal("Get() ok = false, want true")
	}
	if got.State != StateDisabled || got.Source != rec.Source || got.Fingerprint != rec.Fingerprint || got.ActivatedAt != rec.ActivatedAt {
		t.Fatalf("record after SetState = %+v, want only state changed", got)
	}
}

func TestDeleteIsIdempotent(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	if err := Put(paths, "default", Record{KeyType: "custom-v1", Source: SourceCompiled, State: StateEnabled}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	if err := Delete(paths, "default", "custom-v1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if err := Delete(paths, "default", "custom-v1"); err != nil {
		t.Fatalf("Delete(second) error = %v", err)
	}
	_, ok, err := Get(paths, "default", "custom-v1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if ok {
		t.Fatal("Get() ok = true after Delete, want false")
	}
}

func TestGetDistinguishesMissingFromMalformed(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	if _, ok, err := Get(paths, "default", "missing-v1"); err != nil || ok {
		t.Fatalf("Get(missing) = ok %v err %v, want absent without error", ok, err)
	}

	path := mustActive(t, paths).KeyTypeRecord("bad-v1")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("WriteFile(empty) error = %v", err)
	}
	if _, ok, err := Get(paths, "default", "bad-v1"); err == nil || ok {
		t.Fatalf("Get(empty) = ok %v err %v, want corruption error", ok, err)
	}

	if err := os.WriteFile(path, []byte(`{"key_type":"bad-v1","source":"unknown","state":"enabled"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(invalid source) error = %v", err)
	}
	if _, ok, err := Get(paths, "default", "bad-v1"); err == nil || ok {
		t.Fatalf("Get(invalid source) = ok %v err %v, want corruption error", ok, err)
	}
}

func TestListEnabledSurfacesMalformedRecord(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	if err := Put(paths, "default", Record{KeyType: "good-v1", Source: SourceCompiled, State: StateEnabled}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	path := mustActive(t, paths).KeyTypeRecord("bad-v1")
	if err := os.WriteFile(path, []byte(`{bad`), 0o600); err != nil {
		t.Fatalf("WriteFile(bad record) error = %v", err)
	}

	enabled, err := ListEnabled(paths, "default")
	if err == nil {
		t.Fatalf("ListEnabled() = %v, nil; want corruption error", enabled)
	}
	if !strings.Contains(err.Error(), "bad-v1") {
		t.Fatalf("ListEnabled() error = %v, want corrupt key type name", err)
	}
}

func TestRejectsUnsafeKeyType(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	for _, keyType := range []string{"", "../bad", "bad/name", "bad\\name", "bad\x00name", "bad:name", "bad..name"} {
		if err := Put(paths, "default", Record{KeyType: keyType, Source: SourceCompiled, State: StateEnabled}); err == nil {
			t.Fatalf("Put(%q) error = nil, want invalid key type", keyType)
		}
		if _, _, err := Get(paths, "default", keyType); err == nil {
			t.Fatalf("Get(%q) error = nil, want invalid key type", keyType)
		}
	}
}

func TestRequireUnusedRejectsKeyTypeInUse(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	masterKey := []byte("01234567890123456789012345678901")
	bytecode := []byte{0x26, 0x01, 0x01, 0x05, 0x81, 0x01}
	payload := apkeys.NewDSALSigPayload("custom-v1", "custom-v1", []byte{0x01}, []byte{0x02}, nil, bytecode, 5, "", nil, "")
	defer payload.ZeroSecrets()
	if _, err := apkeys.SavePayload(paths, "default", payload, masterKey); err != nil {
		t.Fatalf("SavePayload() error = %v", err)
	}

	err := RequireUnused(paths, "default", "custom-v1", masterKey)
	if err == nil {
		t.Fatal("RequireUnused() error = nil, want in-use rejection")
	}
	if !errors.Is(err, ErrKeyTypeInUse) {
		t.Fatalf("RequireUnused() error = %v, want ErrKeyTypeInUse", err)
	}
	if !strings.Contains(err.Error(), "key(s) still use it") {
		t.Fatalf("RequireUnused() error = %v, want key count context", err)
	}
}

func TestCanGenerate(t *testing.T) {
	defaultKeyType := "keytypestate-default-v1"
	keytypecatalog.Register(keytypecatalog.Entry{
		KeyType:      defaultKeyType,
		Family:       "keytypestate-default",
		Availability: keytypecatalog.AvailabilityDefaultEnabled,
	})

	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	ok, err := CanGenerate(paths, "default", defaultKeyType)
	if err != nil {
		t.Fatalf("CanGenerate(default) error = %v", err)
	}
	if !ok {
		t.Fatal("CanGenerate(default) = false, want true")
	}

	if err := Put(paths, "default", Record{KeyType: "custom-v1", Source: SourceYAMLGeneric, State: StateEnabled}); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	ok, err = CanGenerate(paths, "default", "custom-v1")
	if err != nil {
		t.Fatalf("CanGenerate(custom) error = %v", err)
	}
	if !ok {
		t.Fatal("CanGenerate(custom) = false, want true")
	}

	if err := os.WriteFile(mustActive(t, paths).KeyTypeRecord("bad-v1"), []byte(`{bad`), 0o600); err != nil {
		t.Fatalf("WriteFile(bad record) error = %v", err)
	}
	if ok, err = CanGenerate(paths, "default", "bad-v1"); err == nil || ok {
		t.Fatalf("CanGenerate(bad) = %v, %v; want storage error", ok, err)
	}
}

func TestCanGenerateLifecycleMatrix(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		setup   func(t *testing.T, paths storepaths.Paths)
		want    bool
		wantErr bool
	}{
		{
			name:    "default-enabled compiled key type is generatable without state",
			keyType: "keytypestate-matrix-default-v1",
			setup: func(t *testing.T, _ storepaths.Paths) {
				t.Helper()
				keytypecatalog.Register(keytypecatalog.Entry{
					KeyType:      "keytypestate-matrix-default-v1",
					Family:       "keytypestate-matrix-default",
					Availability: keytypecatalog.AvailabilityDefaultEnabled,
				})
			},
			want: true,
		},
		{
			name:    "library-visible compiled key type is not generatable before activation",
			keyType: "keytypestate-matrix-library-v1",
			setup: func(t *testing.T, _ storepaths.Paths) {
				t.Helper()
				keytypecatalog.Register(keytypecatalog.Entry{
					KeyType:      "keytypestate-matrix-library-v1",
					Family:       "keytypestate-matrix-library",
					Availability: keytypecatalog.AvailabilityLibrary,
				})
			},
		},
		{
			name:    "activated compiled key type is generatable",
			keyType: "keytypestate-matrix-compiled-enabled-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				if err := Put(paths, "default", Record{
					KeyType: "keytypestate-matrix-compiled-enabled-v1",
					Source:  SourceCompiled,
					State:   StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
			want: true,
		},
		{
			name:    "disabled compiled key type is not generatable",
			keyType: "keytypestate-matrix-compiled-disabled-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				if err := Put(paths, "default", Record{
					KeyType: "keytypestate-matrix-compiled-disabled-v1",
					Source:  SourceCompiled,
					State:   StateDisabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
		},
		{
			name:    "enabled generic template is generatable",
			keyType: "keytypestate-matrix-generic-enabled-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				if err := Put(paths, "default", Record{
					KeyType: "keytypestate-matrix-generic-enabled-v1",
					Source:  SourceYAMLGeneric,
					State:   StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
			want: true,
		},
		{
			name:    "disabled generic template is not generatable",
			keyType: "keytypestate-matrix-generic-disabled-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				if err := Put(paths, "default", Record{
					KeyType: "keytypestate-matrix-generic-disabled-v1",
					Source:  SourceYAMLGeneric,
					State:   StateDisabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
		},
		{
			name:    "enabled composed template is generatable",
			keyType: "keytypestate-matrix-composed-enabled-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				if err := Put(paths, "default", Record{
					KeyType: "keytypestate-matrix-composed-enabled-v1",
					Source:  SourceYAMLComposed,
					State:   StateEnabled,
				}); err != nil {
					t.Fatalf("Put() error = %v", err)
				}
			},
			want: true,
		},
		{
			name:    "enabled state for another identity is not generatable",
			keyType: "keytypestate-matrix-cross-identity-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				genstoretest.MintFirst(t, paths, "alice")
				if err := Put(paths, "alice", Record{
					KeyType: "keytypestate-matrix-cross-identity-v1",
					Source:  SourceYAMLGeneric,
					State:   StateEnabled,
				}); err != nil {
					t.Fatalf("Put(alice) error = %v", err)
				}
			},
		},
		{
			name:    "corrupt state record surfaces storage error",
			keyType: "keytypestate-matrix-corrupt-v1",
			setup: func(t *testing.T, paths storepaths.Paths) {
				t.Helper()
				path := mustActive(t, paths).KeyTypeRecord("keytypestate-matrix-corrupt-v1")
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatalf("MkdirAll() error = %v", err)
				}
				if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			genstoretest.MintFirst(t, paths, "default")
			tt.setup(t, paths)

			got, err := CanGenerate(paths, "default", tt.keyType)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CanGenerate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("CanGenerate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompareForReload(t *testing.T) {
	fp := "1:" + strings.Repeat("a", 64)
	other := "1:" + strings.Repeat("b", 64)
	fpV2 := "2:" + strings.Repeat("a", 64)
	tests := []struct {
		name                string
		rec                 Record
		fileFingerprint     string
		registryFingerprint string
		want                ReloadOutcome
	}{
		{
			name:            "empty record fingerprint registers",
			rec:             Record{Source: SourceYAMLGeneric},
			fileFingerprint: fp,
			want:            OutcomeRegister,
		},
		{
			name:            "record matches file and empty registry registers",
			rec:             Record{Source: SourceYAMLGeneric, Fingerprint: fp},
			fileFingerprint: fp,
			want:            OutcomeRegister,
		},
		{
			name:                "all fingerprints match idempotent",
			rec:                 Record{Source: SourceYAMLGeneric, Fingerprint: fp},
			fileFingerprint:     fp,
			registryFingerprint: fp,
			want:                OutcomeIdempotent,
		},
		{
			name:                "registry differs conflicts",
			rec:                 Record{Source: SourceYAMLGeneric, Fingerprint: fp},
			fileFingerprint:     fp,
			registryFingerprint: other,
			want:                OutcomeConflict,
		},
		{
			name:                "file differs external edit",
			rec:                 Record{Source: SourceYAMLGeneric, Fingerprint: fp},
			fileFingerprint:     other,
			registryFingerprint: fp,
			want:                OutcomeExternalEdit,
		},
		{
			name: "missing yaml file orphaned",
			rec:  Record{Source: SourceYAMLComposed, Fingerprint: fp},
			want: OutcomeOrphanedRecord,
		},
		{
			name:                "compiled skips file column",
			rec:                 Record{Source: SourceCompiled, Fingerprint: fp},
			registryFingerprint: fp,
			want:                OutcomeIdempotent,
		},
		{
			name:                "cross-version registry not a conflict",
			rec:                 Record{Source: SourceCompiled, Fingerprint: fp},
			registryFingerprint: fpV2,
			want:                OutcomeRegister,
		},
		{
			name:                "cross-version file is not an external edit",
			rec:                 Record{Source: SourceYAMLGeneric, Fingerprint: fp},
			fileFingerprint:     fpV2,
			registryFingerprint: fp,
			want:                OutcomeIdempotent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareForReload(tt.rec, tt.fileFingerprint, tt.registryFingerprint); got != tt.want {
				t.Fatalf("CompareForReload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConcurrentReadAndWriteConverges(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	genstoretest.MintFirst(t, paths, "default")
	rec := Record{KeyType: "custom-v1", Source: SourceCompiled, State: StateEnabled, Fingerprint: "initial"}
	if err := Put(paths, "default", rec); err != nil {
		t.Fatalf("Put(initial) error = %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 25; i++ {
			_, _, _ = Get(paths, "default", "custom-v1")
		}
	}()
	go func() {
		defer wg.Done()
		rec.Fingerprint = "updated"
		if err := Put(paths, "default", rec); err != nil {
			t.Errorf("Put(updated) error = %v", err)
		}
	}()
	wg.Wait()

	got, ok, err := Get(paths, "default", "custom-v1")
	if err != nil {
		t.Fatalf("Get(final) error = %v", err)
	}
	if !ok || got.Fingerprint != "updated" {
		t.Fatalf("final record = %+v ok %v, want updated record", got, ok)
	}
}

func keyTypesOf(records []Record) []string {
	out := make([]string, len(records))
	for i, rec := range records {
		out[i] = rec.KeyType
	}
	return out
}

func mustActive(t *testing.T, paths storepaths.Paths) storepaths.ActivePaths {
	t.Helper()
	active, err := genstore.ResolveActive(paths, "default")
	if err != nil {
		t.Fatalf("ResolveActive: %v", err)
	}
	return active
}
