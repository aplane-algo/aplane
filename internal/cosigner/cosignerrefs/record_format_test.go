// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cosignerrefs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

// An imported reference is stored as its public key, its type, and the
// Witness Key ID they derive, under its name and import time.
func TestImportStoresTheReferenceFields(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := Import(paths, "lab", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.CosignerRefPath("lab"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	var got []string
	for name := range fields {
		got = append(got, name)
	}
	slices.Sort(got)
	want := []string{"component_key", "imported_at", "key_type", "name", "public_key_hex", "schema"}
	if !slices.Equal(got, want) {
		t.Fatalf("stored fields = %v, want %v", got, want)
	}
}

// A stored record is checked as an import is: its Witness Key ID must derive
// from its type and public key, and only the record's own fields are read.
func TestGetRefusesARecordThatDoesNotHoldTogether(t *testing.T) {
	publicKey := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	otherID, err := witness.ID(witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xcd))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"another key's ID": {
			mutate: func(raw map[string]any) { raw["component_key"] = otherID },
			want:   "witness_key_id does not match key_type and public_key_hex",
		},
		"short public key": {
			mutate: func(raw map[string]any) {
				short := hex.EncodeToString(publicKey[:len(publicKey)-1])
				raw["public_key_hex"] = short
			},
			want: "witness public key length 1792 invalid",
		},
		"public key size": {
			mutate: func(raw map[string]any) { raw["public_key_size"] = len(publicKey) },
			want:   `unknown field "public_key_size"`,
		},
		"public key digest": {
			mutate: func(raw map[string]any) { raw["public_key_sha256"] = strings.Repeat("0", 64) },
			want:   `unknown field "public_key_sha256"`,
		},
		"public key encoding": {
			mutate: func(raw map[string]any) { raw["public_key_encoding"] = "hex" },
			want:   `unknown field "public_key_encoding"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			if _, err := Import(paths, "lab", testExportJSON(t, witness.Falcon1024V1, publicKey)); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(paths.CosignerRefPath("lab"))
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw)
			writeRawRecord(t, paths, "lab", raw)
			if _, _, err := Get(paths, "lab"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Get() error = %v, want %q", err, tc.want)
			}
		})
	}
}

// Import stamps every record with the time it was imported, so a record
// without that time, or with anything else in its place, is malformed.
func TestGetRefusesARecordWithoutItsImportTime(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"absent":     func(raw map[string]any) { delete(raw, "imported_at") },
		"empty":      func(raw map[string]any) { raw["imported_at"] = "" },
		"padded":     func(raw map[string]any) { raw["imported_at"] = " 2026-08-17T00:00:00Z" },
		"not a time": func(raw map[string]any) { raw["imported_at"] = "yesterday" },
	} {
		t.Run(name, func(t *testing.T) {
			paths := storepaths.NewPaths(t.TempDir())
			if _, err := Import(paths, "lab", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(paths.CosignerRefPath("lab"))
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			mutate(raw)
			writeRawRecord(t, paths, "lab", raw)
			if _, _, err := Get(paths, "lab"); err == nil || !strings.Contains(err.Error(), "is not an RFC 3339 time") {
				t.Fatalf("Get() error = %v, want the import time refused", err)
			}
		})
	}
}
