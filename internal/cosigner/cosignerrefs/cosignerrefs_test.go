// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package cosignerrefs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/cosigner/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestImportGetListDelete(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	export := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))

	rec, err := Import(paths, "Lab-Cosigner", export)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if rec.Name != "lab-cosigner" {
		t.Fatalf("Name = %q, want normalized lab-cosigner", rec.Name)
	}
	if rec.Schema != RecordSchema {
		t.Fatalf("Schema = %q, want %q", rec.Schema, RecordSchema)
	}
	if rec.ImportedAt == "" {
		t.Fatal("ImportedAt is empty")
	}

	got, ok, err := Get(paths, "lab-cosigner")
	if err != nil || !ok {
		t.Fatalf("Get() = (%#v, %v, %v), want record", got, ok, err)
	}
	if got.PublicKeyHex != rec.PublicKeyHex {
		t.Fatalf("PublicKeyHex = %q, want %q", got.PublicKeyHex, rec.PublicKeyHex)
	}

	list, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 || list[0].Name != "lab-cosigner" {
		t.Fatalf("List() = %#v, want one lab-cosigner record", list)
	}

	removed, err := Delete(paths, "lab-cosigner")
	if err != nil || !removed {
		t.Fatalf("Delete() = (%v, %v), want removed", removed, err)
	}
	_, ok, err = Get(paths, "lab-cosigner")
	if err != nil || ok {
		t.Fatalf("Get(after delete) = (_, %v, %v), want absent", ok, err)
	}
}

func TestImportIsIdempotentAndRejectsNameReplacement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	firstExport := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))
	first, err := Import(paths, "prod-cosigner", firstExport)
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := Import(paths, "prod-cosigner", firstExport)
	if err != nil {
		t.Fatalf("identical Import() error = %v", err)
	}
	if idempotent.ComponentKey != first.ComponentKey || idempotent.ImportedAt != first.ImportedAt {
		t.Fatalf("identical Import() rewrote record: first=%#v second=%#v", first, idempotent)
	}

	secondExport := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xcd))
	_, err = Import(paths, "prod-cosigner", secondExport)
	if err == nil || !strings.Contains(err.Error(), "remove it explicitly") {
		t.Fatalf("replacement Import() error = %v, want explicit removal requirement", err)
	}
	stored, found, getErr := Get(paths, "prod-cosigner")
	if getErr != nil || !found {
		t.Fatalf("Get() after rejected replacement = (%#v, %v, %v)", stored, found, getErr)
	}
	if stored.ComponentKey != first.ComponentKey {
		t.Fatalf("stored Witness Key ID = %q, want original %q", stored.ComponentKey, first.ComponentKey)
	}
}

func TestImportRejectsMismatchedWitnessIdentity(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	publicKey := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	otherPublicKey := bytesOfLen(falconfamily.PublicKeySize, 0xcd)
	otherID, err := witness.ID(witness.Falcon1024V1, otherPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{
			name: "public key does not match Witness Key ID",
			mutate: func(envelope map[string]any) {
				envelope["witness_key_id"] = otherID
			},
			want: "does not match",
		},
		{
			name: "unsupported key type",
			mutate: func(envelope map[string]any) {
				const unsupported = "aplane.witness-unknown.v1"
				envelope["key_type"] = unsupported
				envelope["witness_key_id"] = witness.DeriveID(unsupported, publicKey)
			},
			want: "is not a witness key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var envelope map[string]any
			if err := json.Unmarshal(testExportJSON(t, witness.Falcon1024V1, publicKey), &envelope); err != nil {
				t.Fatal(err)
			}
			tt.mutate(envelope)
			data, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := Import(paths, "invalid", data); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Import() error = %v, want %q", err, tt.want)
			}
			if _, found, err := Get(paths, "invalid"); err != nil || found {
				t.Fatalf("invalid reference persisted: found=%v err=%v", found, err)
			}
		})
	}
}

func TestImportAllowsFormerEndpointDiscoveryNamespace(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	export := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))
	record, err := Import(paths, "endpoint-manual-planted", export)
	if err != nil {
		t.Fatalf("Import(endpoint-* name) error = %v", err)
	}
	if record.Name != "endpoint-manual-planted" {
		t.Fatalf("record name = %q", record.Name)
	}
}

func TestListSkipsInvalidReferenceRecordWithoutHidingValidReferences(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if _, err := Import(paths, "valid", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.CosignerRefsDir(), 0o700); err != nil {
		t.Fatalf("MkdirAll(cosigners) error = %v", err)
	}
	if err := os.WriteFile(paths.CosignerRefPath("bad"), []byte(`{"schema":"wrong"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(bad reference) error = %v", err)
	}

	records, err := List(paths)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(records) != 1 || records[0].Name != "valid" {
		t.Fatalf("List() = %#v, want only valid reference", records)
	}
	if _, _, err := Get(paths, "bad"); err == nil || !strings.Contains(err.Error(), "invalid cosigner reference bad") {
		t.Fatalf("Get(bad) error = %v, want explicit validation failure", err)
	}
}

func TestResolveCreationParamsUsesImportedReference(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	componentKey, err := witness.ID(witness.Falcon1024V1, pub)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	if _, err := Import(paths, "lab-cosigner", testExportJSON(t, witness.Falcon1024V1, pub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	resolved, err := ResolveCreationParams(paths, keytypes.GuardedFalcon1024Cosigner1024V1, map[string]string{
		ParamCosignerName: "lab-cosigner",
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams() error = %v", err)
	}
	if got := resolved[keytypes.ParameterCosignerPublicKey]; got != strings.Repeat("ab", falconfamily.PublicKeySize) {
		t.Fatalf("cosigner_public_key = %q, want imported public key", got)
	}
	if _, ok := resolved[ParamCosignerName]; ok {
		t.Fatalf("resolved params still contain %s: %#v", ParamCosignerName, resolved)
	}

	resolved, err = ResolveCreationParams(paths, keytypes.GuardedFalcon1024Cosigner1024V1, map[string]string{
		ParamCosignerName: componentKey,
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams(Witness Key ID) error = %v", err)
	}
	if got := resolved[keytypes.ParameterCosignerPublicKey]; got != strings.Repeat("ab", falconfamily.PublicKeySize) {
		t.Fatalf("Witness Key ID cosigner_public_key = %q, want imported public key", got)
	}
}

func TestResolveCreationParamsForBoundedProvider(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0x7c)
	if _, err := Import(paths, "bounded-cosigner", testExportJSON(t, witness.Falcon1024V1, pub)); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveCreationParamsForComponent(
		paths,

		"aplane.custom-bounded-cosigner.v1",
		witness.Falcon1024V1,
		map[string]string{ParamCosignerName: "bounded-cosigner", "limit": "10"},
	)
	if err != nil {
		t.Fatalf("ResolveCreationParamsForComponent() error = %v", err)
	}
	if got := resolved[keytypes.ParameterCosignerPublicKey]; got != strings.Repeat("7c", falconfamily.PublicKeySize) {
		t.Fatalf("cosigner_public_key = %q, want imported public key", got)
	}
	if resolved["limit"] != "10" {
		t.Fatalf("resolved params lost provider parameter: %#v", resolved)
	}
}

func TestResolveCreationParamsRejectsConflictingInputs(t *testing.T) {
	_, err := ResolveCreationParams(storepaths.NewPaths(t.TempDir()), keytypes.GuardedFalcon1024Cosigner1024V1, map[string]string{
		ParamCosignerName:                   "lab-cosigner",
		keytypes.ParameterCosignerPublicKey: strings.Repeat("ab", falconfamily.PublicKeySize),
	})
	if err == nil {
		t.Fatal("ResolveCreationParams() error = nil, want conflicting input rejection")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("ResolveCreationParams() error = %v, want not both", err)
	}
}

// Only the current record schema is read. Earlier schemas and their fields
// are rejected rather than migrated.
func TestGetRejectsRetiredSchemaAndFields(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	record, err := ParseImport("strict", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab)))
	if err != nil {
		t.Fatal(err)
	}
	record.ImportedAt = "2026-08-17T00:00:00Z"
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"v1 schema":        func(raw map[string]any) { raw["schema"] = "aplane.cosigner-public-key-ref.v1" },
		"source":           func(raw map[string]any) { raw["source"] = "discovery" },
		"migration_origin": func(raw map[string]any) { raw["migration_origin"] = "v1_client_discovery" },
	} {
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		mutate(raw)
		writeRawRecord(t, paths, "strict", raw)
		if _, _, err := Get(paths, "strict"); err == nil {
			t.Errorf("Get() accepted a record with a retired %s", name)
		}
	}
}

func writeRawRecord(t *testing.T, paths storepaths.Paths, name string, raw map[string]any) {
	t.Helper()
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	writeRawRecordBytes(t, paths, name, data)
}

func writeRawRecordBytes(t *testing.T, paths storepaths.Paths, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(paths.CosignerRefsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.CosignerRefPath(name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testExportJSON(t *testing.T, keyType string, pub []byte) []byte {
	t.Helper()
	componentKey, err := witness.ID(keyType, pub)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	env, err := NewExportEnvelope(componentKey, keyType, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("NewExportEnvelope() error = %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal(export) error = %v", err)
	}
	return data
}

func bytesOfLen(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}
