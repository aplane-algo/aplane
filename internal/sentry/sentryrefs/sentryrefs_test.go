// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package sentryrefs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/witness"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestImportGetListDelete(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	export := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))

	rec, err := Import(paths, "default", "Lab-Sentry", export)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if rec.Name != "lab-sentry" {
		t.Fatalf("Name = %q, want normalized lab-sentry", rec.Name)
	}
	if rec.Schema != RecordSchema {
		t.Fatalf("Schema = %q, want %q", rec.Schema, RecordSchema)
	}
	if rec.ImportedAt == "" {
		t.Fatal("ImportedAt is empty")
	}

	got, ok, err := Get(paths, "default", "lab-sentry")
	if err != nil || !ok {
		t.Fatalf("Get() = (%#v, %v, %v), want record", got, ok, err)
	}
	if got.PublicKeyHex != rec.PublicKeyHex {
		t.Fatalf("PublicKeyHex = %q, want %q", got.PublicKeyHex, rec.PublicKeyHex)
	}

	list, err := List(paths, "default")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(list) != 1 || list[0].Name != "lab-sentry" {
		t.Fatalf("List() = %#v, want one lab-sentry record", list)
	}

	removed, err := Delete(paths, "default", "lab-sentry")
	if err != nil || !removed {
		t.Fatalf("Delete() = (%v, %v), want removed", removed, err)
	}
	_, ok, err = Get(paths, "default", "lab-sentry")
	if err != nil || ok {
		t.Fatalf("Get(after delete) = (_, %v, %v), want absent", ok, err)
	}
}

func TestImportIsIdempotentAndRejectsNameReplacement(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	firstExport := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))
	first, err := Import(paths, "default", "prod-sentry", firstExport)
	if err != nil {
		t.Fatal(err)
	}
	idempotent, err := Import(paths, "default", "prod-sentry", firstExport)
	if err != nil {
		t.Fatalf("identical Import() error = %v", err)
	}
	if idempotent.ComponentKey != first.ComponentKey || idempotent.ImportedAt != first.ImportedAt {
		t.Fatalf("identical Import() rewrote record: first=%#v second=%#v", first, idempotent)
	}

	secondExport := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xcd))
	_, err = Import(paths, "default", "prod-sentry", secondExport)
	if err == nil || !strings.Contains(err.Error(), "remove it explicitly") {
		t.Fatalf("replacement Import() error = %v, want explicit removal requirement", err)
	}
	stored, found, getErr := Get(paths, "default", "prod-sentry")
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

			if _, err := Import(paths, "default", "invalid", data); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Import() error = %v, want %q", err, tt.want)
			}
			if _, found, err := Get(paths, "default", "invalid"); err != nil || found {
				t.Fatalf("invalid reference persisted: found=%v err=%v", found, err)
			}
		})
	}
}

func TestImportAllowsFormerEndpointDiscoveryNamespace(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	export := testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))
	record, err := Import(paths, "default", "endpoint-manual-planted", export)
	if err != nil {
		t.Fatalf("Import(endpoint-* name) error = %v", err)
	}
	if record.Name != "endpoint-manual-planted" {
		t.Fatalf("record name = %q", record.Name)
	}
}

func TestListRejectsInvalidReferenceRecord(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.SentryRefsDir("default"), 0o700); err != nil {
		t.Fatalf("MkdirAll(sentries) error = %v", err)
	}
	if err := os.WriteFile(paths.SentryRefPath("default", "bad"), []byte(`{"schema":"wrong"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(bad reference) error = %v", err)
	}

	_, err := List(paths, "default")
	if err == nil {
		t.Fatal("List() error = nil, want invalid reference rejection")
	}
	if !strings.Contains(err.Error(), "invalid sentry reference bad") {
		t.Fatalf("List() error = %v, want invalid reference context", err)
	}
}

func TestResolveCreationParamsUsesImportedReference(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	componentKey, err := witness.ID(witness.Falcon1024V1, pub)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	if _, err := Import(paths, "default", "lab-sentry", testExportJSON(t, witness.Falcon1024V1, pub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	resolved, err := ResolveCreationParams(paths, "default", keytypes.GuardedFalcon1024Sentry1024V1, map[string]string{
		ParamSentryName: "lab-sentry",
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams() error = %v", err)
	}
	if got := resolved[keytypes.ParameterSentryPublicKey]; got != strings.Repeat("ab", falconfamily.PublicKeySize) {
		t.Fatalf("sentry_public_key = %q, want imported public key", got)
	}
	if _, ok := resolved[ParamSentryName]; ok {
		t.Fatalf("resolved params still contain %s: %#v", ParamSentryName, resolved)
	}

	resolved, err = ResolveCreationParams(paths, "default", keytypes.GuardedFalcon1024Sentry1024V1, map[string]string{
		ParamSentryName: componentKey,
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams(Witness Key ID) error = %v", err)
	}
	if got := resolved[keytypes.ParameterSentryPublicKey]; got != strings.Repeat("ab", falconfamily.PublicKeySize) {
		t.Fatalf("Witness Key ID sentry_public_key = %q, want imported public key", got)
	}
}

func TestResolveCreationParamsForBoundedProvider(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0x7c)
	if _, err := Import(paths, "default", "bounded-sentry", testExportJSON(t, witness.Falcon1024V1, pub)); err != nil {
		t.Fatal(err)
	}
	resolved, err := ResolveCreationParamsForComponent(
		paths,
		"default",
		"aplane.custom-bounded-sentry.v1",
		witness.Falcon1024V1,
		map[string]string{ParamSentryName: "bounded-sentry", "limit": "10"},
	)
	if err != nil {
		t.Fatalf("ResolveCreationParamsForComponent() error = %v", err)
	}
	if got := resolved[keytypes.ParameterSentryPublicKey]; got != strings.Repeat("7c", falconfamily.PublicKeySize) {
		t.Fatalf("sentry_public_key = %q, want imported public key", got)
	}
	if resolved["limit"] != "10" {
		t.Fatalf("resolved params lost provider parameter: %#v", resolved)
	}
}

func TestResolveCreationParamsRejectsConflictingInputs(t *testing.T) {
	_, err := ResolveCreationParams(storepaths.NewPaths(t.TempDir()), "default", keytypes.GuardedFalcon1024Sentry1024V1, map[string]string{
		ParamSentryName:                   "lab-sentry",
		keytypes.ParameterSentryPublicKey: strings.Repeat("ab", falconfamily.PublicKeySize),
	})
	if err == nil {
		t.Fatal("ResolveCreationParams() error = nil, want conflicting input rejection")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("ResolveCreationParams() error = %v, want not both", err)
	}
}

func TestGetMigratesV1ManualRecordToV2(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	writeV1Record(t, paths, "default", "manual-v1", recordSourceManualV1)

	record, found, err := Get(paths, "default", "manual-v1")
	if err != nil || !found {
		t.Fatalf("Get() = (%#v, %v, %v)", record, found, err)
	}
	if record.Schema != RecordSchema || record.MigrationOrigin != "" {
		t.Fatalf("migrated record = %#v", record)
	}
	assertStoredV2Record(t, paths, "default", "manual-v1", "")
}

func TestGetMigratesV1DiscoveryRecordToPinnedV2(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	writeV1Record(t, paths, "default", "endpoint-old", recordSourceDiscoveryV1)

	record, found, err := Get(paths, "default", "endpoint-old")
	if err != nil || !found {
		t.Fatalf("Get() = (%#v, %v, %v)", record, found, err)
	}
	if record.Schema != RecordSchema || record.Name != "endpoint-old" || record.MigrationOrigin != MigrationOriginV1ClientDiscovery {
		t.Fatalf("migrated record = %#v", record)
	}
	assertStoredV2Record(t, paths, "default", "endpoint-old", MigrationOriginV1ClientDiscovery)

	identical, err := Import(paths, "default", "endpoint-old", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab)))
	if err != nil {
		t.Fatalf("identical Import() error = %v", err)
	}
	if identical.MigrationOrigin != MigrationOriginV1ClientDiscovery {
		t.Fatalf("identical import erased migration marker: %#v", identical)
	}
}

func TestV2RejectsRetiredDiscoveryFieldsAndUnknownMigrationOrigin(t *testing.T) {
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
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["source"] = recordSourceDiscoveryV1
	writeRawRecord(t, paths, "default", "strict", raw)
	if _, _, err := Get(paths, "default", "strict"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Get(v2 source) error = %v, want unknown-field rejection", err)
	}

	delete(raw, "source")
	raw["migration_origin"] = "future"
	writeRawRecord(t, paths, "default", "strict", raw)
	if _, _, err := Get(paths, "default", "strict"); err == nil || !strings.Contains(err.Error(), "unsupported sentry reference migration_origin") {
		t.Fatalf("Get(unknown migration origin) error = %v", err)
	}
}

func TestV2PreservesClosedMigrationMarker(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	record, err := ParseImport("preserved", testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab)))
	if err != nil {
		t.Fatal(err)
	}
	record.MigrationOrigin = MigrationOriginV1ClientDiscovery
	if err := putRecord(paths, "default", *record); err != nil {
		t.Fatal(err)
	}
	got, found, err := Get(paths, "default", "preserved")
	if err != nil || !found || got.MigrationOrigin != MigrationOriginV1ClientDiscovery {
		t.Fatalf("Get() = (%#v, %v, %v)", got, found, err)
	}
}

func writeV1Record(t *testing.T, paths storepaths.Paths, identityID, name, source string) {
	t.Helper()
	record, err := ParseImport(name, testExportJSON(t, witness.Falcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab)))
	if err != nil {
		t.Fatal(err)
	}
	legacy := recordV1{
		Schema:            recordSchemaV1,
		Name:              record.Name,
		ComponentKey:      record.ComponentKey,
		KeyType:           record.KeyType,
		PublicKeyEncoding: record.PublicKeyEncoding,
		PublicKeyHex:      record.PublicKeyHex,
		PublicKeySize:     record.PublicKeySize,
		PublicKeySHA256:   record.PublicKeySHA256,
		Source:            source,
		EndpointAlias:     "sentry-old",
		LastSeenAt:        "2026-06-04T00:00:00Z",
		SyncedAt:          "2026-06-04T00:01:00Z",
		ImportedAt:        record.ImportedAt,
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	writeRawRecordBytes(t, paths, identityID, name, data)
}

func assertStoredV2Record(t *testing.T, paths storepaths.Paths, identityID, name, migrationOrigin string) {
	t.Helper()
	data, err := os.ReadFile(paths.SentryRefPath(identityID, name))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"schema": "`+RecordSchema+`"`) || strings.Contains(text, `"source"`) || strings.Contains(text, `"endpoint_alias"`) {
		t.Fatalf("stored migration = %s", text)
	}
	if migrationOrigin != "" && !strings.Contains(text, `"migration_origin": "`+migrationOrigin+`"`) {
		t.Fatalf("stored migration lacks marker: %s", text)
	}
}

func writeRawRecord(t *testing.T, paths storepaths.Paths, identityID, name string, raw map[string]any) {
	t.Helper()
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	writeRawRecordBytes(t, paths, identityID, name, data)
}

func writeRawRecordBytes(t *testing.T, paths storepaths.Paths, identityID, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(paths.SentryRefsDir(identityID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.SentryRefPath(identityID, name), data, 0o600); err != nil {
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
