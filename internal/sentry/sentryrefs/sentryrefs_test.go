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
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestImportGetListDelete(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	export := testExportJSON(t, keytypes.SentryComponentFalcon1024V1, bytesOfLen(falconfamily.PublicKeySize, 0xab))

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
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	if _, err := Import(paths, "default", "lab-sentry", testExportJSON(t, keytypes.SentryComponentFalcon1024V1, pub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	resolved, err := ResolveCreationParams(paths, "default", keytypes.GuardedFalcon1024SentryFalcon1024V1, map[string]string{
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

	resolved, err = ResolveCreationParams(paths, "default", keytypes.GuardedFalcon1024SentryFalcon1024V1, map[string]string{
		ParamSentryName: componentKey,
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams(Sentry Key ID) error = %v", err)
	}
	if got := resolved[keytypes.ParameterSentryPublicKey]; got != strings.Repeat("ab", falconfamily.PublicKeySize) {
		t.Fatalf("Sentry Key ID sentry_public_key = %q, want imported public key", got)
	}
}

func TestResolveCreationParamsPreservesCorridorRecipients(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xcd)
	if _, err := Import(paths, "default", "falcon-sentry", testExportJSON(t, keytypes.SentryComponentFalcon1024V1, pub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	resolved, err := ResolveCreationParams(paths, "default", keytypes.CorridorV1, map[string]string{
		ParamSentryName: "falcon-sentry",
		"recipients":    "RECIPIENTS",
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams() error = %v", err)
	}
	if got := resolved[keytypes.ParameterSentryPublicKey]; got != strings.Repeat("cd", falconfamily.PublicKeySize) {
		t.Fatalf("sentry_public_key = %q, want imported Falcon public key", got)
	}
	if got := resolved["recipients"]; got != "RECIPIENTS" {
		t.Fatalf("recipients = %q, want preserved", got)
	}
	if _, ok := resolved[ParamSentryName]; ok {
		t.Fatalf("resolved params still contain %s: %#v", ParamSentryName, resolved)
	}
}

func TestResolveCreationParamsRejectsConflictingInputs(t *testing.T) {
	_, err := ResolveCreationParams(storepaths.NewPaths(t.TempDir()), "default", keytypes.GuardedFalcon1024SentryFalcon1024V1, map[string]string{
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

func TestSyncDiscoveredWritesSourceMarkedReferences(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	result, err := SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "Sentry.Local",
		ComponentKey:  componentKey,
		KeyType:       keytypes.SentryComponentFalcon1024V1,
		PublicKeyHex:  strings.ToUpper(hex.EncodeToString(pub)),
		LastSeenAt:    "2026-06-04T00:00:00Z",
	}})
	if err != nil {
		t.Fatalf("SyncDiscovered() error = %v", err)
	}
	if result.Added != 1 || result.Updated != 0 || result.Removed != 0 {
		t.Fatalf("sync counts = %#v, want one added", result)
	}
	wantName, err := SyncedReferenceName("Sentry.Local", componentKey)
	if err != nil {
		t.Fatalf("SyncedReferenceName() error = %v", err)
	}
	rec, ok, err := Get(paths, "default", wantName)
	if err != nil || !ok {
		t.Fatalf("Get(%s) = (%#v, %v, %v), want synced record", wantName, rec, ok, err)
	}
	if rec.Source != SourceClientDiscovery || rec.EndpointAlias != "Sentry.Local" {
		t.Fatalf("record source/endpoint = %q/%q, want client discovery Sentry.Local", rec.Source, rec.EndpointAlias)
	}
	if rec.PublicKeyHex != strings.Repeat("ab", falconfamily.PublicKeySize) {
		t.Fatalf("PublicKeyHex = %q, want lower-case ab", rec.PublicKeyHex)
	}
	if rec.SyncedAt == "" || rec.LastSeenAt == "" {
		t.Fatalf("SyncedAt/LastSeenAt = %q/%q, want populated", rec.SyncedAt, rec.LastSeenAt)
	}
}

func TestSyncDiscoveredRejectsMismatchedComponentSelector(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	otherPub := bytesOfLen(falconfamily.PublicKeySize, 0xcd)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, otherPub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	_, err = SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "sentry-local",
		ComponentKey:  componentKey,
		KeyType:       keytypes.SentryComponentFalcon1024V1,
		PublicKeyHex:  hex.EncodeToString(pub),
	}})
	if err == nil {
		t.Fatal("SyncDiscovered() error = nil, want selector/public-key mismatch rejection")
	}
	if !strings.Contains(err.Error(), "does not match public key") {
		t.Fatalf("SyncDiscovered() error = %v, want Sentry Key ID mismatch", err)
	}
}

func TestSyncDiscoveredRejectsSamePublicKeyFromMultipleEndpoints(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	_, err = SyncDiscovered(paths, "default", []DiscoveredRecord{
		{
			EndpointAlias: "sentry-a",
			ComponentKey:  componentKey,
			KeyType:       keytypes.SentryComponentFalcon1024V1,
			PublicKeyHex:  hex.EncodeToString(pub),
		},
		{
			EndpointAlias: "sentry-b",
			ComponentKey:  componentKey,
			KeyType:       keytypes.SentryComponentFalcon1024V1,
			PublicKeyHex:  strings.ToUpper(hex.EncodeToString(pub)),
		},
	})
	if err == nil {
		t.Fatal("SyncDiscovered() error = nil, want duplicate public-key route rejection")
	}
	if !strings.Contains(err.Error(), "appears under multiple endpoint aliases") {
		t.Fatalf("SyncDiscovered() error = %v, want duplicate endpoint rejection", err)
	}
}

func TestSyncDiscoveredReplacesOnlyClientDiscoveryReferences(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	manualPub := bytesOfLen(falconfamily.PublicKeySize, 0xab)
	if _, err := Import(paths, "default", "manual-sentry", testExportJSON(t, keytypes.SentryComponentFalcon1024V1, manualPub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	stalePub := bytesOfLen(falconfamily.PublicKeySize, 0xcd)
	staleComponent, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, stalePub)
	if err != nil {
		t.Fatalf("ComponentKeySelector(stale) error = %v", err)
	}
	if _, err := SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "stale",
		ComponentKey:  staleComponent,
		KeyType:       keytypes.SentryComponentFalcon1024V1,
		PublicKeyHex:  hex.EncodeToString(stalePub),
	}}); err != nil {
		t.Fatalf("SyncDiscovered(stale) error = %v", err)
	}

	freshPub := bytesOfLen(falconfamily.PublicKeySize, 0xef)
	freshComponent, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, freshPub)
	if err != nil {
		t.Fatalf("ComponentKeySelector(fresh) error = %v", err)
	}
	result, err := SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "fresh",
		ComponentKey:  freshComponent,
		KeyType:       keytypes.SentryComponentFalcon1024V1,
		PublicKeyHex:  hex.EncodeToString(freshPub),
	}})
	if err != nil {
		t.Fatalf("SyncDiscovered(fresh) error = %v", err)
	}
	if result.Added != 1 || result.Removed != 1 {
		t.Fatalf("sync counts = %#v, want one added and one stale removed", result)
	}
	if _, ok, err := Get(paths, "default", "manual-sentry"); err != nil || !ok {
		t.Fatalf("manual reference removed or unreadable: ok=%v err=%v", ok, err)
	}
	staleName, err := SyncedReferenceName("stale", staleComponent)
	if err != nil {
		t.Fatalf("SyncedReferenceName(stale) error = %v", err)
	}
	if _, ok, err := Get(paths, "default", staleName); err != nil || ok {
		t.Fatalf("stale reference Get = ok:%v err:%v, want absent", ok, err)
	}
}

func testExportJSON(t *testing.T, keyType string, pub []byte) []byte {
	t.Helper()
	componentKey, err := keytypes.ComponentKeySelector(keyType, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
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
