// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package attrefs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
	"github.com/aplane-algo/aplane/internal/storepaths"
	falconfamily "github.com/aplane-algo/aplane/lsig/falcon1024/family"
)

func TestImportGetListDelete(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	export := testExportJSON(t, keytypes.AttestorComponentEd25519V1, bytesOfLen(32, 0xab))

	rec, err := Import(paths, "default", "Lab-Att", export)
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	if rec.Name != "lab-att" {
		t.Fatalf("Name = %q, want normalized lab-att", rec.Name)
	}
	if rec.Schema != RecordSchema {
		t.Fatalf("Schema = %q, want %q", rec.Schema, RecordSchema)
	}
	if rec.ImportedAt == "" {
		t.Fatal("ImportedAt is empty")
	}

	got, ok, err := Get(paths, "default", "lab-att")
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
	if len(list) != 1 || list[0].Name != "lab-att" {
		t.Fatalf("List() = %#v, want one lab-att record", list)
	}

	removed, err := Delete(paths, "default", "lab-att")
	if err != nil || !removed {
		t.Fatalf("Delete() = (%v, %v), want removed", removed, err)
	}
	_, ok, err = Get(paths, "default", "lab-att")
	if err != nil || ok {
		t.Fatalf("Get(after delete) = (_, %v, %v), want absent", ok, err)
	}
}

func TestListRejectsInvalidReferenceRecord(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	if err := os.MkdirAll(paths.AttestorRefsDir("default"), 0o700); err != nil {
		t.Fatalf("MkdirAll(attestors) error = %v", err)
	}
	if err := os.WriteFile(paths.AttestorRefPath("default", "bad"), []byte(`{"schema":"wrong"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(bad reference) error = %v", err)
	}

	_, err := List(paths, "default")
	if err == nil {
		t.Fatal("List() error = nil, want invalid reference rejection")
	}
	if !strings.Contains(err.Error(), "invalid attestor reference bad") {
		t.Fatalf("List() error = %v, want invalid reference context", err)
	}
}

func TestResolveCreationParamsUsesImportedReference(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(32, 0xab)
	if _, err := Import(paths, "default", "lab-att", testExportJSON(t, keytypes.AttestorComponentEd25519V1, pub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	resolved, err := ResolveCreationParams(paths, "default", keytypes.AttestedFalcon1024AttEd25519V1, map[string]string{
		ParamAttestorName: "lab-att",
	})
	if err != nil {
		t.Fatalf("ResolveCreationParams() error = %v", err)
	}
	if got := resolved[keytypes.ParameterAttestorPublicKey]; got != strings.Repeat("ab", 32) {
		t.Fatalf("attestor_public_key = %q, want imported public key", got)
	}
	if _, ok := resolved[ParamAttestorName]; ok {
		t.Fatalf("resolved params still contain %s: %#v", ParamAttestorName, resolved)
	}
}

func TestResolveCreationParamsRejectsConflictingInputs(t *testing.T) {
	_, err := ResolveCreationParams(storepaths.NewPaths(t.TempDir()), "default", keytypes.AttestedFalcon1024AttEd25519V1, map[string]string{
		ParamAttestorName:                   "lab-att",
		keytypes.ParameterAttestorPublicKey: strings.Repeat("ab", 32),
	})
	if err == nil {
		t.Fatal("ResolveCreationParams() error = nil, want conflicting input rejection")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("ResolveCreationParams() error = %v, want not both", err)
	}
}

func TestResolveCreationParamsRejectsMismatchedComponentKeyType(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(falconfamily.PublicKeySize, 0xcd)
	if _, err := Import(paths, "default", "falcon-att", testExportJSON(t, keytypes.AttestorComponentFalcon1024V1, pub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	_, err := ResolveCreationParams(paths, "default", keytypes.AttestedFalcon1024AttEd25519V1, map[string]string{
		ParamAttestorName: "falcon-att",
	})
	if err == nil {
		t.Fatal("ResolveCreationParams() error = nil, want key type mismatch")
	}
	if !strings.Contains(err.Error(), "requires "+keytypes.AttestorComponentEd25519V1) {
		t.Fatalf("ResolveCreationParams() error = %v, want required Ed25519 attestor", err)
	}
}

func TestSyncDiscoveredWritesSourceMarkedReferences(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	pub := bytesOfLen(32, 0xab)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}

	result, err := SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "Attestor.Local",
		ComponentKey:  componentKey,
		KeyType:       keytypes.AttestorComponentEd25519V1,
		PublicKeyHex:  strings.ToUpper(hex.EncodeToString(pub)),
		LastSeenAt:    "2026-06-04T00:00:00Z",
	}})
	if err != nil {
		t.Fatalf("SyncDiscovered() error = %v", err)
	}
	if result.Added != 1 || result.Updated != 0 || result.Removed != 0 {
		t.Fatalf("sync counts = %#v, want one added", result)
	}
	wantName, err := SyncedReferenceName("Attestor.Local", componentKey)
	if err != nil {
		t.Fatalf("SyncedReferenceName() error = %v", err)
	}
	rec, ok, err := Get(paths, "default", wantName)
	if err != nil || !ok {
		t.Fatalf("Get(%s) = (%#v, %v, %v), want synced record", wantName, rec, ok, err)
	}
	if rec.Source != SourceClientDiscovery || rec.EndpointAlias != "Attestor.Local" {
		t.Fatalf("record source/endpoint = %q/%q, want client discovery Attestor.Local", rec.Source, rec.EndpointAlias)
	}
	if rec.PublicKeyHex != strings.Repeat("ab", 32) {
		t.Fatalf("PublicKeyHex = %q, want lower-case ab", rec.PublicKeyHex)
	}
	if rec.SyncedAt == "" || rec.LastSeenAt == "" {
		t.Fatalf("SyncedAt/LastSeenAt = %q/%q, want populated", rec.SyncedAt, rec.LastSeenAt)
	}
}

func TestSyncDiscoveredReplacesOnlyClientDiscoveryReferences(t *testing.T) {
	paths := storepaths.NewPaths(t.TempDir())
	manualPub := bytesOfLen(32, 0xab)
	if _, err := Import(paths, "default", "manual-att", testExportJSON(t, keytypes.AttestorComponentEd25519V1, manualPub)); err != nil {
		t.Fatalf("Import() error = %v", err)
	}
	stalePub := bytesOfLen(32, 0xcd)
	staleComponent, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, stalePub)
	if err != nil {
		t.Fatalf("ComponentKeySelector(stale) error = %v", err)
	}
	if _, err := SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "stale",
		ComponentKey:  staleComponent,
		KeyType:       keytypes.AttestorComponentEd25519V1,
		PublicKeyHex:  hex.EncodeToString(stalePub),
	}}); err != nil {
		t.Fatalf("SyncDiscovered(stale) error = %v", err)
	}

	freshPub := bytesOfLen(32, 0xef)
	freshComponent, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, freshPub)
	if err != nil {
		t.Fatalf("ComponentKeySelector(fresh) error = %v", err)
	}
	result, err := SyncDiscovered(paths, "default", []DiscoveredRecord{{
		EndpointAlias: "fresh",
		ComponentKey:  freshComponent,
		KeyType:       keytypes.AttestorComponentEd25519V1,
		PublicKeyHex:  hex.EncodeToString(freshPub),
	}})
	if err != nil {
		t.Fatalf("SyncDiscovered(fresh) error = %v", err)
	}
	if result.Added != 1 || result.Removed != 1 {
		t.Fatalf("sync counts = %#v, want one added and one stale removed", result)
	}
	if _, ok, err := Get(paths, "default", "manual-att"); err != nil || !ok {
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
