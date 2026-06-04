// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package attrefs

import (
	"encoding/hex"
	"encoding/json"
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
