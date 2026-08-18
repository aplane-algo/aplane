// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyeditor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/policy"
)

func TestFileStoreSaveReplacesOnlyStandaloneDraft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "draft.yaml")
	before := []byte("# standalone draft\nreject_foreign_rekey: true\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	productionPath := filepath.Join(dir, "policy.yaml")
	production := []byte("# must remain untouched\nreject_foreign_rekey: true\n")
	if err := os.WriteFile(productionPath, production, 0o600); err != nil {
		t.Fatal(err)
	}

	store := &FileStore{Path: path, Target: TargetSigner}
	if got := store.Persistence(); got.Kind != PersistenceDraft || got.Path != path {
		t.Fatalf("Persistence() = %#v", got)
	}
	stored, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reject := false
	stored.RejectForeignRekey = &reject
	if err := store.Save(context.Background(), stored); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "reject_foreign_rekey: false") {
		t.Fatalf("draft was not replaced:\n%s", got)
	}
	productionAfter, err := os.ReadFile(productionPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(productionAfter) != string(production) {
		t.Fatalf("production policy changed:\n%s", productionAfter)
	}
	for _, sidecar := range []string{path + ".hmac", filepath.Join(dir, "policy.yaml.hmac")} {
		if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
			t.Fatalf("standalone save created sidecar %s: %v", sidecar, err)
		}
	}
}

func TestFileStoreRejectedSaveLeavesDraftUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draft.yaml")
	want := []byte("reject_foreign_rekey: true\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	enabled := true
	invalid := &policy.StoredConfig{StoredPolicyCore: policy.StoredPolicyCore{
		TransferPolicy: &policy.StoredTransferPolicy{SchemaVersion: 1, Enabled: &enabled},
	}}
	store := &FileStore{Path: path, Target: TargetSigner}
	if err := store.Save(context.Background(), invalid); err == nil || !strings.Contains(err.Error(), "on_no_route is required") {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("rejected save changed draft:\n%s", got)
	}
}
