// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/genstore"
	"github.com/aplane-algo/aplane/internal/signerapp/adminserver"
)

func TestDurableCredentialRestoreIntentGate(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	if err := auditLog.LogCredentialRestoreIntentDurableContext(
		adminserver.SessionContext{}, "restore-1", "backup.tar.gz", true,
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CREDENTIAL_RESTORE_INTENT") || !strings.Contains(string(data), "restore-1") {
		t.Fatalf("audit log missing durable restore intent: %q", data)
	}
}

func TestDurableGenerationQuarantinePruneIntentGate(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	if err := auditLog.LogGenerationQuarantinePruneIntentDurableContext(
		adminserver.SessionContext{},
		"prune-1",
		[]string{"gen-1700000000-0123abcd"},
	); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "GENERATION_QUARANTINE_PRUNE_INTENT") ||
		!strings.Contains(string(data), "gen-1700000000-0123abcd") {
		t.Fatalf("audit log missing durable quarantine-prune intent: %q", data)
	}
}

func TestDurableGenerationQuarantineIntentRecordsClassification(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	auditLog, err := NewAuditLogger(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	record := genstore.QuarantineRecord{
		GenerationID:         "gen-1700000000-0123abcd",
		ParentID:             "gen-1699999999-4567abcd",
		ManifestSHA256:       "manifest-digest",
		LiveInventorySHA256:  "live-digest",
		AtMintInventoryMatch: false,
		EntryCount:           4,
		EncodedBytes:         1024,
	}
	if err := auditLog.LogGenerationQuarantineIntentDurable(record); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"GENERATION_QUARANTINE_INTENT",
		`"generation_id":"gen-1700000000-0123abcd"`,
		`"manifest_sha256":"manifest-digest"`,
		`"live_inventory_sha256":"live-digest"`,
		`"at_mint_inventory_match":false`,
		`"quarantine_entry_count":4`,
		`"byte_count":1024`,
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("audit log missing %q: %s", want, data)
		}
	}
}
