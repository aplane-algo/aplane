// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyExportAudit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := NewAuditLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogKeyExported(context.Background(), "ACCOUNT", "falcon1024", "released")
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry AuditEntry
	if err := json.Unmarshal(raw, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Event != AuditKeyExported || entry.Outcome != "released" || entry.TxnAuth != "ACCOUNT" || entry.Reason != "falcon1024" {
		t.Fatal("export audit fields missing")
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"mnemonic", "passphrase", "private_key", "recovery_entropy"} {
		if _, ok := fields[secret]; ok {
			t.Fatalf("audit contains secret field %s", secret)
		}
	}
}
