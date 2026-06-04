// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/attrefs"
	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
)

func TestCmdAttestorImportListShowRemove(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		exportPath := filepath.Join(t.TempDir(), "attestor-public.json")
		if err := os.WriteFile(exportPath, testAttestorExportJSON(t), 0o600); err != nil {
			t.Fatalf("WriteFile(export) error = %v", err)
		}

		if err := cmdAttestor([]string{"import", exportPath, "Lab-Att"}); err != nil {
			t.Fatalf("cmdAttestor(import) error = %v", err)
		}

		listOut, err := withCapturedStdout(func() error {
			return cmdAttestor([]string{"list"})
		})
		if err != nil {
			t.Fatalf("cmdAttestor(list) error = %v", err)
		}
		if !strings.Contains(listOut, "lab-att") || !strings.Contains(listOut, keytypes.AttestorComponentEd25519V1) {
			t.Fatalf("list output = %q, want imported attestor reference", listOut)
		}

		showOut, err := withCapturedStdout(func() error {
			return cmdAttestor([]string{"show", "lab-att"})
		})
		if err != nil {
			t.Fatalf("cmdAttestor(show) error = %v", err)
		}
		var rec attrefs.Record
		if err := json.Unmarshal([]byte(showOut), &rec); err != nil {
			t.Fatalf("show output is not JSON: %v\n%s", err, showOut)
		}
		if rec.Name != "lab-att" {
			t.Fatalf("show Name = %q, want lab-att", rec.Name)
		}

		if err := cmdAttestor([]string{"remove", "lab-att"}); err != nil {
			t.Fatalf("cmdAttestor(remove) error = %v", err)
		}
		records, err := attrefs.List(keystorePaths(), productIdentityID())
		if err != nil {
			t.Fatalf("attrefs.List() error = %v", err)
		}
		if len(records) != 0 {
			t.Fatalf("records after remove = %#v, want empty", records)
		}
	})
}

func testAttestorExportJSON(t *testing.T) []byte {
	t.Helper()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xab
	}
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	env, err := attrefs.NewExportEnvelope(componentKey, keytypes.AttestorComponentEd25519V1, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("NewExportEnvelope() error = %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal(export) error = %v", err)
	}
	return data
}
