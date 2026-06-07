// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/sentry/keytypes"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
)

func TestCmdSentryImportPublicListShowRemove(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		exportPath := filepath.Join(t.TempDir(), "sentry-public.json")
		if err := os.WriteFile(exportPath, testSentryExportJSON(t), 0o600); err != nil {
			t.Fatalf("WriteFile(export) error = %v", err)
		}

		if err := cmdSentry([]string{"import-public", exportPath, "Lab-Sentry"}); err != nil {
			t.Fatalf("cmdSentry(import-public) error = %v", err)
		}

		listOut, err := withCapturedStdout(func() error {
			return cmdSentry([]string{"list"})
		})
		if err != nil {
			t.Fatalf("cmdSentry(list) error = %v", err)
		}
		if !strings.Contains(listOut, "lab-sentry") || !strings.Contains(listOut, keytypes.SentryComponentEd25519V1) {
			t.Fatalf("list output = %q, want imported sentry reference", listOut)
		}

		showOut, err := withCapturedStdout(func() error {
			return cmdSentry([]string{"show", "lab-sentry"})
		})
		if err != nil {
			t.Fatalf("cmdSentry(show) error = %v", err)
		}
		var rec sentryrefs.Record
		if err := json.Unmarshal([]byte(showOut), &rec); err != nil {
			t.Fatalf("show output is not JSON: %v\n%s", err, showOut)
		}
		if rec.Name != "lab-sentry" {
			t.Fatalf("show Name = %q, want lab-sentry", rec.Name)
		}

		if err := cmdSentry([]string{"remove", "lab-sentry"}); err != nil {
			t.Fatalf("cmdSentry(remove) error = %v", err)
		}
		records, err := sentryrefs.List(keystorePaths(), productIdentityID())
		if err != nil {
			t.Fatalf("sentryrefs.List() error = %v", err)
		}
		if len(records) != 0 {
			t.Fatalf("records after remove = %#v, want empty", records)
		}
	})
}

func testSentryExportJSON(t *testing.T) []byte {
	t.Helper()
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xab
	}
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentEd25519V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	env, err := sentryrefs.NewExportEnvelope(componentKey, keytypes.SentryComponentEd25519V1, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("NewExportEnvelope() error = %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal(export) error = %v", err)
	}
	return data
}
