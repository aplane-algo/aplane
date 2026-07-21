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

func TestCmdSentryImportListShowRemove(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		exportPath := filepath.Join(t.TempDir(), "sentry-public.json")
		exportJSON := testSentryExportJSON(t)
		var env sentryrefs.ExportEnvelope
		if err := json.Unmarshal(exportJSON, &env); err != nil {
			t.Fatalf("Unmarshal(export) error = %v", err)
		}
		if err := os.WriteFile(exportPath, exportJSON, 0o600); err != nil {
			t.Fatalf("WriteFile(export) error = %v", err)
		}

		if err := cmdSentry([]string{"import", exportPath, "Lab-Sentry"}); err != nil {
			t.Fatalf("cmdSentry(import) error = %v", err)
		}

		listOut, err := withCapturedStdout(func() error {
			return cmdSentry([]string{"list"})
		})
		if err != nil {
			t.Fatalf("cmdSentry(list) error = %v", err)
		}
		if !strings.Contains(listOut, env.ComponentKey) ||
			!strings.Contains(listOut, keytypes.SentryComponentFalcon1024V1) ||
			!strings.Contains(listOut, "name: lab-sentry") {
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

func TestCmdSentryListHidesEndpointSyncedRecordName(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		pub := make([]byte, testSentryPublicKeySize(t))
		for i := range pub {
			pub[i] = 0xab
		}
		componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, pub)
		if err != nil {
			t.Fatalf("ComponentKeySelector() error = %v", err)
		}
		if _, err := sentryrefs.SyncDiscovered(keystorePaths(), productIdentityID(), []sentryrefs.DiscoveredRecord{{
			EndpointAlias: "foo",
			ComponentKey:  componentKey,
			KeyType:       keytypes.SentryComponentFalcon1024V1,
			PublicKeyHex:  strings.Repeat("ab", testSentryPublicKeySize(t)),
		}}); err != nil {
			t.Fatalf("SyncDiscovered() error = %v", err)
		}
		generatedName, err := sentryrefs.SyncedReferenceName("foo", componentKey)
		if err != nil {
			t.Fatalf("SyncedReferenceName() error = %v", err)
		}

		listOut, err := withCapturedStdout(func() error {
			return cmdSentry([]string{"list"})
		})
		if err != nil {
			t.Fatalf("cmdSentry(list) error = %v", err)
		}
		if strings.Contains(listOut, generatedName) {
			t.Fatalf("list output exposed generated record name %q:\n%s", generatedName, listOut)
		}
		if !strings.Contains(listOut, componentKey) ||
			!strings.Contains(listOut, keytypes.SentryComponentFalcon1024V1) ||
			!strings.Contains(listOut, "endpoint: foo") {
			t.Fatalf("list output = %q, want Sentry Key ID, key type, and endpoint alias", listOut)
		}
	})
}

func testSentryExportJSON(t *testing.T) []byte {
	t.Helper()
	pub := make([]byte, testSentryPublicKeySize(t))
	for i := range pub {
		pub[i] = 0xab
	}
	componentKey, err := keytypes.ComponentKeySelector(keytypes.SentryComponentFalcon1024V1, pub)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	env, err := sentryrefs.NewExportEnvelope(componentKey, keytypes.SentryComponentFalcon1024V1, strings.Repeat("ab", testSentryPublicKeySize(t)))
	if err != nil {
		t.Fatalf("NewExportEnvelope() error = %v", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal(export) error = %v", err)
	}
	return data
}

func testSentryPublicKeySize(t *testing.T) int {
	t.Helper()
	size, ok := keytypes.ComponentPublicKeySize(keytypes.SentryComponentFalcon1024V1)
	if !ok {
		t.Fatal("Falcon sentry public-key size is unavailable")
	}
	return size
}
