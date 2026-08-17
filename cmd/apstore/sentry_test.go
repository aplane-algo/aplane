// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apkeys "github.com/aplane-algo/aplane/internal/keys"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/sentryrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestCmdSentryImportListShowRemove(t *testing.T) {
	withPolicyCommandStore(t, func(_ string, _ []byte) {
		withLocalSentryAdminClient(t)
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
		if !strings.Contains(listOut, env.WitnessKeyID) ||
			!strings.Contains(listOut, witness.Falcon1024V1) ||
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

func withLocalSentryAdminClient(t *testing.T) {
	t.Helper()
	fake := &fakeApstoreAdminRequester{}
	fake.requestFunc = func(msg any, out any) error {
		switch request := msg.(type) {
		case protocol.ImportSentryReferenceMessage:
			record, err := sentryrefs.Import(keystorePaths(), productIdentityID(), request.Name, []byte(request.EnvelopeJSON))
			if err != nil {
				return err
			}
			result := out.(*protocol.ImportSentryReferenceResultMessage)
			result.Success = true
			result.Reference = protocolSentryReferenceForTest(*record)
		case protocol.ListSentryReferencesMessage:
			records, err := sentryrefs.List(keystorePaths(), productIdentityID())
			if err != nil {
				return err
			}
			result := out.(*protocol.SentryReferencesListMessage)
			for _, record := range records {
				result.References = append(result.References, protocolSentryReferenceForTest(record))
			}
		case protocol.GetSentryReferenceMessage:
			record, found, err := sentryrefs.Get(keystorePaths(), productIdentityID(), request.Name)
			if err != nil {
				return err
			}
			result := out.(*protocol.SentryReferenceMessage)
			result.Success = found
			if found {
				result.Reference = protocolSentryReferenceForTest(record)
			} else {
				result.Error = "sentry reference not found"
			}
		case protocol.RemoveSentryReferenceMessage:
			removed, err := sentryrefs.Delete(keystorePaths(), productIdentityID(), request.Name)
			if err != nil {
				return err
			}
			result := out.(*protocol.RemoveSentryReferenceResultMessage)
			result.Success, result.Removed, result.Name = true, removed, request.Name
		case protocol.ExportSentryPublicMessage:
			envelope, found, err := apkeys.ReadWitnessPublicMetadata(keystorePaths(), productIdentityID(), request.WitnessKeyID)
			if err != nil {
				return err
			}
			result := out.(*protocol.ExportSentryPublicResultMessage)
			if !found {
				result.Error = "sentry public metadata not found"
				return nil
			}
			data, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				return err
			}
			result.Success = true
			result.EnvelopeJSON = string(append(data, '\n'))
		default:
			return fmt.Errorf("unexpected sentry request %T", msg)
		}
		return nil
	}
	withFakeApstoreAdminClient(t, fake)
}

func protocolSentryReferenceForTest(record sentryrefs.Record) protocol.SentryReferenceInfo {
	return protocol.SentryReferenceInfo{
		Schema: record.Schema, Name: record.Name, ComponentKey: record.ComponentKey, KeyType: record.KeyType,
		PublicKeyEncoding: record.PublicKeyEncoding, PublicKeyHex: record.PublicKeyHex,
		PublicKeySize: record.PublicKeySize, PublicKeySHA256: record.PublicKeySHA256,
		ImportedAt: record.ImportedAt, MigrationOrigin: record.MigrationOrigin,
	}
}

func testSentryExportJSON(t *testing.T) []byte {
	t.Helper()
	pub := make([]byte, testSentryPublicKeySize(t))
	for i := range pub {
		pub[i] = 0xab
	}
	componentKey, err := witness.ID(witness.Falcon1024V1, pub)
	if err != nil {
		t.Fatalf("witness.ID() error = %v", err)
	}
	env, err := sentryrefs.NewExportEnvelope(componentKey, witness.Falcon1024V1, strings.Repeat("ab", testSentryPublicKeySize(t)))
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
	size, ok := witness.PublicKeySize(witness.Falcon1024V1)
	if !ok {
		t.Fatal("Falcon sentry public-key size is unavailable")
	}
	return size
}
