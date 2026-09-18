// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apadminapp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aplane-algo/aplane/internal/config"
	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/protocol"
	"github.com/aplane-algo/aplane/internal/sentry/enrollment"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestCatalogAuthModeClassifiesSentryEnrollmentCommands(t *testing.T) {
	reference := testEnrollmentReference(t)
	tests := []struct {
		args []string
		want AuthMode
	}{
		{args: []string{"enrollment", "export", reference.WitnessKeyID, "--out", "sentry.json"}, want: AuthReadOnly},
		{args: []string{"enrollment", "import", "sentry.json", "--name", "lab"}, want: AuthUnlock},
		{args: []string{"enrollment", "import", "-", "--name", "lab", "--dry-run"}, want: AuthUnlock},
	}
	for _, tt := range tests {
		mode, err := CatalogAuthMode("sentry", tt.args)
		if err != nil {
			t.Fatalf("CatalogAuthMode(%v) error = %v", tt.args, err)
		}
		if mode != tt.want {
			t.Fatalf("CatalogAuthMode(%v) = %v, want %v", tt.args, mode, tt.want)
		}
	}
}

func TestSentryEnrollmentImportResultContractFixtureIsCanonical(t *testing.T) {
	result := SentryEnrollmentImportResult{
		Schema:       SentryEnrollmentImportResultSchema,
		WitnessKeyID: "TDLABGFRRAHTNGVSCX6ALUZPBRWWAWEEXHZRCCYZ3DPSXC3Y3VEA",
		ReferenceImport: SentryEnrollmentImportStep{
			Status: "imported", Name: "lab-sentry",
		},
		EndpointImport: SentryEnrollmentImportStep{
			Status: "applied", Alias: "sentry-lab", URL: "ssh://sentry.example:2223",
		},
	}
	want, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	fixturePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "test", "contracts", "sentry", "enrollment_import_result_v1.json")
	got, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("fixture %s is not the canonical %s encoding", fixturePath, SentryEnrollmentImportResultSchema)
	}
}

func TestCatalogSentryEnrollmentExportComposesEndpoint(t *testing.T) {
	reference := testEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		switch message.(type) {
		case protocol.ExportSentryPublicMessage:
			*result.(*protocol.ExportSentryPublicResultMessage) = protocol.ExportSentryPublicResultMessage{
				Success: true, EnvelopeJSON: string(witnessJSON),
			}
		case protocol.GetAdminSettingsMessage:
			*result.(*protocol.AdminSettingsMessage) = protocol.AdminSettingsMessage{SignerPort: 11270}
		default:
			return fmt.Errorf("request = %T", message)
		}
		return nil
	}}
	outPath := filepath.Join(t.TempDir(), "lab.aplane-sentry.json")
	err = (Catalog{Client: requester}).Run("sentry", []string{
		"enrollment", "export", reference.WitnessKeyID,
		"--url", "ssh://sentry.example:2223", "--out", outPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := enrollment.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Witness != reference || bundle.Endpoint == nil || bundle.Endpoint.URL != "ssh://sentry.example:2223" || bundle.Endpoint.SignerPort != 11270 {
		t.Fatalf("bundle = %#v", bundle)
	}
}

func TestCatalogSentryEnrollmentExportAllowsWitnessOnlyBundle(t *testing.T) {
	reference := testEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		switch message.(type) {
		case protocol.ExportSentryPublicMessage:
			*result.(*protocol.ExportSentryPublicResultMessage) = protocol.ExportSentryPublicResultMessage{Success: true, EnvelopeJSON: string(witnessJSON)}
		case protocol.GetAdminSettingsMessage:
			*result.(*protocol.AdminSettingsMessage) = protocol.AdminSettingsMessage{
				EndpointAdvertiseURL: "ssh://configured.example:2223", SignerPort: 11270,
			}
		default:
			return fmt.Errorf("request = %T", message)
		}
		return nil
	}}
	outPath := filepath.Join(t.TempDir(), "public-only.json")
	if err := (Catalog{Client: requester}).Run("sentry", []string{
		"enrollment", "export", reference.WitnessKeyID, "--out", outPath,
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := enrollment.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Endpoint != nil {
		t.Fatalf("Endpoint = %#v, want nil", bundle.Endpoint)
	}
}

func TestCatalogSentryEnrollmentExportIncludesConfiguredEndpointOnRequest(t *testing.T) {
	reference := testEnrollmentReference(t)
	witnessJSON, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		switch message.(type) {
		case protocol.ExportSentryPublicMessage:
			*result.(*protocol.ExportSentryPublicResultMessage) = protocol.ExportSentryPublicResultMessage{Success: true, EnvelopeJSON: string(witnessJSON)}
		case protocol.GetAdminSettingsMessage:
			*result.(*protocol.AdminSettingsMessage) = protocol.AdminSettingsMessage{
				EndpointAdvertiseURL: "ssh://configured.example:2223", SignerPort: 11270,
			}
		default:
			return fmt.Errorf("request = %T", message)
		}
		return nil
	}}
	outPath := filepath.Join(t.TempDir(), "with-endpoint.json")
	if err := (Catalog{Client: requester}).Run("sentry", []string{
		"enrollment", "export", reference.WitnessKeyID, "--include-endpoint", "--out", outPath,
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := enrollment.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Endpoint == nil || bundle.Endpoint.URL != "ssh://configured.example:2223" || bundle.Endpoint.SignerPort != 11270 {
		t.Fatalf("Endpoint = %#v", bundle.Endpoint)
	}
}

func TestCatalogSentryEnrollmentImportDryRunMakesNoChanges(t *testing.T) {
	reference := testEnrollmentReference(t)
	dataDir := t.TempDir()
	t.Setenv("APCLIENT_DATA", dataDir)
	path := writeEnrollmentBundle(t, reference, true)
	requester := &fakeRequester{handle: func(message, _ any) error {
		return fmt.Errorf("unexpected request %T", message)
	}}
	var stdout bytes.Buffer
	err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout}}).Run(
		"sentry", []string{"enrollment", "import", path, "--name", "lab", "--dry-run"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(requester.requests) != 0 {
		t.Fatalf("requests = %d, want none", len(requester.requests))
	}
	if _, err := os.Stat(config.GetClientEndpointsPath(dataDir)); !os.IsNotExist(err) {
		t.Fatalf("endpoints.yaml stat error = %v, want not exist", err)
	}
	result := decodeEnrollmentImportResult(t, stdout.Bytes())
	if !result.DryRun || result.ReferenceImport.Status != "planned" || result.EndpointImport.Status != "not_requested" {
		t.Fatalf("result = %#v", result)
	}
}

func TestCatalogSentryEnrollmentImportAcceptsLegacyWitnessEnvelope(t *testing.T) {
	reference := testEnrollmentReference(t)
	data, err := enrollment.MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		if _, ok := message.(protocol.ImportSentryReferenceMessage); !ok {
			return fmt.Errorf("request = %T", message)
		}
		*result.(*protocol.ImportSentryReferenceResultMessage) = protocol.ImportSentryReferenceResultMessage{
			Success: true, Reference: protocol.SentryReferenceInfo{Name: "lab"},
		}
		return nil
	}}
	var stdout bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout}}).Run(
		"sentry", []string{"enrollment", "import", path, "--name", "lab"},
	); err != nil {
		t.Fatal(err)
	}
	result := decodeEnrollmentImportResult(t, stdout.Bytes())
	if result.ReferenceImport.Status != "imported" || result.EndpointImport.Status != "not_requested" {
		t.Fatalf("result = %#v", result)
	}
}

func testEnrollmentReference(t *testing.T) witness.PublicReference {
	t.Helper()
	publicKey := bytes.Repeat([]byte{0x24}, 1793)
	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	return reference
}

func writeEnrollmentBundle(t *testing.T, reference witness.PublicReference, withEndpoint bool) string {
	t.Helper()
	bundle := enrollment.Envelope{Schema: enrollment.Schema, Witness: reference}
	if withEndpoint {
		endpoint := endpointrefs.Envelope{Schema: endpointrefs.Schema, URL: "ssh://sentry.example:2223", SignerPort: 11270}
		bundle.Endpoint = &endpoint
	}
	data, err := enrollment.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sentry.aplane-sentry.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func decodeEnrollmentImportResult(t *testing.T, data []byte) SentryEnrollmentImportResult {
	t.Helper()
	var result SentryEnrollmentImportResult
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("decode result %q: %v", data, err)
	}
	return result
}

func TestCatalogSentryBundleImportIgnoresClientState(t *testing.T) {
	reference := testEnrollmentReference(t)
	path := writeEnrollmentBundle(t, reference, true)
	dataDir := t.TempDir()
	t.Setenv("APCLIENT_DATA", dataDir)
	clientPath := filepath.Join(dataDir, "endpoints.yaml")
	original := []byte("invalid client configuration must not affect admin")
	if err := os.WriteFile(clientPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	requester := &fakeRequester{handle: func(message, result any) error {
		request, ok := message.(protocol.ImportSentryReferenceMessage)
		if !ok {
			return fmt.Errorf("unexpected request %T", message)
		}
		if request.Name != "lab" {
			t.Fatalf("name = %q", request.Name)
		}
		*result.(*protocol.ImportSentryReferenceResultMessage) = protocol.ImportSentryReferenceResultMessage{Success: true}
		return nil
	}}
	var stdout bytes.Buffer
	if err := (Catalog{Client: requester, Streams: Streams{Stdout: &stdout}}).Run("sentry", []string{"enrollment", "import", path, "--name", "lab"}); err != nil {
		t.Fatal(err)
	}
	result := decodeEnrollmentImportResult(t, stdout.Bytes())
	if result.ReferenceImport.Status != "imported" || result.EndpointImport.Status != "not_requested" {
		t.Fatalf("result = %+v", result)
	}
	after, err := os.ReadFile(clientPath)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatalf("client configuration changed: %v", err)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("client state changed: %v, %v", entries, err)
	}
}

func TestCatalogSentryImportRejectsEndpointAlias(t *testing.T) {
	_, err := CatalogAuthMode("sentry", []string{"enrollment", "import", "bundle.json", "--name", "lab", "--endpoint-alias", "route"})
	if err == nil {
		t.Fatal("retired endpoint-alias option accepted")
	}
}
