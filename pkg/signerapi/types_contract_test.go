// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	contractFixtureManifestName          = "fixture_manifest.json"
	contractFixtureHashManifestName      = "SHA256SUMS"
	contractErrorCodesFixtureName        = "error_codes.json"
	contractErrorClassificationsFileName = "error_code_classifications.json"
	contractFixtureSchemaVersion         = 1
)

type contractFixtureManifest struct {
	SchemaVersion int      `json:"schema_version"`
	Fixtures      []string `json:"fixtures"`
}

type contractErrorCodesFixture struct {
	SchemaVersion int      `json:"schema_version"`
	Codes         []string `json:"codes"`
}

type contractErrorClassificationsFixture struct {
	SchemaVersion   int               `json:"schema_version"`
	Classifications map[string]string `json:"classifications"`
}

func contractFixturePath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "test", "contracts", "signerapi", name)
}

func contractFixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Dir(contractFixturePath(t, "README.md"))
}

func expectedContractFixtureNames(t *testing.T) []string {
	t.Helper()
	var manifest contractFixtureManifest
	readContractMetadata(t, contractFixtureManifestName, &manifest)
	if manifest.SchemaVersion != contractFixtureSchemaVersion {
		t.Fatalf("%s schema_version = %d, want %d", contractFixtureManifestName, manifest.SchemaVersion, contractFixtureSchemaVersion)
	}
	names := sortedUniqueStrings(t, contractFixtureManifestName, manifest.Fixtures)
	for _, name := range names {
		if !strings.HasSuffix(name, ".json") {
			t.Fatalf("%s contains non-json fixture %q", contractFixtureManifestName, name)
		}
		if isContractMetadataFile(name) {
			t.Fatalf("%s must list API payload fixtures only, not metadata file %q", contractFixtureManifestName, name)
		}
	}
	return names
}

func committedContractFixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(contractFixtureDir(t))
	if err != nil {
		t.Fatalf("read contract fixture dir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && !isContractMetadataFile(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
}

func isContractMetadataFile(name string) bool {
	switch name {
	case contractFixtureManifestName, contractErrorCodesFixtureName, contractErrorClassificationsFileName:
		return true
	default:
		return false
	}
}

func readContractMetadata(t *testing.T, name string, out any) {
	t.Helper()
	raw, err := os.ReadFile(contractFixturePath(t, name))
	if err != nil {
		t.Fatalf("read contract metadata %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshal contract metadata %s: %v", name, err)
	}
}

func assertContractRoundTrip[T any](t *testing.T, name string) {
	t.Helper()
	raw, err := os.ReadFile(contractFixturePath(t, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("unmarshal %s into contract type: %v", name, err)
	}

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s from contract type: %v", name, err)
	}

	var want any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("unmarshal fixture %s as generic JSON: %v", name, err)
	}
	var got any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal round-tripped %s as generic JSON: %v", name, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch for %s\nwant: %#v\n got: %#v", name, want, got)
	}
}

func TestSignerAPIContractFixturesRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, string)
	}{
		{"group_sign_request_mixed.json", assertContractRoundTrip[GroupSignRequest]},
		{"group_sign_response_mutated.json", assertContractRoundTrip[GroupSignResponse]},
		{"group_plan_response_mutated.json", assertContractRoundTrip[GroupPlanResponse]},
		{"group_simulate_response_mutated.json", assertContractRoundTrip[GroupSimulateResponse]},
		{"error_response.json", assertContractRoundTrip[ErrorResponse]},
		{"keys_response_guarded.json", assertContractRoundTrip[KeysResponse]},
		{"keys_response_generic.json", assertContractRoundTrip[KeysResponse]},
		{"keys_response_component.json", assertContractRoundTrip[KeysResponse]},
		{"keytypes_response_full.json", assertContractRoundTrip[KeyTypesResponse]},
		{"admin_generate_request_generic.json", assertContractRoundTrip[AdminGenerateRequest]},
		{"admin_generate_response_generic.json", assertContractRoundTrip[AdminGenerateResponse]},
		{"admin_generate_response_component.json", assertContractRoundTrip[AdminGenerateResponse]},
		{"admin_delete_response_success.json", assertContractRoundTrip[AdminDeleteResponse]},
		{"admin_sync_sentries_request.json", assertContractRoundTrip[AdminSyncSentryReferencesRequest]},
		{"admin_sync_sentries_response.json", assertContractRoundTrip[AdminSyncSentryReferencesResponse]},
		{"cancel_sign_request.json", assertContractRoundTrip[CancelSignRequest]},
		{"cancel_sign_response_not_found.json", assertContractRoundTrip[CancelSignResponse]},
		{"cancel_sign_response_success.json", assertContractRoundTrip[CancelSignResponse]},
		{"component_sign_request_sentry.json", assertContractRoundTrip[ComponentSignRequest]},
		{"component_sign_response_sentry.json", assertContractRoundTrip[ComponentSignResponse]},
		{"guarded_assembly_request_mixed.json", assertContractRoundTrip[GuardedAssemblyRequest]},
		{"guarded_assembly_response.json", assertContractRoundTrip[GuardedAssemblyResponse]},
		{"guarded_simulate_request_mixed.json", assertContractRoundTrip[GuardedSimulateRequest]},
		{"guarded_simulate_response.json", assertContractRoundTrip[GuardedSimulateResponse]},
		{"health_response_ready.json", assertContractRoundTrip[HealthResponse]},
		{"status_response_ready.json", assertContractRoundTrip[StatusResponse]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.run(t, tt.name)
		})
	}
}

func TestSignerAPIContractFixtureManifest(t *testing.T) {
	expected := expectedContractFixtureNames(t)
	if got := committedContractFixtureNames(t); !reflect.DeepEqual(got, expected) {
		t.Fatalf("contract fixture manifest mismatch\nwant: %#v\n got: %#v", expected, got)
	}
	for _, name := range expected {
		raw, err := os.ReadFile(contractFixturePath(t, name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("fixture %s is not valid JSON: %v", name, err)
		}
	}
}

func TestSignerAPIContractErrorCodes(t *testing.T) {
	var fixture contractErrorCodesFixture
	readContractMetadata(t, contractErrorCodesFixtureName, &fixture)
	if fixture.SchemaVersion != contractFixtureSchemaVersion {
		t.Fatalf("%s schema_version = %d, want %d", contractErrorCodesFixtureName, fixture.SchemaVersion, contractFixtureSchemaVersion)
	}
	assertStringSetEqual(t, "signer API error codes", signerAPIErrorCodes(t), fixture.Codes)
}

func TestSignerAPIContractErrorClassifications(t *testing.T) {
	var fixture contractErrorClassificationsFixture
	readContractMetadata(t, contractErrorClassificationsFileName, &fixture)
	if fixture.SchemaVersion != contractFixtureSchemaVersion {
		t.Fatalf("%s schema_version = %d, want %d", contractErrorClassificationsFileName, fixture.SchemaVersion, contractFixtureSchemaVersion)
	}

	var classifiedCodes []string
	for code, class := range fixture.Classifications {
		if strings.TrimSpace(class) == "" {
			t.Fatalf("%s has empty classification for code %q", contractErrorClassificationsFileName, code)
		}
		classifiedCodes = append(classifiedCodes, code)
	}
	assertStringSetEqual(t, "signer API error classifications", signerAPIErrorCodes(t), classifiedCodes)
}

func TestSignerAPIContractHashManifest(t *testing.T) {
	want := readContractHashManifest(t)
	got := computeContractHashes(t)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("contract fixture hash manifest mismatch\nwant: %#v\n got: %#v", want, got)
	}
}

func signerAPIErrorCodes(t *testing.T) []string {
	t.Helper()
	return []string{
		ErrCodeBadRequest,
		ErrCodeUnauthorized,
		ErrCodeForbidden,
		ErrCodeLocked,
		ErrCodeNotFound,
		ErrCodeInvalidPassphrase,
		ErrCodeUnavailable,
		ErrCodeCacheRefresh,
		ErrCodeInternal,
	}
}

func assertStringSetEqual(t *testing.T, label string, want, got []string) {
	t.Helper()
	wantSorted := sortedUniqueStrings(t, label+" want", want)
	gotSorted := sortedUniqueStrings(t, label+" got", got)
	if !reflect.DeepEqual(gotSorted, wantSorted) {
		t.Fatalf("%s mismatch\nwant: %#v\n got: %#v", label, wantSorted, gotSorted)
	}
}

func sortedUniqueStrings(t *testing.T, label string, values []string) []string {
	t.Helper()
	seen := make(map[string]struct{}, len(values))
	out := append([]string(nil), values...)
	sort.Strings(out)
	for _, value := range out {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s contains an empty value", label)
		}
		if _, ok := seen[value]; ok {
			t.Fatalf("%s contains duplicate value %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return out
}

func readContractHashManifest(t *testing.T) map[string]string {
	t.Helper()
	file, err := os.Open(contractFixturePath(t, contractFixtureHashManifestName))
	if err != nil {
		t.Fatalf("open %s: %v", contractFixtureHashManifestName, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Fatalf("close %s: %v", contractFixtureHashManifestName, err)
		}
	}()

	hashes := map[string]string{}
	scanner := bufio.NewScanner(file)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("%s:%d: expected '<sha256>  <filename>', got %q", contractFixtureHashManifestName, lineNo, line)
		}
		hash, name := fields[0], fields[1]
		if len(hash) != sha256.Size*2 {
			t.Fatalf("%s:%d: invalid sha256 length for %q", contractFixtureHashManifestName, lineNo, name)
		}
		if _, err := hex.DecodeString(hash); err != nil {
			t.Fatalf("%s:%d: invalid sha256 for %q: %v", contractFixtureHashManifestName, lineNo, name, err)
		}
		if name == contractFixtureHashManifestName {
			t.Fatalf("%s:%d: hash manifest must not include itself", contractFixtureHashManifestName, lineNo)
		}
		if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
			t.Fatalf("%s:%d: expected base filename, got %q", contractFixtureHashManifestName, lineNo, name)
		}
		if _, exists := hashes[name]; exists {
			t.Fatalf("%s:%d: duplicate hash entry for %q", contractFixtureHashManifestName, lineNo, name)
		}
		hashes[name] = hash
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", contractFixtureHashManifestName, err)
	}
	return hashes
}

func computeContractHashes(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(contractFixtureDir(t))
	if err != nil {
		t.Fatalf("read contract fixture dir: %v", err)
	}
	hashes := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == contractFixtureHashManifestName {
			continue
		}
		raw, err := os.ReadFile(contractFixturePath(t, entry.Name()))
		if err != nil {
			t.Fatalf("read contract fixture file %s: %v", entry.Name(), err)
		}
		sum := sha256.Sum256(raw)
		hashes[entry.Name()] = hex.EncodeToString(sum[:])
	}
	return hashes
}
