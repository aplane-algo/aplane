// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signerapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var expectedContractFixtureNames = []string{
	"admin_delete_response_success.json",
	"admin_generate_request_generic.json",
	"admin_generate_response_generic.json",
	"cancel_sign_request.json",
	"cancel_sign_response_not_found.json",
	"cancel_sign_response_success.json",
	"error_response.json",
	"group_plan_response_mutated.json",
	"group_sign_request_mixed.json",
	"group_sign_response_mutated.json",
	"health_response_ready.json",
	"keys_response_generic.json",
	"keytypes_response_full.json",
	"status_response_ready.json",
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

func committedContractFixtureNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(contractFixtureDir(t))
	if err != nil {
		t.Fatalf("read contract fixture dir: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names
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
		{"error_response.json", assertContractRoundTrip[ErrorResponse]},
		{"keys_response_generic.json", assertContractRoundTrip[KeysResponse]},
		{"keytypes_response_full.json", assertContractRoundTrip[KeyTypesResponse]},
		{"admin_generate_request_generic.json", assertContractRoundTrip[AdminGenerateRequest]},
		{"admin_generate_response_generic.json", assertContractRoundTrip[AdminGenerateResponse]},
		{"admin_delete_response_success.json", assertContractRoundTrip[AdminDeleteResponse]},
		{"cancel_sign_request.json", assertContractRoundTrip[CancelSignRequest]},
		{"cancel_sign_response_not_found.json", assertContractRoundTrip[CancelSignResponse]},
		{"cancel_sign_response_success.json", assertContractRoundTrip[CancelSignResponse]},
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
	if got := committedContractFixtureNames(t); !reflect.DeepEqual(got, expectedContractFixtureNames) {
		t.Fatalf("contract fixture manifest mismatch\nwant: %#v\n got: %#v", expectedContractFixtureNames, got)
	}
	for _, name := range expectedContractFixtureNames {
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
