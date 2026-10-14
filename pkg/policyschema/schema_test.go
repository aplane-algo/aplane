// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policyschema

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchemaV1IsWellFormed(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(SchemaV1, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("$schema = %v, want draft 2020-12", schema["$schema"])
	}
	defs, _ := schema["$defs"].(map[string]any)
	for name, role := range map[string]string{"signerPolicy": "signer", "cosignerPolicy": "cosigner"} {
		def, _ := defs[name].(map[string]any)
		props, _ := def["properties"].(map[string]any)
		formatProp, _ := props["format"].(map[string]any)
		if formatProp["const"] != FormatV1 {
			t.Errorf("$defs.%s.format const = %v, want %q", name, formatProp["const"], FormatV1)
		}
		roleProp, _ := props["role"].(map[string]any)
		if roleProp["const"] != role {
			t.Errorf("$defs.%s.role const = %v, want %q", name, roleProp["const"], role)
		}
	}
}

// TestContractFixturesV1AreWellFormed keeps the published examples parseable
// and typed: one format, and a role that matches the fixture's file name.
// Schema conformance is checked against the Go validator in internal/policy.
func TestContractFixturesV1AreWellFormed(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "contracts", "policy", "v1")
	for _, pattern := range []string{"*.json", filepath.Join("invalid", "*.json"), filepath.Join("semantic_invalid", "*.json")} {
		files, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil || len(files) == 0 {
			t.Fatalf("no fixtures matched %s: %v", pattern, err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Format string `json:"format"`
				Role   string `json:"role"`
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Errorf("%s: not valid JSON: %v", file, err)
				continue
			}
			if base := filepath.Base(filepath.Dir(file)); base == "invalid" || base == "semantic_invalid" {
				continue
			}
			if doc.Format != FormatV1 {
				t.Errorf("%s: format = %q, want %q", file, doc.Format, FormatV1)
			}
			want := "signer"
			if strings.HasPrefix(filepath.Base(file), "cosigner_") {
				want = "cosigner"
			}
			if doc.Role != want {
				t.Errorf("%s: role = %q, want %q", file, doc.Role, want)
			}
		}
	}
}
