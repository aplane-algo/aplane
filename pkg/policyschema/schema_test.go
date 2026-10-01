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
	for name, format := range map[string]string{"signerPolicy": SignerFormatV1, "cosignerPolicy": CosignerFormatV1} {
		def, _ := defs[name].(map[string]any)
		props, _ := def["properties"].(map[string]any)
		formatProp, _ := props["format"].(map[string]any)
		if formatProp["const"] != format {
			t.Errorf("$defs.%s.format const = %v, want %q", name, formatProp["const"], format)
		}
	}
}

// TestContractFixturesV1AreWellFormed keeps the published examples parseable
// and typed. Schema conformance of the fixtures is checked against the Go
// validator once it exists.
func TestContractFixturesV1AreWellFormed(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "contracts", "policy", "v1")
	for _, pattern := range []string{"*.json", filepath.Join("invalid", "*.json")} {
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
			}
			if err := json.Unmarshal(data, &doc); err != nil {
				t.Errorf("%s: not valid JSON: %v", file, err)
				continue
			}
			if strings.Contains(file, string(filepath.Separator)+"invalid"+string(filepath.Separator)) {
				continue
			}
			base := filepath.Base(file)
			want := SignerFormatV1
			if strings.HasPrefix(base, "cosigner_") {
				want = CosignerFormatV1
			}
			if doc.Format != want {
				t.Errorf("%s: format = %q, want %q", file, doc.Format, want)
			}
		}
	}
}
