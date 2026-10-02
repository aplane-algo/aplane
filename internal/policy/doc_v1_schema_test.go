// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/aplane-algo/aplane/pkg/policyschema"
)

// TestPolicyV1FixturesAgreeWithSchema runs every contract fixture through the
// published JSON Schema and the Go decoder. Valid fixtures must pass both and
// compile; invalid/ fixtures must fail both; semantic_invalid/ fixtures must
// pass the schema and fail the decoder, which enforces rules the schema cannot.
func TestPolicyV1FixturesAgreeWithSchema(t *testing.T) {
	schema := compilePolicySchemaV1(t)
	dir := filepath.Join("..", "..", "test", "contracts", "policy", "v1")
	for _, group := range []struct {
		pattern      string
		schemaValid  bool
		decoderValid bool
	}{
		{"*.json", true, true},
		{filepath.Join("invalid", "*.json"), false, false},
		{filepath.Join("semantic_invalid", "*.json"), true, false},
	} {
		files, err := filepath.Glob(filepath.Join(dir, group.pattern))
		if err != nil || len(files) == 0 {
			t.Fatalf("no fixtures matched %s: %v", group.pattern, err)
		}
		for _, file := range files {
			t.Run(filepath.ToSlash(file[len(dir)+1:]), func(t *testing.T) {
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
				if err != nil {
					t.Fatalf("fixture is not JSON: %v", err)
				}
				schemaErr := schema.Validate(instance)
				if (schemaErr == nil) != group.schemaValid {
					t.Errorf("schema valid = %v, want %v (%v)", schemaErr == nil, group.schemaValid, schemaErr)
				}
				compiled, decodeErr := decodeAndCompileFixtureV1(data)
				if (decodeErr == nil) != group.decoderValid {
					t.Errorf("decoder valid = %v, want %v (%v)", decodeErr == nil, group.decoderValid, decodeErr)
				}
				if decodeErr == nil && compiled == nil {
					t.Error("decoded fixture compiled to nil config")
				}
			})
		}
	}
}

func compilePolicySchemaV1(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(policyschema.SchemaV1))
	if err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("urn:aplane:policy:v1", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("urn:aplane:policy:v1")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

// decodeAndCompileFixtureV1 picks the decoder by the fixture's format and,
// for cosigner documents, supplies a file name matching its key.
func decodeAndCompileFixtureV1(data []byte) (*Config, error) {
	var head struct {
		Format string `json:"format"`
		Key    string `json:"key"`
	}
	_ = json.Unmarshal(data, &head)
	if head.Format == policyschema.CosignerFormatV1 {
		doc, err := DecodeCosignerPolicyV1(data, head.Key)
		if err != nil {
			return nil, err
		}
		return doc.Compile(DefaultConfig())
	}
	doc, err := DecodeSignerPolicyV1(data)
	if err != nil {
		return nil, err
	}
	return doc.Compile(DefaultConfig())
}
