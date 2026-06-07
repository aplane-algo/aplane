// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package endpointrefs

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseNormalizesEndpointEnvelope(t *testing.T) {
	data := []byte(`{
  "schema": "aplane.endpoint.v1",
  "url": "ssh://signer.example:2223/",
  "signer_port": 11270
}`)

	env, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if env.Schema != Schema {
		t.Fatalf("Schema = %q, want %q", env.Schema, Schema)
	}
	if env.URL != "ssh://signer.example:2223" {
		t.Fatalf("URL = %q, want trimmed URL", env.URL)
	}
	if env.SignerPort != 11270 {
		t.Fatalf("SignerPort = %d, want 11270", env.SignerPort)
	}
}

func TestParseRejectsInvalidEnvelope(t *testing.T) {
	valid := `{
  "schema": "aplane.endpoint.v1",
  "url": "ssh://signer.example:2223"
}`

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "unknown field",
			data:    strings.Replace(valid, `"url":`, `"extra": true, "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "stale kind field",
			data:    strings.Replace(valid, `"schema":`, `"kind": "aplane.endpoint.v1", "schema":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "stale schema version field",
			data:    strings.Replace(valid, `"url":`, `"schema_version": 1, "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "stale role field",
			data:    strings.Replace(valid, `"url":`, `"role": "attestation", "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "stale attestor keys field",
			data:    strings.Replace(valid, `"url":`, `"sentry_public_keys": [], "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "missing schema",
			data:    strings.Replace(valid, `"schema": "aplane.endpoint.v1",`, ``, 1),
			wantErr: "schema is required",
		},
		{
			name:    "unsupported schema",
			data:    strings.Replace(valid, `"schema": "aplane.endpoint.v1"`, `"schema": "aplane.endpoint.v2"`, 1),
			wantErr: "unsupported endpoint envelope schema",
		},
		{
			name:    "self url",
			data:    strings.Replace(valid, `"url": "ssh://signer.example:2223"`, `"url": "self"`, 1),
			wantErr: "not allowed",
		},
		{
			name:    "remote http",
			data:    strings.Replace(valid, `"url": "ssh://signer.example:2223"`, `"url": "http://signer.example:11270"`, 1),
			wantErr: "raw http endpoints must be loopback",
		},
		{
			name:    "trailing content",
			data:    valid + `{}`,
			wantErr: "trailing JSON content",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse() error = %q, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestMarshalValidatesEnvelope(t *testing.T) {
	_, err := Marshal(Envelope{
		Schema: Schema,
		URL:    "self",
	})
	if err == nil {
		t.Fatal("Marshal() error = nil, want validation error")
	}
}

func TestMarshalParseRoundTripStable(t *testing.T) {
	env := Envelope{
		Schema:     Schema,
		URL:        "ssh://signer.example:2223",
		SignerPort: 11270,
		LocalPort:  12001,
	}

	first, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal(first) error = %v", err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse(first) error = %v", err)
	}
	second, err := Marshal(parsed)
	if err != nil {
		t.Fatalf("Marshal(second) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("marshal/parse/marshal changed envelope:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}
