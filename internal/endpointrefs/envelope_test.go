// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package endpointrefs

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseNormalizesEndpointEnvelope(t *testing.T) {
	data := []byte(`{
  "schema": "aplane.endpoint.v1",
  "url": "ssh://signer.example:2223/"
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
			name:    "retired signer_port field",
			data:    strings.Replace(valid, `"url":`, `"signer_port": 11270, "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "retired local_port field",
			data:    strings.Replace(valid, `"url":`, `"local_port": 18080, "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "stale role field",
			data:    strings.Replace(valid, `"url":`, `"role": "cosigner", "url":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "stale cosigner keys field",
			data:    strings.Replace(valid, `"url":`, `"cosigner_public_keys": [], "url":`, 1),
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
			wantErr: `unsupported url scheme ""`,
		},
		{
			name:    "remote http",
			data:    strings.Replace(valid, `"url": "ssh://signer.example:2223"`, `"url": "http://signer.example:11270"`, 1),
			wantErr: `unsupported url scheme "http"`,
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
		Schema: Schema,
		URL:    "ssh://signer.example:2223",
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

// The URL rules for an endpoint envelope, which apadmin endpoint export
// writes and apshell endpoints import reads. Accepted URLs are kept without
// surrounding space or a trailing slash.
func TestEnvelopeURLRules(t *testing.T) {
	tests := []struct {
		raw     string
		wantURL string
		wantErr string
	}{
		{raw: "ssh://signer.example", wantURL: "ssh://signer.example"},
		{raw: "ssh://signer.example:2223", wantURL: "ssh://signer.example:2223"},
		{raw: " ssh://signer.example:2223/ ", wantURL: "ssh://signer.example:2223"},
		{raw: "SSH://signer.example", wantURL: "SSH://signer.example"},
		{raw: "ssh://user@signer.example", wantURL: "ssh://user@signer.example"},
		{raw: "ssh://[::1]:2223", wantURL: "ssh://[::1]:2223"},
		{raw: "ssh://127.0.0.1:65535", wantURL: "ssh://127.0.0.1:65535"},
		{raw: "ssh://signer.example:0", wantErr: `invalid url port "0"`},
		{raw: "ssh://signer.example:65536", wantErr: `invalid url port "65536"`},
		{raw: "ssh://signer.example:abc", wantErr: `invalid url: parse "ssh://signer.example:abc": invalid port ":abc" after host`},
		{raw: "ssh://", wantErr: "url host is required"},
		{raw: "ssh:///path", wantErr: "url host is required"},
		{raw: "https://signer.example", wantErr: `unsupported url scheme "https"; endpoints are ssh://host[:port]`},
		{raw: "https://signer.example:8443", wantErr: `unsupported url scheme "https"; endpoints are ssh://host[:port]`},
		{raw: "http://127.0.0.1:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://localhost:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://[::1]:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "http://signer.example:11270", wantErr: `unsupported url scheme "http"; endpoints are ssh://host[:port]`},
		{raw: "ftp://signer.example", wantErr: `unsupported url scheme "ftp"; endpoints are ssh://host[:port]`},
		{raw: "self", wantErr: `unsupported url scheme ""; endpoints are ssh://host[:port]`},
		{raw: "", wantErr: "url is required"},
		{raw: "://bad", wantErr: `invalid url: parse "://bad": missing protocol scheme`},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			data, err := json.Marshal(Envelope{Schema: Schema, URL: tt.raw})
			if err != nil {
				t.Fatal(err)
			}
			env, err := Parse(data)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("Parse() error = %v, want %q", err, tt.wantErr)
				}
				if _, err := Marshal(Envelope{Schema: Schema, URL: tt.raw}); err == nil || err.Error() != tt.wantErr {
					t.Fatalf("Marshal() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || env.URL != tt.wantURL {
				t.Fatalf("Parse() = %q, %v; want %q", env.URL, err, tt.wantURL)
			}
		})
	}
}
