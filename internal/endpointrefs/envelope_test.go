// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package endpointrefs

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/attestor/keytypes"
)

func TestParseNormalizesEndpointEnvelope(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x42}, 32)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	data := []byte(`{
  "kind": "aplane.endpoint.v1",
  "schema_version": 1,
  "alias": "attestor-local",
  "role": "ATTESTATION",
  "url": "ssh://signer.example:2223/",
  "signer_port": 11270,
  "attestor_public_keys": [
    {
      "key_type": "aplane.attestor-ed25519.v1",
      "public_key_hex": "` + strings.ToUpper(hex.EncodeToString(publicKey)) + `",
      "component_key": "` + componentKey + `"
    }
  ]
}`)

	env, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if env.Role != RoleAttestation {
		t.Fatalf("Role = %q, want %q", env.Role, RoleAttestation)
	}
	if env.URL != "ssh://signer.example:2223" {
		t.Fatalf("URL = %q, want trimmed URL", env.URL)
	}
	if got := env.AttestorPublicKeys[0].PublicKeyHex; got != hex.EncodeToString(publicKey) {
		t.Fatalf("PublicKeyHex = %q, want lowercase hex", got)
	}
}

func TestParseRejectsInvalidEnvelope(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x24}, 32)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	valid := `{
  "kind": "aplane.endpoint.v1",
  "schema_version": 1,
  "alias": "attestor-local",
  "role": "attestation",
  "url": "ssh://signer.example:2223",
  "attestor_public_keys": [
    {
      "key_type": "aplane.attestor-ed25519.v1",
      "public_key_hex": "` + hex.EncodeToString(publicKey) + `",
      "component_key": "` + componentKey + `"
    }
  ]
}`

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "unknown field",
			data:    strings.Replace(valid, `"alias":`, `"extra": true, "alias":`, 1),
			wantErr: "unknown field",
		},
		{
			name:    "missing kind",
			data:    strings.Replace(valid, `"kind": "aplane.endpoint.v1",`, ``, 1),
			wantErr: "kind is required",
		},
		{
			name:    "zero schema version",
			data:    strings.Replace(valid, `"schema_version": 1`, `"schema_version": 0`, 1),
			wantErr: "schema_version is required",
		},
		{
			name:    "future schema version",
			data:    strings.Replace(valid, `"schema_version": 1`, `"schema_version": 2`, 1),
			wantErr: "unsupported future",
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
			name:    "bad selector",
			data:    strings.Replace(valid, componentKey, strings.Replace(componentKey, "a_", "a_00", 1), 1),
			wantErr: "component_key",
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

func TestNormalizeRejectsDuplicateAttestorKeys(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x51}, 32)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	_, err = Normalize(Envelope{
		Kind:          Kind,
		SchemaVersion: SchemaVersion,
		Alias:         "attestor-local",
		Role:          RoleAttestation,
		URL:           "ssh://signer.example:2223",
		AttestorPublicKeys: []AttestorPublicKey{
			{
				KeyType:      keytypes.AttestorComponentEd25519V1,
				PublicKeyHex: hex.EncodeToString(publicKey),
				ComponentKey: componentKey,
			},
			{
				KeyType:      keytypes.AttestorComponentEd25519V1,
				PublicKeyHex: hex.EncodeToString(publicKey),
				ComponentKey: componentKey,
			},
		},
	})
	if err == nil {
		t.Fatal("Normalize() error = nil, want duplicate rejection")
	}
	if !strings.Contains(err.Error(), "duplicate public_key_hex") {
		t.Fatalf("Normalize() error = %q, want duplicate public_key_hex", err)
	}
}

func TestMarshalValidatesEnvelope(t *testing.T) {
	_, err := Marshal(Envelope{
		Kind:          Kind,
		SchemaVersion: SchemaVersion,
		Alias:         "attestor-local",
		Role:          RoleAttestation,
		URL:           "self",
	})
	if err == nil {
		t.Fatal("Marshal() error = nil, want validation error")
	}
}

func TestMarshalParseRoundTripStable(t *testing.T) {
	publicKey := bytes.Repeat([]byte{0x73}, 32)
	componentKey, err := keytypes.ComponentKeySelector(keytypes.AttestorComponentEd25519V1, publicKey)
	if err != nil {
		t.Fatalf("ComponentKeySelector() error = %v", err)
	}
	env := Envelope{
		Kind:          Kind,
		SchemaVersion: SchemaVersion,
		Alias:         "attestor-local",
		Role:          RoleAttestation,
		URL:           "ssh://signer.example:2223",
		SignerPort:    11270,
		LocalPort:     12001,
		AttestorPublicKeys: []AttestorPublicKey{{
			KeyType:      keytypes.AttestorComponentEd25519V1,
			PublicKeyHex: hex.EncodeToString(publicKey),
			ComponentKey: componentKey,
		}},
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
