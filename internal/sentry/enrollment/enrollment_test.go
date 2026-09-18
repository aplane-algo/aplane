// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package enrollment

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/aplane-algo/aplane/internal/endpointrefs"
	"github.com/aplane-algo/aplane/internal/witness"
)

func TestMarshalParseRoundTripStable(t *testing.T) {
	reference := testReference(t)
	endpoint := endpointrefs.Envelope{
		Schema: endpointrefs.Schema, URL: "ssh://sentry.example:2223/", SignerPort: 11270,
	}

	first, err := Marshal(Envelope{Schema: Schema, Witness: reference, Endpoint: &endpoint})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Endpoint == nil || parsed.Endpoint.URL != "ssh://sentry.example:2223" {
		t.Fatalf("parsed endpoint = %#v", parsed.Endpoint)
	}
	second, err := Marshal(parsed)
	if err != nil {
		t.Fatalf("Marshal(parsed) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip changed envelope:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestParseAcceptsWitnessOnlyBundle(t *testing.T) {
	data, err := Marshal(Envelope{Schema: Schema, Witness: testReference(t)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Endpoint != nil {
		t.Fatalf("Endpoint = %#v, want nil", parsed.Endpoint)
	}
}

func TestParseArtifactSupportsLegacyAndCombined(t *testing.T) {
	reference := testReference(t)
	legacy, err := MarshalWitness(reference)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := Marshal(Envelope{Schema: Schema, Witness: reference})
	if err != nil {
		t.Fatal(err)
	}

	legacyArtifact, err := ParseArtifact(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if legacyArtifact.Combined || legacyArtifact.Endpoint != nil || legacyArtifact.Witness != reference {
		t.Fatalf("legacy artifact = %#v", legacyArtifact)
	}
	combinedArtifact, err := ParseArtifact(combined)
	if err != nil {
		t.Fatal(err)
	}
	if !combinedArtifact.Combined || combinedArtifact.Witness != reference {
		t.Fatalf("combined artifact = %#v", combinedArtifact)
	}
}

func TestParseRejectsInvalidEnvelope(t *testing.T) {
	reference, err := MarshalWitness(testReference(t))
	if err != nil {
		t.Fatal(err)
	}
	witnessJSON := strings.TrimSpace(string(reference))
	valid := `{"schema":"` + Schema + `","witness":` + witnessJSON + `}`

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{name: "unknown outer field", data: strings.TrimSuffix(valid, "}") + `,"token":"secret"}`, wantErr: "unknown field"},
		{name: "unknown witness field", data: strings.Replace(valid, `"public_key_hex":`, `"private_key_hex":"00","public_key_hex":`, 1), wantErr: "unknown field"},
		{name: "unknown endpoint field", data: strings.TrimSuffix(valid, "}") + `,"endpoint":{"schema":"aplane.endpoint.v1","url":"ssh://sentry.example","role":"sentry"}}`, wantErr: "unknown field"},
		{name: "unsupported outer schema", data: strings.Replace(valid, Schema, "aplane.sentry-enrollment.v2", 1), wantErr: "unsupported sentry enrollment schema"},
		{name: "missing witness", data: `{"schema":"` + Schema + `"}`, wantErr: "witness is required"},
		{name: "null witness", data: `{"schema":"` + Schema + `","witness":null}`, wantErr: "must not be null"},
		{name: "null endpoint", data: strings.TrimSuffix(valid, "}") + `,"endpoint":null}`, wantErr: "endpoint must not be null"},
		{name: "trailing JSON", data: valid + `{}`, wantErr: "multiple JSON values"},
		{name: "non-portable endpoint", data: strings.TrimSuffix(valid, "}") + `,"endpoint":{"schema":"aplane.endpoint.v1","url":"http://sentry.example"}}`, wantErr: "raw http endpoints must be loopback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Parse() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseRejectsMismatchedWitnessIdentity(t *testing.T) {
	data, err := Marshal(Envelope{Schema: Schema, Witness: testReference(t)})
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(data, []byte(`"witness_key_id": "`), []byte(`"witness_key_id": "A`), 1)
	if _, err := Parse(mutated); err == nil || !strings.Contains(err.Error(), "key ID") {
		t.Fatalf("Parse() error = %v, want key ID rejection", err)
	}
}

func TestParseRejectsOversizeBeforeDecode(t *testing.T) {
	if _, err := Parse(bytes.Repeat([]byte("x"), MaxEnvelopeBytes+1)); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("Parse() error = %v, want size rejection", err)
	}
}

func FuzzParse(f *testing.F) {
	reference := testReference(f)
	data, err := Marshal(Envelope{Schema: Schema, Witness: reference})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Parse(input)
	})
}

type testTB interface {
	Helper()
	Fatalf(string, ...any)
}

func testReference(tb testTB) witness.PublicReference {
	tb.Helper()
	publicKey := bytes.Repeat([]byte{0x42}, 1793)
	keyID, err := witness.ID(witness.Falcon1024V1, publicKey)
	if err != nil {
		tb.Fatalf("witness.ID() error = %v", err)
	}
	reference, err := witness.NewPublicReference(witness.Falcon1024V1, keyID, hex.EncodeToString(publicKey))
	if err != nil {
		tb.Fatalf("witness.NewPublicReference() error = %v", err)
	}
	return reference
}
