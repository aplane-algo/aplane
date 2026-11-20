// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Each malformed envelope is refused with the message its parse step gives.
func TestEnvelopeParseErrors(t *testing.T) {
	passphrase := []byte("pass")
	standalone, err := EncryptStandalone([]byte("data"), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	var fields EncryptedDataStandalone
	if err := json.Unmarshal(standalone, &fields); err != nil {
		t.Fatal(err)
	}
	fields.KDFMemory++
	wrongKDF, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}

	kr, err := NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	defer kr.Zero()
	sealed, err := kr.Seal([]byte("secret"), envelopeTestContext)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, sealed); err != nil {
		t.Fatal(err)
	}
	withField := bytes.Replace(sealed, []byte("{\n"), []byte("{\n  \"extra\": 1,\n"), 1)
	noTerm := bytes.Replace(sealed, fmt.Appendf(nil, `"term": %d`, kr.CurrentTerm()), []byte(`"term": 0`), 1)
	otherTerm := bytes.Replace(sealed, fmt.Appendf(nil, `"term": %d`, kr.CurrentTerm()), fmt.Appendf(nil, `"term": %d`, kr.CurrentTerm()+1), 1)

	open := func(data []byte) error {
		_, err := kr.Open(data, envelopeTestContext)
		return err
	}
	inspect := func(data []byte) error {
		_, _, err := InspectTermEnvelope(data)
		return err
	}
	tests := []struct {
		name string
		err  error
		want string // the whole message, or its start when it ends in ": "
	}{
		{"standalone with a trailing value", func() error {
			_, err := DecryptStandalone(append(bytes.Clone(standalone), []byte(" {}")...), passphrase)
			return err
		}(), "failed to parse encrypted data: trailing data after JSON document"},
		{"standalone with an unknown field", func() error {
			_, err := DecryptStandalone(bytes.Replace(standalone, []byte("{\n"), []byte("{\n  \"extra\": 1,\n"), 1), passphrase)
			return err
		}(), `failed to parse encrypted data: json: unknown field "extra"`},
		{"standalone with other KDF parameters", func() error {
			_, err := DecryptStandalone(wrongKDF, passphrase)
			return err
		}(), fmt.Sprintf(
			"standalone envelope KDF parameters (%d, %d, %d) are not this release's (%d, %d, %d)",
			argon2Time, argon2Memory+1, argon2Threads, argon2Time, argon2Memory, argon2Threads,
		)},
		{"a standalone envelope opened as a term envelope", open(standalone), "envelope_version 2 is not a term envelope (expected 3)"},
		{"a term envelope that is not JSON", open([]byte("not json")), "failed to parse encrypted data: "},
		{"a term envelope with an unknown field", open(withField), `failed to parse encrypted data: json: unknown field "extra"`},
		{"a term envelope that is not canonical", open(compact.Bytes()), "failed to parse encrypted data: term envelope is not canonical JSON"},
		{"a term envelope with no term", open(noTerm), "failed to parse encrypted data: term envelope has no term"},
		{"a term envelope under another term", open(otherTerm), fmt.Sprintf("term %d is not authorized for current state", kr.CurrentTerm()+1)},
		{"inspecting a version that is not a number", inspect([]byte(`{"envelope_version":"3"}`)), "failed to parse encrypted data: json: cannot unmarshal string into Go struct field .envelope_version of type int"},
		{"inspecting a standalone envelope", inspect(standalone), "envelope_version 2 is not a term envelope (expected 3)"},
		{"inspecting a term envelope with no term", inspect(noTerm), "failed to parse encrypted data: term envelope has no term"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatalf("accepted, want %q", tt.want)
			}
			got := tt.err.Error()
			if strings.HasSuffix(tt.want, ": ") {
				if !strings.HasPrefix(got, tt.want) {
					t.Fatalf("error = %q, want one starting %q", got, tt.want)
				}
			} else if got != tt.want {
				t.Fatalf("error = %q, want %q", got, tt.want)
			}
		})
	}
}
