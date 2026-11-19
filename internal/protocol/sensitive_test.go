// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"encoding/json"
	"testing"
)

// MarshalJSON writes the value itself, so it must not detour through
// json.Marshal's HTML escaping (or its string copy and pooled buffer).
func TestSensitiveBytesMarshalJSONWritesWithoutHTMLEscaping(t *testing.T) {
	got, err := NewSensitiveBytes(`<a&b>`).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	if want := `"<a&b>"`; string(got) != want {
		t.Fatalf("MarshalJSON() = %s, want %s", got, want)
	}
	if cap(got) != len(got) {
		t.Fatalf("MarshalJSON() buffer cap %d, want exactly its length %d", cap(got), len(got))
	}
}

// The hand-written encoder must decode to exactly what encoding/json's
// encoding of the same text decodes to, for every escape it handles.
func TestSensitiveBytesMarshalJSONMatchesEncodingJSON(t *testing.T) {
	for _, value := range []string{
		"",
		"plain passphrase",
		"quote\" backslash\\ slash/",
		"\x00\x01\x1f\b\f\n\r\t",
		"   separators",
		"päss ⚠ \U0001f510",
		"bad \xff utf-8 \xc3",
		"\x7f del",
	} {
		got, err := NewSensitiveBytes(value).MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON(%q) error = %v", value, err)
		}
		if !json.Valid(got) {
			t.Fatalf("MarshalJSON(%q) = %s, not valid JSON", value, got)
		}
		want, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var gotText, wantText string
		if err := json.Unmarshal(got, &gotText); err != nil {
			t.Fatalf("decode MarshalJSON(%q): %v", value, err)
		}
		if err := json.Unmarshal(want, &wantText); err != nil {
			t.Fatal(err)
		}
		if gotText != wantText {
			t.Fatalf("MarshalJSON(%q) decodes to %q, encoding/json gives %q", value, gotText, wantText)
		}
		var decoded SensitiveBytes
		if err := json.Unmarshal(got, &decoded); err != nil || string(decoded) != wantText {
			t.Fatalf("SensitiveBytes round trip of %q = %q, %v", value, decoded, err)
		}
	}
}

// A string cut off by a bad escape must not leave the part decoded so far in
// the dropped buffer.
func TestDecodeJSONStringBytesZeroesPartialValueOnError(t *testing.T) {
	for _, data := range []string{
		`"secret-prefix\q"`,
		`"secret-prefix\u12zz"`,
		`"secret-prefix` + "\x01" + `"`,
		`"secret-prefix\ud800"`,
	} {
		out := make([]byte, 0, len(data))
		if _, err := decodeJSONStringBytes(out, []byte(data)); err == nil {
			t.Fatalf("decodeJSONStringBytes(%q) accepted a bad string", data)
		}
		if !bytes.Equal(out[:cap(out)], make([]byte, cap(out))) {
			t.Fatalf("decodeJSONStringBytes(%q) left %q in its buffer", data, out[:cap(out)])
		}
	}
}
