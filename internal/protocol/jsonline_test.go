// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bufio"
	"bytes"
	"testing"
)

func TestWriteJSONLineAndReadJSONLine(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"type":"status","state":"locked"}`)

	if err := WriteJSONLine(&buf, payload); err != nil {
		t.Fatalf("WriteJSONLine() error = %v", err)
	}
	if got := buf.Bytes(); len(got) == 0 || got[len(got)-1] != '\n' {
		t.Fatalf("WriteJSONLine() bytes = %q, want trailing newline", got)
	}

	line, err := ReadJSONLine(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("ReadJSONLine() error = %v", err)
	}
	if bytes.Contains(line, []byte{'\n'}) {
		t.Fatalf("ReadJSONLine() returned %q, want newline-trimmed payload", line)
	}
	if !bytes.Equal(line, payload) {
		t.Fatalf("ReadJSONLine() = %q, want %q", line, payload)
	}
}

func TestWriteJSONLineDoesNotMutateCallerBuffer(t *testing.T) {
	var buf bytes.Buffer
	raw := []byte(`{"type":"status"}`)
	backing := append(append([]byte(nil), raw...), 'X')
	payload := backing[:len(raw)]

	if err := WriteJSONLine(&buf, payload); err != nil {
		t.Fatalf("WriteJSONLine() error = %v", err)
	}
	if !bytes.Equal(payload, raw) {
		t.Fatalf("payload = %q, want unchanged %q", payload, raw)
	}
	if backing[len(raw)] != 'X' {
		t.Fatalf("backing guard byte = %q, want X", backing[len(raw)])
	}
}
