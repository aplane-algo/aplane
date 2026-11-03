// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// retainFrameWriter keeps the input only to inspect cleanup after Write returns.
// Real io.Writer implementations must not retain their input buffer.
type retainFrameWriter struct {
	frame, written []byte
	err            error
	partial        bool
}

func (w *retainFrameWriter) Write(p []byte) (int, error) {
	w.frame = p
	w.written = bytes.Clone(p)
	if w.err != nil {
		if w.partial {
			return len(p) / 2, w.err
		}
		return 0, w.err
	}
	return len(p), nil
}

func TestWriteJSONLineClearsFramingBuffer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		partial bool
	}{
		{name: "success"},
		{name: "write error", err: io.ErrClosedPipe},
		{name: "partial write error", err: io.ErrShortWrite, partial: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`{"type":"export_result","mnemonic":"test recovery material"}`)
			original := bytes.Clone(payload)
			w := &retainFrameWriter{err: tc.err, partial: tc.partial}
			if err := WriteJSONLine(w, payload); !errors.Is(err, tc.err) {
				t.Fatalf("WriteJSONLine() error = %v, want %v", err, tc.err)
			}
			if !bytes.Equal(w.written, append(bytes.Clone(original), '\n')) {
				t.Fatal("writer received an incorrect frame")
			}
			if !bytes.Equal(w.frame, make([]byte, len(w.frame))) {
				t.Fatal("framing buffer retained recovery material after write")
			}
			if !bytes.Equal(payload, original) {
				t.Fatal("caller buffer was changed")
			}
		})
	}
}

func TestWriteJSONLineAndReadJSONLine(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte(`{"type":"status","state":"locked"}`)

	if err := WriteJSONLine(&buf, payload); err != nil {
		t.Fatalf("WriteJSONLine() error = %v", err)
	}
	if got := buf.Bytes(); len(got) == 0 || got[len(got)-1] != '\n' {
		t.Fatalf("WriteJSONLine() bytes = %q, want trailing newline", got)
	}

	line, err := NewFrameReader(&buf).ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if bytes.Contains(line, []byte{'\n'}) {
		t.Fatalf("ReadFrame() returned %q, want newline-trimmed payload", line)
	}
	if !bytes.Equal(line, payload) {
		t.Fatalf("ReadFrame() = %q, want %q", line, payload)
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

func TestReadFrameSizeLimit(t *testing.T) {
	atLimit := append(bytes.Repeat([]byte{'x'}, MaxAdminMessageBytes), '\n')
	if line, err := NewFrameReader(bytes.NewReader(atLimit)).ReadFrame(); err != nil || len(line) != MaxAdminMessageBytes {
		t.Fatalf("ReadFrame() at limit = %d bytes, %v", len(line), err)
	}
	over := append(bytes.Repeat([]byte{'x'}, MaxAdminMessageBytes+1), '\n')
	if _, err := NewFrameReader(bytes.NewReader(over)).ReadFrame(); err == nil {
		t.Fatal("ReadFrame() error = nil, want size rejection")
	}
}

// fragmentReader returns at most n bytes per Read, so frames span refills.
type fragmentReader struct {
	src io.Reader
	n   int
}

func (r *fragmentReader) Read(p []byte) (int, error) {
	if len(p) > r.n {
		p = p[:r.n]
	}
	return r.src.Read(p)
}

// assertNoSecret checks that no reader-owned buffer still holds frame bytes.
func assertNoSecret(t *testing.T, f *FrameReader, secret string) {
	t.Helper()
	if bytes.Contains(f.buf, []byte(secret)) {
		t.Fatalf("read buffer retained %q", secret)
	}
}

func TestReadFrameClearsFragmentedFrames(t *testing.T) {
	// Fragmented reads leave a partial frame buffered when the refill
	// happens: the case where bufio slides bytes and leaves copies behind.
	first := `{"mnemonic":"secret recovery phrase words"}`
	second := `{"type":"next","mnemonic":"other phrase"}`
	stream := first + "\n" + second + "\n"
	for _, chunk := range []int{1, 7, 16, len(first) + 3} {
		f := NewFrameReader(&fragmentReader{src: strings.NewReader(stream), n: chunk})
		line, err := f.ReadFrame()
		if err != nil || string(line) != first {
			t.Fatalf("chunk %d: first frame = %q, %v", chunk, line, err)
		}
		assertNoSecret(t, f, "secret")
		assertNoSecret(t, f, "words")
		line, err = f.ReadFrame()
		if err != nil || string(line) != second {
			t.Fatalf("chunk %d: second frame = %q, %v", chunk, line, err)
		}
		assertNoSecret(t, f, "other phrase")
	}
}

func TestReadFrameKeepsUnreadFramesAndClearsOnError(t *testing.T) {
	f := NewFrameReader(strings.NewReader("{\"a\":1}\n{\"mnemonic\":\"secret\""))
	if line, err := f.ReadFrame(); err != nil || string(line) != `{"a":1}` {
		t.Fatalf("first frame = %q, %v", line, err)
	}
	if !bytes.Contains(f.buf[f.r:f.w], []byte("secret")) {
		t.Fatal("unread bytes were cleared before they were framed")
	}
	if _, err := f.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF", err)
	}
	assertNoSecret(t, f, "secret")
	if _, err := f.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Fatalf("error is not sticky: %v", err)
	}
}

func TestReadFrameReturnsEmptyFrame(t *testing.T) {
	line, err := NewFrameReader(strings.NewReader("\n")).ReadFrame()
	if err != nil || line == nil || len(line) != 0 {
		t.Fatalf("empty frame = %#v, %v", line, err)
	}
}

func TestAppendClearingOldClearsOutgrownAllocation(t *testing.T) {
	line := make([]byte, 0, 8)
	line = append(line, "secret12"...)
	old := line[:cap(line)]
	grown := appendClearingOld(line, []byte("more"))
	if string(grown) != "secret12more" {
		t.Fatalf("grown = %q", grown)
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatal("outgrown line allocation retained frame bytes")
	}
}
