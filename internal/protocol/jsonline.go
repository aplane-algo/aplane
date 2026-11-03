// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bytes"
	"fmt"
	"io"
)

// MaxAdminMessageBytes bounds every IPC admin frame before JSON decode.
// Current messages are normally kilobytes; this leaves room for template and
// policy documents without permitting an authenticated or pre-auth peer to
// grow memory without bound.
const MaxAdminMessageBytes = 4 * 1024 * 1024

func WriteJSONLine(w io.Writer, data []byte) error {
	line := make([]byte, len(data)+1)
	defer SensitiveBytes(line).Zero()
	copy(line, data)
	line[len(line)-1] = '\n'
	_, err := w.Write(line)
	return err
}

// frameReadSize is the FrameReader read-buffer size.
const frameReadSize = 4096

// FrameReader reads bounded, newline-delimited admin frames. It replaces
// bufio.Reader for admin streams because frames carry passphrases and
// recovery phrases: bufio slides partial frames to the front of its buffer on
// refill and leaves the originals behind, out of reach. FrameReader refills
// only when its buffer is empty, so it never moves bytes, and it clears every
// byte it consumes and every outgrown line allocation. The returned frame is
// therefore the only mutable copy it leaves.
type FrameReader struct {
	src  io.Reader
	buf  []byte
	r, w int
	err  error
}

// NewFrameReader wraps src for admin frame reads.
func NewFrameReader(src io.Reader) *FrameReader {
	return &FrameReader{src: src, buf: make([]byte, frameReadSize)}
}

// ReadFrame reads one bounded admin frame without its trailing newline. Any
// error invalidates framing: callers must close the connection and must not
// reuse the reader. In particular, it deliberately does not drain an
// oversized unterminated frame, which could otherwise let a malicious peer
// block the reader indefinitely.
func (f *FrameReader) ReadFrame() ([]byte, error) {
	var line []byte
	fail := func(err error) ([]byte, error) {
		SensitiveBytes(line).Zero()
		f.discardBuffered()
		f.err = err
		return nil, err
	}
	for {
		buffered := f.buf[f.r:f.w]
		if i := bytes.IndexByte(buffered, '\n'); i >= 0 {
			if len(line)+i > MaxAdminMessageBytes {
				return fail(fmt.Errorf("admin message exceeds %d-byte limit", MaxAdminMessageBytes))
			}
			line = appendClearingOld(line, buffered[:i])
			f.consume(i + 1)
			if line == nil {
				line = []byte{}
			}
			return line, nil
		}
		if len(line)+len(buffered) > MaxAdminMessageBytes {
			return fail(fmt.Errorf("admin message exceeds %d-byte limit", MaxAdminMessageBytes))
		}
		line = appendClearingOld(line, buffered)
		f.consume(len(buffered))
		if f.err != nil {
			return fail(f.err)
		}
		// The buffer is empty: refill from the start, never sliding bytes.
		n, err := f.src.Read(f.buf)
		f.w = n
		// Bytes read alongside an error are framed before it is reported.
		f.err = err
	}
}

// consume clears and releases n buffered bytes.
func (f *FrameReader) consume(n int) {
	SensitiveBytes(f.buf[f.r : f.r+n]).Zero()
	f.r += n
	if f.r == f.w {
		f.r, f.w = 0, 0
	}
}

func (f *FrameReader) discardBuffered() {
	f.consume(f.w - f.r)
}

// appendClearingOld appends part to line, clearing line's old backing array
// when growth moves it, so no abandoned allocation retains frame bytes.
func appendClearingOld(line, part []byte) []byte {
	if len(line)+len(part) <= cap(line) {
		return append(line, part...)
	}
	grown := make([]byte, len(line), max(2*cap(line), len(line)+len(part)))
	copy(grown, line)
	SensitiveBytes(line[:cap(line)]).Zero()
	return append(grown, part...)
}
