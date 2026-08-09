// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// MaxAdminMessageBytes bounds every IPC/SSH admin frame before JSON decode.
// Current messages are normally kilobytes; this leaves room for template and
// policy documents without permitting an authenticated or pre-auth peer to
// grow memory without bound.
const MaxAdminMessageBytes = 4 * 1024 * 1024

func WriteJSONLine(w io.Writer, data []byte) error {
	line := make([]byte, len(data)+1)
	copy(line, data)
	line[len(line)-1] = '\n'
	_, err := w.Write(line)
	return err
}

func ReadJSONLine(r *bufio.Reader) ([]byte, error) {
	line := make([]byte, 0, 4096)
	for {
		part, err := r.ReadSlice('\n')
		if len(line)+len(part) > MaxAdminMessageBytes+1 {
			return nil, fmt.Errorf("admin message exceeds %d-byte limit", MaxAdminMessageBytes)
		}
		line = append(line, part...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return line, nil
}
