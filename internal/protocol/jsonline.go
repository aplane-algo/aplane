// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package protocol

import (
	"bufio"
	"io"
)

func WriteJSONLine(w io.Writer, data []byte) error {
	line := make([]byte, len(data)+1)
	copy(line, data)
	line[len(line)-1] = '\n'
	_, err := w.Write(line)
	return err
}

func ReadJSONLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	return line, nil
}
