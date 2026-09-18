// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"fmt"
	"io"
	"net"
)

// AdminConnector establishes the stream used for adminproto.
type AdminConnector interface {
	Connect() (io.ReadWriteCloser, error)
	Label() string
}

type LocalIPCConnector struct {
	Path string
}

func (c LocalIPCConnector) Connect() (io.ReadWriteCloser, error) {
	return dialUnixSocket(c.Path)
}

func (c LocalIPCConnector) Label() string {
	return "IPC"
}

func dialUnixSocket(path string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC socket: %w", err)
	}
	return conn, nil
}
