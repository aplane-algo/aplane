// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package tui

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
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

type SSHAdminConnector struct {
	Host            string
	Port            int
	Token           string
	IdentityFile    string
	KnownHostsPath  string
	HostKeyApproval sshtunnel.HostKeyApprovalHandler
}

func (c SSHAdminConnector) Connect() (io.ReadWriteCloser, error) {
	client := sshtunnel.NewClient(c.Host, c.Port, 0, 0, c.IdentityFile, c.KnownHostsPath)
	client.SetIdentityID(auth.CurrentProductIdentityID())
	client.SetAPIToken(c.Token)
	if c.HostKeyApproval != nil {
		client.SetHostKeyApprovalHandler(c.HostKeyApproval)
	}
	if err := client.ConnectWithKey(context.Background()); err != nil {
		return nil, err
	}
	stream, err := client.OpenSubsystem(sshtunnel.AdminSubsystemName)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return stream, nil
}

func (c SSHAdminConnector) Label() string {
	return "SSH"
}

func dialUnixSocket(path string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to IPC socket: %w", err)
	}
	return conn, nil
}
