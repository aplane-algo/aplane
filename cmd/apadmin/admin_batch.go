// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/transport"
	"golang.org/x/term"
)

type adminBatchGlobalOptions struct {
	dataDir       string
	clientDataDir string
	ipcPath       string
	remote        bool
}

type adminBatchStreams struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type adminBatchPrompt struct {
	stdin  io.Reader
	reader *bufio.Reader
	stderr io.Writer
}

func newAdminBatchPrompt(stdin io.Reader, stderr io.Writer) *adminBatchPrompt {
	return &adminBatchPrompt{stdin: stdin, reader: bufio.NewReader(stdin), stderr: stderr}
}

func (p *adminBatchPrompt) passphrase(remote bool) ([]byte, error) {
	if !remote {
		if value := os.Getenv("APSIGNER_PASSPHRASE"); value != "" {
			return []byte(value), nil
		}
	}
	if file, ok := p.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		_, _ = fmt.Fprint(p.stderr, "Enter store passphrase: ")
		secret, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(p.stderr)
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		return secret, nil
	}
	line, err := p.reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	secret := []byte(strings.TrimSpace(line))
	if len(secret) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	return secret, nil
}

func (p *adminBatchPrompt) confirm(message string) bool {
	_, _ = fmt.Fprint(p.stderr, message)
	line, _ := p.reader.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func runCatalogCommand(command string, args []string, globals adminBatchGlobalOptions, streams adminBatchStreams) int {
	mode, err := apadminapp.CatalogAuthMode(command, args)
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 2
	}

	prompt := newAdminBatchPrompt(streams.stdin, streams.stderr)
	passphrase, err := prompt.passphrase(globals.remote)
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	defer crypto.ZeroBytes(passphrase)

	if globals.remote {
		sshtunnel.SetStatusWriter(io.Discard)
		defer sshtunnel.SetStatusWriter(nil)
	}
	session, err := selectAdminTransport(globals)
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	client, err := apadminapp.Open(session, passphrase, mode)
	if err != nil {
		if globals.remote {
			err = formatRemoteConnectError(err)
		}
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	defer client.Close()

	err = (apadminapp.Catalog{
		Client:  client,
		Streams: apadminapp.Streams{Stdout: streams.stdout, Stderr: streams.stderr},
		Confirm: prompt.confirm,
	}).Run(command, args)
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	return 0
}

func selectAdminTransport(globals adminBatchGlobalOptions) (transport.Transport, error) {
	if globals.remote {
		cfg, err := loadRemoteAdminConfig(globals.clientDataDir)
		if err != nil {
			return nil, err
		}
		return transport.NewSSHAdmin(
			cfg.ssh.Host, cfg.ssh.Port, cfg.token, cfg.ssh.IdentityFile, cfg.ssh.KnownHostsPath,
		), nil
	}
	dataDir := serverconfig.GetSignerDataDir(globals.dataDir)
	ipcPath, err := adminipc.ResolveClientPath(adminipc.ClientPathRequest{
		DataDir: dataDir, IPCPath: globals.ipcPath, DataDirExplicit: globals.dataDir != "",
	})
	if err != nil {
		return nil, err
	}
	return transport.NewIPC(ipcPath), nil
}
