// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/apadminapp"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/protocol"
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
	return p.secret("Enter store passphrase: ", !remote)
}

func (p *adminBatchPrompt) secret(message string, allowEnvironment bool) ([]byte, error) {
	if allowEnvironment {
		if value := os.Getenv("APSIGNER_PASSPHRASE"); value != "" {
			return []byte(value), nil
		}
	}
	var secret []byte
	if file, ok := p.stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		_, _ = fmt.Fprint(p.stderr, message)
		var err error
		secret, err = term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(p.stderr)
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
	} else {
		line, err := p.reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		secret = []byte(strings.TrimSpace(line))
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}
	return secret, nil
}

func (p *adminBatchPrompt) confirmed(first, second string, allowEnvironment bool) ([]byte, error) {
	secret, err := p.secret(first, allowEnvironment)
	if err != nil {
		return nil, err
	}
	confirmation, err := p.secret(second, allowEnvironment)
	if err != nil {
		crypto.ZeroBytes(secret)
		return nil, err
	}
	defer crypto.ZeroBytes(confirmation)
	if !bytes.Equal(secret, confirmation) {
		crypto.ZeroBytes(secret)
		return nil, fmt.Errorf("passphrases do not match")
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
		return adminBatchExitCode(err)
	}
	return 0
}

func runStoreCommand(command string, args []string, globals adminBatchGlobalOptions, streams adminBatchStreams) int {
	mode, err := apadminapp.StoreAuthMode(command, args)
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 2
	}
	prompt := newAdminBatchPrompt(streams.stdin, streams.stderr)

	var current, next []byte
	if command == changePassSubcommand {
		current, err = prompt.secret("Enter current passphrase: ", false)
		if err == nil {
			next, err = prompt.confirmed("Enter new passphrase: ", "Confirm new passphrase: ", false)
		}
		if err == nil && bytes.Equal(current, next) {
			err = fmt.Errorf("new passphrase must be different from current passphrase")
		}
		if err == nil && !prompt.confirm("Proceed with passphrase change? [y/N]: ") {
			_, _ = fmt.Fprintln(streams.stderr, "passphrase change cancelled")
			crypto.ZeroBytes(current)
			crypto.ZeroBytes(next)
			return 0
		}
	} else {
		current, err = prompt.passphrase(globals.remote)
	}
	if err != nil {
		crypto.ZeroBytes(current)
		crypto.ZeroBytes(next)
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	defer crypto.ZeroBytes(current)
	defer crypto.ZeroBytes(next)

	if globals.remote {
		sshtunnel.SetStatusWriter(io.Discard)
		defer sshtunnel.SetStatusWriter(nil)
	}
	session, err := selectAdminTransport(globals)
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	client, err := apadminapp.Open(session, current, mode)
	if err != nil {
		if globals.remote {
			err = formatRemoteConnectError(err)
		}
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return 1
	}
	defer client.Close()

	store := apadminapp.Store{
		Client:  client,
		Streams: apadminapp.Streams{Stdout: streams.stdout, Stderr: streams.stderr},
		ReadSecret: func(message string) ([]byte, error) {
			return prompt.secret(message, false)
		},
		ReadConfirmed: func(first, second string) ([]byte, error) {
			return prompt.confirmed(first, second, false)
		},
		Confirm: prompt.confirm,
	}
	switch command {
	case backupSubcommand:
		err = store.RunBackup(args)
	case restoreSubcommand:
		err = store.RunRestore(args)
	case changePassSubcommand:
		err = store.ChangePassphrase(current, next)
	}
	if err != nil {
		_, _ = fmt.Fprintf(streams.stderr, "apadmin: %v\n", err)
		return adminBatchExitCode(err)
	}
	return 0
}

func adminBatchExitCode(err error) int {
	switch protocol.CodeForError(err) {
	case protocol.ErrCodeAuthenticationFailed,
		protocol.ErrCodeInvalidPassphrase,
		protocol.ErrCodeUnlockFailed,
		protocol.ErrCodeAuthorizationDenied,
		protocol.ErrCodeSignerLocked,
		protocol.ErrCodeNoIdentityBound:
		return 3
	case protocol.ResultCodeRestoreRateLimited:
		return 4
	case protocol.ResultCodeKeyTypeInUse,
		protocol.ResultCodeActivationFailed,
		protocol.ResultCodeDeactivationFailed,
		protocol.ResultCodeRemoveFailed,
		protocol.ResultCodeRestoreConflict,
		protocol.ResultCodeRestoreRollbackDiverged:
		return 5
	case "verification_failed", "invalid_backup", "corrupt_archive", "bad_export_passphrase", "unsupported_backup_format":
		return 6
	case protocol.ErrCodeInvalidMessageFormat,
		protocol.ErrCodeInvalidAuthMessage,
		protocol.ErrCodeInvalidRequest,
		protocol.ErrCodeUnknownMessageType:
		return 2
	default:
		return 1
	}
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
