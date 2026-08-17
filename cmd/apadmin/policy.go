// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/auth"
	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/policy"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policycmd"
	"github.com/aplane-algo/aplane/internal/signerapp/policyeditor"
	"github.com/aplane-algo/aplane/internal/signerapp/policytui"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/transport"
	tea "github.com/charmbracelet/bubbletea"
)

type policyGlobalOptions struct {
	dataDir          string
	clientDataDir    string
	ipcPath          string
	remote           bool
	clientDataPassed bool
	ipcPathPassed    bool
}

type policyStreams struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

var setPolicySSHStatusWriter = sshtunnel.SetStatusWriter

func runPolicyCommand(ctx context.Context, args []string, globals policyGlobalOptions, streams policyStreams) int {
	command, rescue, err := parsePolicyCommand(args, streams.stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		writePolicyError(streams.stderr, err)
		return 2
	}
	if err := policycmd.RejectRetiredEnvironment(); err != nil {
		writePolicyError(streams.stderr, err)
		return 2
	}
	command.Remote = globals.remote
	command.DataDir = globals.dataDir
	ioStreams := policycmd.Streams{Stdin: streams.stdin, Stdout: streams.stdout, Stderr: streams.stderr}
	editor := launchPolicyEditor

	if rescue {
		if globals.remote || globals.clientDataPassed || globals.ipcPathPassed {
			writePolicyError(streams.stderr, fmt.Errorf("policy rescue cannot use --remote, --client-data, or --ipc-path"))
			return 2
		}
		if needsPolicyDataDir(command) {
			dataDir, err := signerbootstrap.ResolveDataDir(globals.dataDir)
			if err != nil {
				writePolicyError(streams.stderr, err)
				return 2
			}
			command.DataDir = dataDir
		}
		if err := (policycmd.RescueRunner{Editor: editor}).Run(ctx, command, ioStreams); err != nil {
			writePolicyError(streams.stderr, err)
			return 1
		}
		return 0
	}

	var session policycmd.OnlineSession
	if globals.remote {
		// The SSH client emits lifecycle and identity-key status outside the
		// admin protocol. Keep machine-readable policy stdout and the editor's
		// alternate screen isolated for the complete remote command lifetime.
		setPolicySSHStatusWriter(io.Discard)
		defer setPolicySSHStatusWriter(nil)
		remoteCfg, err := loadRemoteAdminConfig(globals.clientDataDir)
		if err != nil {
			writePolicyError(streams.stderr, err)
			return 1
		}
		session = transport.NewSSHAdmin(
			remoteCfg.ssh.Host,
			remoteCfg.ssh.Port,
			remoteCfg.token,
			remoteCfg.ssh.IdentityFile,
			remoteCfg.ssh.KnownHostsPath,
		)
	} else {
		dataDir := serverconfig.GetSignerDataDir(globals.dataDir)
		ipcPath, err := adminipc.ResolveClientPath(adminipc.ClientPathRequest{
			DataDir: dataDir, IPCPath: globals.ipcPath, DataDirExplicit: globals.dataDir != "",
		})
		if err != nil {
			writePolicyError(streams.stderr, err)
			return 1
		}
		session = transport.NewIPC(ipcPath)
	}
	if err := (policycmd.OnlineRunner{Session: session, Editor: editor}).Run(ctx, command, ioStreams); err != nil {
		if globals.remote {
			err = formatRemoteConnectError(err)
		}
		writePolicyError(streams.stderr, err)
		return 1
	}
	return 0
}

func parsePolicyCommand(args []string, stderr io.Writer) (policycmd.Command, bool, error) {
	command := policycmd.Command{Verb: policycmd.VerbEdit, Target: policyeditor.TargetAuto}
	rescue := false
	if len(args) > 0 && args[0] == "rescue" {
		rescue = true
		args = args[1:]
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		verb, err := policycmd.ParseVerb(args[0])
		if err != nil {
			return command, rescue, err
		}
		command.Verb = verb
		args = args[1:]
	}
	for _, arg := range args {
		switch arg {
		case "--check", "--yaml", "--sha256", "--save", "--to-sentry", "--online":
			return command, rescue, fmt.Errorf("%s is retired; use an apadmin policy verb (check, export, digest, apply, or to-sentry)", arg)
		}
	}
	fs := flag.NewFlagSet("apadmin policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := ""
	if rescue {
		mode = " rescue"
	}
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, `Usage: apadmin [GLOBAL FLAGS] policy%s [VERB] [--target auto|signer|sentry] [FILE|-]

Verbs:
  edit [FILE]       open the guided editor (default)
  check [FILE]      validate policy
  export [FILE]     write exact validated YAML
  digest [FILE]     write the exact YAML SHA-256 digest
  apply FILE|-      validate and replace production policy
  to-sentry [FILE]  convert signer policy to sentry policy

Online commands authenticate and unlock before policy access; local IPC may use
APSIGNER_PASSPHRASE, while --remote requires the controlling terminal. Policy
rescue commands access the store directly, require a stopped daemon for
production edits, and reject --remote, --client-data, and --ipc-path.
`, mode)
	}
	targetRaw := fs.String("target", "auto", "policy target: auto, signer, or sentry")
	if err := fs.Parse(args); err != nil {
		return command, rescue, err
	}
	target, err := policyeditor.ParseTarget(*targetRaw)
	if err != nil {
		return command, rescue, err
	}
	command.Target = target
	sources := fs.Args()
	if len(sources) > 1 {
		return command, rescue, fmt.Errorf("policy %s accepts at most one YAML file", command.Verb)
	}
	if len(sources) == 1 {
		command.Source = sources[0]
	}
	if err := command.Validate(); err != nil {
		return command, rescue, err
	}
	return command, rescue, nil
}

func needsPolicyDataDir(command policycmd.Command) bool {
	if command.Verb == policycmd.VerbApply || command.Source == "" {
		return true
	}
	return command.DataDir != "" || os.Getenv("APSIGNER_DATA") != ""
}

func launchPolicyEditor(store policyeditor.Store, stored *policy.StoredConfig, dataDir, identityID string, target policyeditor.Target) error {
	if identityID == "" {
		identityID = auth.CurrentProductIdentityID()
	}
	program := tea.NewProgram(
		policytui.NewWithTarget(store, stored, dataDir, identityID, target),
		tea.WithAltScreen(),
	)
	_, err := program.Run()
	return err
}

func writePolicyError(stderr io.Writer, err error) {
	_, _ = fmt.Fprintf(stderr, "apadmin: %v\n", err)
}
