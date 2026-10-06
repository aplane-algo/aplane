// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/adminipc"
	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/policycmd"
	"github.com/aplane-algo/aplane/internal/transport"
)

type policyGlobalOptions struct {
	dataDir       string
	ipcPath       string
	ipcPathPassed bool
}

type policyStreams struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

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
	command.DataDir = globals.dataDir
	ioStreams := policycmd.Streams{Stdin: streams.stdin, Stdout: streams.stdout, Stderr: streams.stderr}

	if rescue {
		if globals.ipcPathPassed {
			writePolicyError(streams.stderr, fmt.Errorf("policy rescue cannot use --ipc-path"))
			return 2
		}
		dataDir, err := signerbootstrap.ResolveDataDir(globals.dataDir)
		if err != nil {
			writePolicyError(streams.stderr, err)
			return 1
		}
		command.DataDir = dataDir
		if err := (policycmd.RescueRunner{}).Run(ctx, command, ioStreams); err != nil {
			writePolicyError(streams.stderr, err)
			return 1
		}
		return 0
	}

	dataDir := serverconfig.GetSignerDataDir(globals.dataDir)
	ipcPath, err := adminipc.ResolveClientPath(adminipc.ClientPathRequest{
		DataDir: dataDir, IPCPath: globals.ipcPath, DataDirExplicit: globals.dataDir != "",
	})
	if err != nil {
		writePolicyError(streams.stderr, err)
		return 1
	}
	session := transport.NewIPC(ipcPath)
	if err := (policycmd.OnlineRunner{Session: session}).Run(ctx, command, ioStreams); err != nil {
		writePolicyError(streams.stderr, err)
		return 1
	}
	return 0
}

func parsePolicyCommand(args []string, stderr io.Writer) (policycmd.Command, bool, error) {
	var command policycmd.Command
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
		case "--check", "--yaml", "--sha256", "--save", "--to-cosigner", "--online", "--target":
			return command, rescue, fmt.Errorf("%s is retired; use an apadmin policy verb (status, export, check, diff, apply, remove, or template)", arg)
		}
	}
	fs := flag.NewFlagSet("apadmin policy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mode := ""
	if rescue {
		mode = " rescue"
	}
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, `Usage: apadmin [GLOBAL FLAGS] policy%s VERB [ARGS]

Verbs:
  status            list the node's policy documents and cosigner key coverage
  export [--key ID] write one policy document exactly as stored
  check FILE...     validate policy files against the node
  diff FILE...|-    describe how policy files differ from the active policy
  apply FILE...|-   check, show the diff, confirm, then replace documents in one commit
  remove ID...      show the diff, confirm, then delete cosigner keys' policies
  template [--key ID] signer|cosigner
                    write an annotated starting document for that node role,
                    with every field explained in comments and an example
                    route commented out; --key names the cosigner key

apply and remove ask for confirmation on the terminal; --yes skips it.
template needs no node and no passphrase.

A signer node takes one policy.json file. On a cosigner node each file is one
key's document and names that key in its "key" field; apply leaves documents
for other keys unchanged. Policy files may carry // and /* */ comments, which
apadmin removes before the document reaches the node.

Online commands authenticate and unlock before policy access; local IPC may use
APSIGNER_PASSPHRASE. IPC commands may read one passphrase line from stdin.
When applying policy from stdin, use APSIGNER_PASSPHRASE or a controlling terminal
so the policy document and passphrase stay separate.
Policy rescue commands access the store directly, require a stopped daemon for
apply and remove, and reject --ipc-path.

`, mode)
	}
	key := fs.String("key", "", "Witness Key ID of the cosigner document to export, or to name in a cosigner template")
	yes := fs.Bool("yes", false, "apply or remove without asking for confirmation")
	if err := fs.Parse(args); err != nil {
		return command, rescue, err
	}
	if command.Verb == "" {
		return command, rescue, fmt.Errorf("policy requires a verb: status, export, check, diff, apply, remove, or template")
	}
	command.Key = *key
	command.Yes = *yes
	command.Args = fs.Args()
	if err := command.Validate(); err != nil {
		return command, rescue, err
	}
	return command, rescue, nil
}

func writePolicyError(stderr io.Writer, err error) {
	_, _ = fmt.Fprintf(stderr, "apadmin: %v\n", err)
}
