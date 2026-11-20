// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
)

func (r *REPLState) executeAppDeploy(args []string) (command.Result, error) {
	params, err := parseAppDeployArgs(args)
	if err != nil {
		return nil, err
	}

	result, err := r.app().AppDeploy(r.commandContext(), params.AppDeployRequest)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range renderAppCallLines(result.PreSubmitLines, result.FromAddress, r) {
				r.println(line)
			}
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			if result.Submitted {
				r.printf("App deploy submitted: %s\n", result.Structured.TxID)
			}
			// apshellapp gives confirmed lines only to a deploy it saw
			// confirmed, with the app it created.
			for _, line := range renderAppCallLines(result.ConfirmedLines, result.FromAddress, r) {
				r.println(line)
			}
		})
	}, result.Structured)
}

// appDeployArgs is the deploy request the parser fills in.
type appDeployArgs struct {
	apshellapp.AppDeployRequest
}

func parseAppDeployArgs(args []string) (*appDeployArgs, error) {
	params := &appDeployArgs{Wait: true}
	if len(args) < 2 || args[0] != "from" || args[1] == "" {
		return nil, fmt.Errorf("usage: app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> global-uint=<n> global-bytes=<n> local-uint=<n> local-bytes=<n> [extra-pages=<n>] [note=<text>] [fee=<microalgos>] [nowait] [arg:[<account>:]<name>=<value>]")
	}
	params.From = args[1]

	// Every option app deploy takes, but arg:, is single-valued.
	seen := cmdspec.SeenOptions{}
	for _, arg := range args[2:] {
		if err := params.applyOption(seen, arg); err != nil {
			return nil, err
		}
	}

	return params, nil
}

// appDeployUintOption is a numeric option: its width and where it is stored.
type appDeployUintOption struct {
	bits int
	set  func(params *appDeployArgs, value uint64)
}

var appDeployUintOptions = map[string]appDeployUintOption{
	"global-uint":  {64, func(p *appDeployArgs, v uint64) { p.GlobalUint = v }},
	"global-bytes": {64, func(p *appDeployArgs, v uint64) { p.GlobalBytes = v }},
	"local-uint":   {64, func(p *appDeployArgs, v uint64) { p.LocalUint = v }},
	"local-bytes":  {64, func(p *appDeployArgs, v uint64) { p.LocalBytes = v }},
	"extra-pages":  {32, func(p *appDeployArgs, v uint64) { p.ExtraPages = uint32(v) }},
}

// applyOption applies one argument after the account.
func (a *appDeployArgs) applyOption(seen cmdspec.SeenOptions, arg string) error {
	if arg == "nowait" {
		a.Wait = false
		return nil
	}
	if name, value, ok := strings.Cut(arg, "="); ok {
		if handled, err := a.applyNamedOption(seen, name, value); handled {
			return err
		}
	}
	if strings.HasPrefix(arg, "arg:") {
		return cmdspec.AddLsigArg(&a.LsigArgs, arg)
	}
	return fmt.Errorf("unknown app deploy argument: %s", arg)
}

// applyNamedOption applies name=value when name is an option, and reports
// whether it was one.
func (a *appDeployArgs) applyNamedOption(seen cmdspec.SeenOptions, name, value string) (bool, error) {
	if option, known := appDeployUintOptions[name]; known {
		return true, a.setUint(seen, name, value, option)
	}
	return applyAppTxnOption(&a.AppTxnOptions, seen, name, value)
}

// setUint parses and stores a numeric option, once.
func (a *appDeployArgs) setUint(seen cmdspec.SeenOptions, name, value string, option appDeployUintOption) error {
	if err := seen.Once(name); err != nil {
		return err
	}
	parsed, err := strconv.ParseUint(value, 10, option.bits)
	if err != nil {
		return fmt.Errorf("invalid %s value: %s", name, value)
	}
	option.set(a, parsed)
	return nil
}
