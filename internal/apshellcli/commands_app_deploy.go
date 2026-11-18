// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/appinput"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
	"github.com/aplane-algo/aplane/internal/command"
)

func (r *REPLState) executeAppDeploy(args []string) (command.Result, error) {
	params, err := parseAppDeployArgs(args)
	if err != nil {
		return nil, err
	}

	result, err := r.app().AppDeploy(r.commandContext(), params.toAppRequest())
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
			if params.Wait && result.Structured.Confirmed {
				for _, line := range renderAppCallLines(result.ConfirmedLines, result.FromAddress, r) {
					r.println(line)
				}
			}
		})
	}, result.Structured)
}

type appDeployArgs struct {
	From             string
	ApprovalPath     string
	ApprovalCompiled bool
	ClearPath        string
	ClearCompiled    bool
	GlobalUint       uint64
	GlobalBytes      uint64
	LocalUint        uint64
	LocalBytes       uint64
	ExtraPages       uint32
	Note             string
	Wait             bool
	Fee              uint64
	UseFlatFee       bool
	LsigArgs         cmdspec.LsigArgs
}

func (a *appDeployArgs) toAppRequest() apshellapp.AppDeployRequest {
	return apshellapp.AppDeployRequest{
		From:             a.From,
		ApprovalPath:     a.ApprovalPath,
		ApprovalCompiled: a.ApprovalCompiled,
		ClearPath:        a.ClearPath,
		ClearCompiled:    a.ClearCompiled,
		GlobalUint:       a.GlobalUint,
		GlobalBytes:      a.GlobalBytes,
		LocalUint:        a.LocalUint,
		LocalBytes:       a.LocalBytes,
		ExtraPages:       a.ExtraPages,
		Note:             a.Note,
		Wait:             a.Wait,
		Fee:              a.Fee,
		UseFlatFee:       a.UseFlatFee,
		LsigArgs:         a.LsigArgs,
	}
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

	if params.ApprovalPath == "" {
		return nil, fmt.Errorf("missing approval program")
	}
	if params.ClearPath == "" {
		return nil, fmt.Errorf("missing clear program")
	}
	return params, nil
}

// appDeployProgramOption is one spelling of a program option: which program
// it sets, and how its value says whether the file is compiled.
type appDeployProgramOption struct {
	kind   string
	source func(value string) appinput.ProgramSource
}

func programAs(compiled bool) func(string) appinput.ProgramSource {
	return func(value string) appinput.ProgramSource {
		return appinput.ProgramSource{Path: value, Compiled: compiled}
	}
}

var appDeployProgramOptions = map[string]appDeployProgramOption{
	"approval":      {"approval", appinput.DetectProgramSource},
	"approval-teal": {"approval", programAs(false)},
	"approval-bin":  {"approval", programAs(true)},
	"clear":         {"clear", appinput.DetectProgramSource},
	"clear-teal":    {"clear", programAs(false)},
	"clear-bin":     {"clear", programAs(true)},
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
	"fee": {64, func(p *appDeployArgs, v uint64) {
		p.Fee = v
		p.UseFlatFee = true
	}},
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
	if option, known := appDeployProgramOptions[name]; known {
		return true, a.setProgram(seen, option.kind, option.source(value))
	}
	if option, known := appDeployUintOptions[name]; known {
		return true, a.setUint(seen, name, value, option)
	}
	if name == "note" {
		if err := seen.Once("note"); err != nil {
			return true, err
		}
		a.Note = value
		return true, nil
	}
	return false, nil
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

// setProgram records the approval or clear program, once.
func (a *appDeployArgs) setProgram(seen cmdspec.SeenOptions, kind string, source appinput.ProgramSource) error {
	if source.Path == "" {
		return fmt.Errorf("missing value for %s", kind)
	}
	if err := seen.Once(kind); err != nil {
		return err
	}
	switch kind {
	case "approval":
		a.ApprovalPath = source.Path
		a.ApprovalCompiled = source.Compiled
	case "clear":
		a.ClearPath = source.Path
		a.ClearCompiled = source.Compiled
	default:
		return fmt.Errorf("unknown program kind: %s", kind)
	}
	return nil
}
