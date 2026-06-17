// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aplane-algo/aplane/internal/appinput"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/cmdspec"
)

func (r *REPLState) runAppDeploy(args []string) error {
	params, err := parseAppDeployArgs(args)
	if err != nil {
		return err
	}

	result, err := r.app().AppDeploy(r.commandContext(), params.toAppRequest())
	if err != nil {
		return err
	}
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

	return nil
}

func execAppDeploy(r *REPLState, args []string) (*JSONResult, error) {
	params, err := parseAppDeployArgs(args)
	if err != nil {
		return nil, err
	}

	result, err := r.app().AppDeploy(r.commandContext(), params.toAppRequest())
	if err != nil {
		return nil, err
	}

	return &JSONResult{Data: result.Structured}, nil
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
	LsigArgs         map[string][]byte
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
		return nil, fmt.Errorf("usage: app deploy from <account> approval=<path>|approval-teal=<path>|approval-bin=<path> clear=<path>|clear-teal=<path>|clear-bin=<path> global-uint=<n> global-bytes=<n> local-uint=<n> local-bytes=<n> [extra-pages=<n>] [note=<text>] [fee=<microalgos>] [nowait] [arg:name=value]")
	}
	params.From = args[1]

	setProgram := func(kind, value string, compiled bool) error {
		if value == "" {
			return fmt.Errorf("missing value for %s", kind)
		}
		switch kind {
		case "approval":
			params.ApprovalPath = value
			params.ApprovalCompiled = compiled
		case "clear":
			params.ClearPath = value
			params.ClearCompiled = compiled
		default:
			return fmt.Errorf("unknown program kind: %s", kind)
		}
		return nil
	}

	for i := 2; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "nowait":
			params.Wait = false
		case strings.HasPrefix(arg, "approval-teal="):
			if err := setProgram("approval", strings.TrimPrefix(arg, "approval-teal="), false); err != nil {
				return nil, err
			}
		case strings.HasPrefix(arg, "approval-bin="):
			if err := setProgram("approval", strings.TrimPrefix(arg, "approval-bin="), true); err != nil {
				return nil, err
			}
		case strings.HasPrefix(arg, "approval="):
			src := appinput.DetectProgramSource(strings.TrimPrefix(arg, "approval="))
			if err := setProgram("approval", src.Path, src.Compiled); err != nil {
				return nil, err
			}
		case strings.HasPrefix(arg, "clear-teal="):
			if err := setProgram("clear", strings.TrimPrefix(arg, "clear-teal="), false); err != nil {
				return nil, err
			}
		case strings.HasPrefix(arg, "clear-bin="):
			if err := setProgram("clear", strings.TrimPrefix(arg, "clear-bin="), true); err != nil {
				return nil, err
			}
		case strings.HasPrefix(arg, "clear="):
			src := appinput.DetectProgramSource(strings.TrimPrefix(arg, "clear="))
			if err := setProgram("clear", src.Path, src.Compiled); err != nil {
				return nil, err
			}
		case strings.HasPrefix(arg, "global-uint="):
			v, err := strconv.ParseUint(strings.TrimPrefix(arg, "global-uint="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid global-uint value: %s", strings.TrimPrefix(arg, "global-uint="))
			}
			params.GlobalUint = v
		case strings.HasPrefix(arg, "global-bytes="):
			v, err := strconv.ParseUint(strings.TrimPrefix(arg, "global-bytes="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid global-bytes value: %s", strings.TrimPrefix(arg, "global-bytes="))
			}
			params.GlobalBytes = v
		case strings.HasPrefix(arg, "local-uint="):
			v, err := strconv.ParseUint(strings.TrimPrefix(arg, "local-uint="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid local-uint value: %s", strings.TrimPrefix(arg, "local-uint="))
			}
			params.LocalUint = v
		case strings.HasPrefix(arg, "local-bytes="):
			v, err := strconv.ParseUint(strings.TrimPrefix(arg, "local-bytes="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid local-bytes value: %s", strings.TrimPrefix(arg, "local-bytes="))
			}
			params.LocalBytes = v
		case strings.HasPrefix(arg, "extra-pages="):
			v, err := strconv.ParseUint(strings.TrimPrefix(arg, "extra-pages="), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid extra-pages value: %s", strings.TrimPrefix(arg, "extra-pages="))
			}
			params.ExtraPages = uint32(v)
		case strings.HasPrefix(arg, "note="):
			params.Note = strings.TrimPrefix(arg, "note=")
		case strings.HasPrefix(arg, "fee="):
			feeVal, err := strconv.ParseUint(strings.TrimPrefix(arg, "fee="), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid fee value: %s", strings.TrimPrefix(arg, "fee="))
			}
			params.Fee = feeVal
			params.UseFlatFee = true
		case strings.HasPrefix(arg, "arg:"):
			argName, argValue, err := cmdspec.ParseLsigArg(arg)
			if err != nil {
				return nil, err
			}
			if params.LsigArgs == nil {
				params.LsigArgs = make(map[string][]byte)
			}
			params.LsigArgs[argName] = argValue
		default:
			return nil, fmt.Errorf("unknown app deploy argument: %s", arg)
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
