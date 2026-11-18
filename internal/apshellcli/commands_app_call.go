// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"strings"

	"github.com/aplane-algo/aplane/internal/appresult"
	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

func (r *REPLState) executeAppCall(args []string) (command.Result, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: app call <app-id> <method> --abi <path> from <account> | app call raw <app-id> from <account>")
	}
	if args[0] == "raw" {
		return r.executeAppCallRaw(args)
	}
	return r.executeAppCallMethod(args)
}

func (r *REPLState) executeAppCallRaw(args []string) (command.Result, error) {
	params, err := parseRawAppCallArgs(args)
	if err != nil {
		return nil, err
	}
	result, err := r.app().AppCallRaw(r.commandContext(), params.toAppRawRequest())
	if err != nil {
		return nil, err
	}
	return r.appCallResult(params.Wait, appCallOutput{
		from:       result.FromAddress,
		preSubmit:  result.PreSubmitLines,
		output:     result.Output,
		warnings:   result.Warnings,
		confirmed:  result.ConfirmedLines,
		structured: result.Structured,
	})
}

func (r *REPLState) executeAppCallMethod(args []string) (command.Result, error) {
	params, err := parseMethodAppCallArgs(args)
	if err != nil {
		return nil, err
	}
	result, err := r.app().AppCallMethod(r.commandContext(), params.toAppMethodRequest())
	if err != nil {
		return nil, err
	}
	return r.appCallResult(params.Wait, appCallOutput{
		from:       result.FromAddress,
		preSubmit:  result.PreSubmitLines,
		output:     result.Output,
		warnings:   result.Warnings,
		confirmed:  result.ConfirmedLines,
		structured: result.Structured,
	})
}

// appCallOutput is what both forms of app call print.
type appCallOutput struct {
	from       string
	preSubmit  []string
	output     string
	warnings   []apshellapp.Warning
	confirmed  []string
	structured appresult.AppCall
}

func (r *REPLState) appCallResult(wait bool, out appCallOutput) (command.Result, error) {
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range renderAppCallLines(out.preSubmit, out.from, r) {
				r.println(line)
			}
			r.renderSubmissionOutput(out.output)
			r.renderWarnings(out.warnings)
			if wait && out.structured.Confirmed {
				for _, line := range renderAppCallLines(out.confirmed, out.from, r) {
					r.println(line)
				}
			}
		})
	}, out.structured)
}

func renderAppCallLines(lines []string, fromAddress string, r *REPLState) []string {
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		rendered = append(rendered, strings.ReplaceAll(line, "{from}", r.app().FormatAddress(fromAddress, "")))
	}
	return rendered
}
