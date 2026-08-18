// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"io"
	"strings"

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

	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range renderAppCallLines(result.PreSubmitLines, result.FromAddress, r) {
				r.println(line)
			}
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			if params.Wait && result.Structured.Confirmed {
				for _, line := range renderAppCallLines(result.ConfirmedLines, result.FromAddress, r) {
					r.println(line)
				}
			}
		})
	}, result.Structured)
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

	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			for _, line := range renderAppCallLines(result.PreSubmitLines, result.FromAddress, r) {
				r.println(line)
			}
			r.renderSubmissionOutput(result.Output)
			r.renderWarnings(result.Warnings)
			if params.Wait && result.Structured.Confirmed {
				for _, line := range renderAppCallLines(result.ConfirmedLines, result.FromAddress, r) {
					r.println(line)
				}
			}
		})
	}, result.Structured)
}

func renderAppCallLines(lines []string, fromAddress string, r *REPLState) []string {
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		rendered = append(rendered, strings.ReplaceAll(line, "{from}", r.app().FormatAddress(fromAddress, "")))
	}
	return rendered
}
