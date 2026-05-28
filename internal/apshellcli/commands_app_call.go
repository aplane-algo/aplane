// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"fmt"
	"strings"
)

func execAppCall(r *REPLState, args []string) (*JSONResult, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: app call <app-id> <method> --abi <path> from <account> | app call raw <app-id> from <account>")
	}
	if args[0] == "raw" {
		return execAppCallRaw(r, args)
	}
	return execAppCallMethod(r, args)
}

func execAppCallRaw(r *REPLState, args []string) (*JSONResult, error) {
	params, err := parseRawAppCallArgs(args)
	if err != nil {
		return nil, err
	}
	result, err := r.app().AppCallRaw(r.commandContext(), params.toAppRawRequest())
	if err != nil {
		return nil, err
	}

	return &JSONResult{Data: result.Structured}, nil
}

func execAppCallMethod(r *REPLState, args []string) (*JSONResult, error) {
	params, err := parseMethodAppCallArgs(args)
	if err != nil {
		return nil, err
	}
	result, err := r.app().AppCallMethod(r.commandContext(), params.toAppMethodRequest())
	if err != nil {
		return nil, err
	}

	return &JSONResult{Data: result.Structured}, nil
}

func (r *REPLState) runAppCall(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: app call <app-id> <method> --abi <path> from <account> | app call raw <app-id> from <account>")
	}
	if args[0] == "raw" {
		return r.runAppCallRaw(args)
	}
	return r.runAppCallMethod(args)
}

func (r *REPLState) runAppCallRaw(args []string) error {
	params, err := parseRawAppCallArgs(args)
	if err != nil {
		return err
	}
	result, err := r.app().AppCallRaw(r.commandContext(), params.toAppRawRequest())
	if err != nil {
		return err
	}

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

	return nil
}

func (r *REPLState) runAppCallMethod(args []string) error {
	params, err := parseMethodAppCallArgs(args)
	if err != nil {
		return err
	}
	result, err := r.app().AppCallMethod(r.commandContext(), params.toAppMethodRequest())
	if err != nil {
		return err
	}

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

	return nil
}

func renderAppCallLines(lines []string, fromAddress string, r *REPLState) []string {
	rendered := make([]string, 0, len(lines))
	for _, line := range lines {
		rendered = append(rendered, strings.ReplaceAll(line, "{from}", r.app().FormatAddress(fromAddress, "")))
	}
	return rendered
}
