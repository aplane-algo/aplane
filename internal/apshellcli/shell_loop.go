// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"strings"

	"github.com/aplane-algo/aplane/internal/shellrepl"
)

func (r *REPLState) handleShellInput(raw string) (handled bool, err error) {
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "#") {
		return true, nil
	}
	if strings.HasPrefix(trimmed, "!") {
		return true, r.runShellCommand(trimmed[1:])
	}
	return false, nil
}

func (r *REPLState) parseInputCommand(raw string) (Command, error) {
	return parseShellCommand(raw)
}

func parseShellCommand(raw string) (Command, error) {
	cmdName, cmdArgs, err := shellrepl.ParseCommand(raw)
	if err != nil {
		return Command{}, err
	}
	if cmdName == "" {
		return Command{}, nil
	}

	cmd := Command{Name: cmdName, Args: cmdArgs}
	cmd.RawArgs = commandRawArgs(cmdName, raw)
	return cmd, nil
}
