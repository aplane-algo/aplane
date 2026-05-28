// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import "fmt"

func (r *REPLState) cmdApp(args []string, _ interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: app read <info|global|local|box|boxes> | app call raw <app-id> from <account> | app deploy from <account>")
	}

	switch args[0] {
	case "read":
		result, err := execAppRead(r, args[1:])
		if err != nil {
			return err
		}
		result.RenderText(r.Out, r)
		return nil
	case "call":
		return r.runAppCall(args[1:])
	case "deploy":
		return r.runAppDeploy(args[1:])
	default:
		return fmt.Errorf("unknown app command: %s", args[0])
	}
}

// execApp is used by MCP for structured JSON responses.
func execApp(r *REPLState, args []string) (*JSONResult, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: app read <info|global|local|box|boxes> | app call raw <app-id> from <account> | app deploy from <account>")
	}
	switch args[0] {
	case "read":
		return execAppRead(r, args[1:])
	case "call":
		return execAppCall(r, args[1:])
	case "deploy":
		return execAppDeploy(r, args[1:])
	}
	return nil, fmt.Errorf("app command does not support structured JSON result for this subcommand")
}
