// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

func (r *REPLState) cmdApp(args []string, _ interface{}) (command.Result, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: app read <info|global|local|box|boxes> | app call raw <app-id> from <account> | app deploy from <account>")
	}

	switch args[0] {
	case "read":
		result, err := r.app().AppRead(r.commandContext(), apshellapp.AppReadRequest{Args: args[1:]})
		if err != nil {
			return nil, err
		}
		return newShellCommandResult(func(w io.Writer) error {
			data, err := json.MarshalIndent(result.Data, "", "  ")
			if err != nil {
				return err
			}
			if _, err := w.Write(data); err != nil {
				return err
			}
			_, err = io.WriteString(w, "\n")
			return err
		}, result.Data)
	case "call":
		return r.executeAppCall(args[1:])
	case "deploy":
		return r.executeAppDeploy(args[1:])
	default:
		return nil, fmt.Errorf("unknown app command: %s", args[0])
	}
}
