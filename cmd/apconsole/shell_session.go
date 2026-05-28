// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellcli"
	shellbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/shell"
)

func loadShellConsole(clientDataDirFlag, networkFlag string) (*apshellcli.Session, []string) {
	startup, err := shellbootstrap.Load(clientDataDirFlag, networkFlag)
	if err != nil {
		return nil, []string{"Shell disabled: " + err.Error()}
	}

	session, err := apshellcli.NewSession(startup.Network, startup.Config, startup.DataDir, io.Discard)
	lines := []string{
		fmt.Sprintf("APCLIENT_DATA: %s", startup.DataDir),
		fmt.Sprintf("network: %s", startup.Network),
	}
	if err != nil {
		lines = append(lines, "Shell disabled: "+err.Error())
		return nil, lines
	}
	// Plugin stderr would otherwise be written straight to the terminal,
	// scrambling the bubbletea-managed apconsole layout.
	session.SetPluginStderr(io.Discard)
	return session, lines
}
