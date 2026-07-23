// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/clientenroll"
	"github.com/aplane-algo/aplane/internal/config"
	tui "github.com/aplane-algo/aplane/internal/signerapp/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
)

type remoteAdminConfig struct {
	dataDir   string
	ssh       config.ClientEndpointSSH
	token     string
	connector tui.SSHAdminConnector
}

func formatRemoteConnectError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "unknown SSH host ") {
		return fmt.Errorf("%w\nhint: remote apadmin requires a trusted signer host; run standalone 'apshell request-token' or 'apshell connect' first to save the host key to known_hosts", err)
	}
	return err
}

func loadRemoteAdminConfig(clientDataDirFlag string) (*remoteAdminConfig, error) {
	clientDataDir := config.GetClientDataDir(clientDataDirFlag)
	if clientDataDir == "" {
		return nil, fmt.Errorf("client data directory not specified: pass --client-data <path> or set APCLIENT_DATA")
	}

	prereqs, err := clientenroll.LoadEnrolledClient(clientDataDir, clientenroll.Options{
		Product:              "remote apadmin",
		MissingSSHHint:       "configure or import the signer endpoint before starting remote apadmin",
		MissingTokenHint:     fmt.Sprintf("run apshell -d %s request-token before starting remote apadmin", clientDataDir),
		MissingKnownHostHint: "run standalone apshell request-token or connect first",
	})
	if err != nil {
		return nil, err
	}
	theme.Init(prereqs.Config.Theme)

	connector := tui.SSHAdminConnector{
		Host:           prereqs.SSH.Host,
		Port:           prereqs.SSH.Port,
		Token:          prereqs.Token,
		IdentityFile:   prereqs.SSH.IdentityFile,
		KnownHostsPath: prereqs.SSH.KnownHostsPath,
	}

	return &remoteAdminConfig{
		dataDir:   clientDataDir,
		ssh:       prereqs.SSH,
		token:     prereqs.Token,
		connector: connector,
	}, nil
}
