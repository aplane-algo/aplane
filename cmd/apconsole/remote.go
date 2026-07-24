// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	tui "github.com/aplane-algo/aplane/internal/signerapp/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
)

type remoteAdminConfig struct {
	dataDir   string
	token     string
	connector *tui.SSHAdminConnector
}

func loadRemoteAdminConfig(clientDataDirFlag string) (*remoteAdminConfig, error) {
	prereqs, err := loadConsoleClientPrereqs(clientDataDirFlag)
	if err != nil {
		return nil, err
	}
	cfg := prereqs.config
	theme.Init(cfg.Theme)

	connector := &tui.SSHAdminConnector{
		Host:           prereqs.ssh.Host,
		Port:           prereqs.ssh.Port,
		Token:          prereqs.token,
		IdentityFile:   prereqs.ssh.IdentityFile,
		KnownHostsPath: prereqs.ssh.KnownHostsPath,
	}

	return &remoteAdminConfig{
		dataDir:   prereqs.dataDir,
		token:     prereqs.token,
		connector: connector,
	}, nil
}
