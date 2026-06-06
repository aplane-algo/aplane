// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"github.com/aplane-algo/aplane/internal/config"
	tui "github.com/aplane-algo/aplane/internal/signertui"
	"github.com/aplane-algo/aplane/internal/theme"
)

type remoteAdminConfig struct {
	dataDir   string
	config    config.Config
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
		Host:           cfg.LegacySSH.Host,
		Port:           cfg.LegacySSH.Port,
		Token:          prereqs.token,
		IdentityFile:   cfg.LegacySSH.IdentityFile,
		KnownHostsPath: cfg.LegacySSH.KnownHostsPath,
	}

	return &remoteAdminConfig{
		dataDir:   prereqs.dataDir,
		config:    cfg,
		token:     prereqs.token,
		connector: connector,
	}, nil
}
