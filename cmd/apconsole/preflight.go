// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/clientenroll"
	"github.com/aplane-algo/aplane/internal/config"
)

type consoleClientPrereqs struct {
	dataDir string
	config  config.Config
	token   string
}

func loadConsoleClientPrereqs(clientDataDirFlag string) (*consoleClientPrereqs, error) {
	clientDataDir := config.GetClientDataDir(clientDataDirFlag)
	if clientDataDir == "" {
		return nil, fmt.Errorf("client data directory not specified: pass -client-data <path>, set APCLIENT_DATA, or configure client_data in apconsole.yaml")
	}

	prereqs, err := clientenroll.LoadEnrolledClient(clientDataDir, clientenroll.Options{
		Product:              "apconsole",
		MissingSSHHint:       "run apshell enrollment/setup before starting apconsole",
		MissingTokenHint:     fmt.Sprintf("run apshell -d %s request-token before starting apconsole", clientDataDir),
		MissingKnownHostHint: "run apshell request-token or connect once before starting apconsole",
	})
	if err != nil {
		return nil, err
	}

	return &consoleClientPrereqs{
		dataDir: prereqs.DataDir,
		config:  prereqs.Config,
		token:   prereqs.Token,
	}, nil
}
