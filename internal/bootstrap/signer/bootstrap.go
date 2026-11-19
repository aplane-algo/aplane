// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package signer

import (
	"fmt"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"time"

	"github.com/aplane-algo/aplane/internal/storepaths"
)

// Startup captures resolved apsigner startup configuration.
type Startup struct {
	DataDir           string
	Config            serverconfig.ServerConfig
	PassphraseTimeout time.Duration
	Paths             storepaths.Paths
}

// ResolveDataDir resolves the signer data directory from flags and environment.
func ResolveDataDir(dataDirFlag string) (string, error) {
	dataDir := serverconfig.GetSignerDataDir(dataDirFlag)
	if dataDir == "" {
		return "", fmt.Errorf("data directory not specified")
	}
	return dataDir, nil
}

// Load resolves apsigner startup state from flags and config.
func Load(dataDirFlag string) (*Startup, error) {
	dataDir, err := ResolveDataDir(dataDirFlag)
	if err != nil {
		return nil, err
	}
	return LoadResolved(dataDir)
}

// LoadResolved is Load for callers that already resolved the data directory
// (typically to access-check it first) — avoids resolving twice.
func LoadResolved(dataDir string) (*Startup, error) {
	cfg, err := serverconfig.LoadServerConfig(dataDir)
	if err != nil {
		return nil, err
	}

	passphraseTimeout, err := serverconfig.ParsePassphraseTimeout(cfg.PassphraseTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid passphrase_timeout in config: %w", err)
	}

	return &Startup{
		DataDir:           dataDir,
		Config:            cfg,
		PassphraseTimeout: passphraseTimeout,
		Paths:             storepaths.NewPaths(dataDir),
	}, nil
}
