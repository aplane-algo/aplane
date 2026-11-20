// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package signeradmin holds the startup steps shared by the binaries that
// host the signer admin TUI, apadmin and apconsole.
package signeradmin

import (
	"fmt"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/keygen"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/mnemonic"
	"github.com/aplane-algo/aplane/internal/serverconfig"
)

// EnsureProviders reports whether the binary registered the key generators,
// mnemonic handlers and algorithm metadata the admin TUI needs.
func EnsureProviders() error {
	if len(keygen.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no key generators registered - check providers.go imports")
	}
	if len(mnemonic.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no mnemonic handlers registered - check providers.go imports")
	}
	if len(algorithm.GetRegisteredFamilies()) == 0 {
		return fmt.Errorf("no algorithm metadata registered - check providers.go imports")
	}
	return nil
}

// ConfigureAlgodOnDSAs gives the DSA providers an algod client for the
// config's TEAL compile network, so composed providers can compile TEAL at
// runtime during key generation. warnf reports why there is none.
func ConfigureAlgodOnDSAs(config serverconfig.ServerConfig, warnf func(format string, args ...any)) {
	cfg, err := config.GetTEALCompileAlgod()
	if err != nil || cfg.Server == "" {
		warnf("no algod.%s.server configured - composed Falcon templates unavailable", config.TEALCompileNetwork)
		return
	}

	client, err := algod.MakeClient(cfg.Server, cfg.Token)
	if err != nil {
		warnf("failed to create algod client: %v", err)
		warnf("composed Falcon templates will be unavailable")
		return
	}

	logicsigdsa.ConfigureAlgodClient(client)
}
