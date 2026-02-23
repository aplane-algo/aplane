// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"

	"github.com/aplane-algo/aplane/internal/util"
)

// validateStartup performs comprehensive startup validation for apshell.
// Returns an error if any required config is missing.
// Required: algod URL for the selected network
func validateStartup(config *util.Config, network string) error {
	// Check algod URL for selected network (required for transaction submission)
	algodConfig, err := config.GetAlgodConfig(network)
	if err != nil {
		return fmt.Errorf("invalid network '%s': %w", network, err)
	}
	if algodConfig.Server == "" {
		return fmt.Errorf("%s_algod_server is required in config.yaml", network)
	}
	return nil
}
