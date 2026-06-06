// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

import (
	"os"

	"github.com/aplane-algo/aplane/internal/config"
)

func maybePromptClientEndpointMigration(state *REPLState) {
	if state == nil || !stdinIsTerminal() {
		return
	}
	needed, err := config.StoredClientPrimaryEndpointMaterializationNeeded(state.DataDir)
	if err != nil {
		state.printf("Warning: could not inspect endpoint registry migration state: %v\n", err)
		return
	}
	if !needed {
		return
	}

	response, err := state.readPromptResponse("Client config uses legacy signer settings. Create endpoints.yaml with primary signer now? [Y/n]: ")
	if err != nil {
		state.printf("Warning: could not read endpoint migration response: %v\n", err)
		return
	}
	if response != "" && response != "y" && response != "yes" {
		state.println("Leaving endpoint registry unchanged; legacy config.yaml signer settings remain active.")
		return
	}

	if _, changed, err := config.MaterializeStoredClientPrimaryEndpoint(state.DataDir); err != nil {
		state.printf("Warning: could not create endpoints.yaml: %v\n", err)
	} else if changed {
		state.printf("Created %s with primary signer endpoint.\n", config.ClientEndpointsFile)
	}
}

func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
