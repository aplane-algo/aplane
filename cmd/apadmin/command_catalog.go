// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

const (
	policySubcommand = "policy"

	testModeListCommand     = "list"
	testModeGenerateCommand = "generate"
	testModeImportCommand   = "import"
	testModeDeleteCommand   = "delete"
	testModeUnlockCommand   = "unlock"
)

var productionSubcommands = []string{policySubcommand}

var testModeCommandNames = []string{
	testModeListCommand,
	testModeGenerateCommand,
	testModeImportCommand,
	testModeDeleteCommand,
	testModeUnlockCommand,
}

func isProductionSubcommand(args []string) bool {
	return len(args) > 0 && args[0] == policySubcommand
}
