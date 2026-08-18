// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

const (
	policySubcommand      = "policy"
	backupSubcommand      = "backup"
	restoreSubcommand     = "restore"
	changePassSubcommand  = "changepass"
	templateSubcommand    = "template"
	keyTypeSubcommand     = "keytype"
	sentrySubcommand      = "sentry"
	endpointSubcommand    = "endpoint"
	generationsSubcommand = "generations"

	testModeListCommand     = "list"
	testModeGenerateCommand = "generate"
	testModeImportCommand   = "import"
	testModeDeleteCommand   = "delete"
	testModeUnlockCommand   = "unlock"
)

var productionSubcommands = []string{
	policySubcommand,
	backupSubcommand,
	restoreSubcommand,
	changePassSubcommand,
	templateSubcommand,
	keyTypeSubcommand,
	sentrySubcommand,
	endpointSubcommand,
	generationsSubcommand,
}

var catalogSubcommands = map[string]bool{
	templateSubcommand:    true,
	keyTypeSubcommand:     true,
	sentrySubcommand:      true,
	endpointSubcommand:    true,
	generationsSubcommand: true,
}

var storeSubcommands = map[string]bool{
	backupSubcommand:     true,
	restoreSubcommand:    true,
	changePassSubcommand: true,
}

var testModeCommandNames = []string{
	testModeListCommand,
	testModeGenerateCommand,
	testModeImportCommand,
	testModeDeleteCommand,
	testModeUnlockCommand,
}

func isProductionSubcommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, command := range productionSubcommands {
		if args[0] == command {
			return true
		}
	}
	return false
}

func isCatalogSubcommand(command string) bool { return catalogSubcommands[command] }
func isStoreSubcommand(command string) bool   { return storeSubcommands[command] }
