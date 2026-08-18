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

type productionCommandKind uint8

const (
	productionPolicy productionCommandKind = iota + 1
	productionCatalog
	productionStore
)

// productionSubcommands is the single production command catalog used by both
// dispatch and the production/testmode collision guard.
var productionSubcommands = map[string]productionCommandKind{
	policySubcommand:      productionPolicy,
	backupSubcommand:      productionStore,
	restoreSubcommand:     productionStore,
	changePassSubcommand:  productionStore,
	templateSubcommand:    productionCatalog,
	keyTypeSubcommand:     productionCatalog,
	sentrySubcommand:      productionCatalog,
	endpointSubcommand:    productionCatalog,
	generationsSubcommand: productionCatalog,
}

var testModeCommandNames = []string{
	testModeListCommand,
	testModeGenerateCommand,
	testModeImportCommand,
	testModeDeleteCommand,
	testModeUnlockCommand,
}

func classifyProductionSubcommand(args []string) (productionCommandKind, bool) {
	if len(args) == 0 {
		return 0, false
	}
	kind, ok := productionSubcommands[args[0]]
	return kind, ok
}

func isProductionSubcommand(args []string) bool {
	_, ok := classifyProductionSubcommand(args)
	return ok
}
