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
	cosignerSubcommand    = "cosigner"
	asaSubcommand         = "asa"
	clientsSubcommand     = "clients"
	endpointSubcommand    = "endpoint"
	generationsSubcommand = "generations"
	archiveSubcommand     = "archive"

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
	cosignerSubcommand:    productionCatalog,
	asaSubcommand:         productionCatalog,
	clientsSubcommand:     productionCatalog,
	endpointSubcommand:    productionCatalog,
	generationsSubcommand: productionCatalog,
	archiveSubcommand:     productionCatalog,
}

// classifyProductionSubcommand returns the kind of the production command
// args name, or 0 when they name none.
func classifyProductionSubcommand(args []string) productionCommandKind {
	if len(args) == 0 {
		return 0
	}
	return productionSubcommands[args[0]]
}
