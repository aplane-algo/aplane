// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package command

import (
	"fmt"
	"strings"
)

func ShowHelp(registry *Registry, network string) {
	fmt.Println("\nAvailable commands:")

	// Get commands grouped by category
	categories := registry.ByCategory()

	// Define category order
	categoryOrder := []string{
		CategorySetup,
		CategoryTransaction,
		CategoryAlias,
		CategoryRekey,
		CategoryInfo,
		CategoryKeyMgmt,
		CategoryASA,
		CategoryConfig,
		CategoryVariables,
		CategoryAutomation,
		CategoryRemote,
		CategoryOrchestration,
	}

	for _, category := range categoryOrder {
		commands, exists := categories[category]
		if !exists || len(commands) == 0 {
			continue
		}

		fmt.Printf("\n%s:\n", category)
		for _, cmd := range commands {
			aliasStr := ""
			if len(cmd.Aliases) > 0 {
				aliasStr = fmt.Sprintf(" (aliases: %s)", strings.Join(cmd.Aliases, ", "))
			}

			pluginIndicator := ""
			if cmd.IsPlugin {
				pluginIndicator = " [plugin]"
			}

			fmt.Printf("  %-40s - %s%s%s\n",
				cmd.Usage,
				cmd.Description,
				aliasStr,
				pluginIndicator)
		}
	}

	fmt.Printf("\nCurrent network: %s\n", network)
	fmt.Println("\nFor detailed help on a command, type: help <command>")
}

func ShowCommandHelp(cmd *Command) {
	fmt.Printf("\nCommand: %s\n", cmd.Name)

	if len(cmd.Aliases) > 0 {
		fmt.Printf("Aliases: %s\n", strings.Join(cmd.Aliases, ", "))
	}

	fmt.Printf("Usage: %s\n", cmd.Usage)
	fmt.Printf("Category: %s\n", cmd.Category)

	if cmd.IsPlugin {
		fmt.Println("Type: External Plugin")
	}

	fmt.Printf("\nDescription:\n%s\n", cmd.Description)

	if cmd.LongHelp != "" {
		fmt.Printf("\nDetails:\n%s\n", cmd.LongHelp)
	}
}
