// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package command

import (
	"fmt"
	"io"
	"strings"
)

//nolint:errcheck // display-only writes
func ShowHelp(w io.Writer, registry *Registry) {
	fmt.Fprintln(w, "\nAvailable commands:")

	categories := registry.ByCategory()

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

		fmt.Fprintf(w, "\n%s:\n", category)
		for _, cmd := range commands {
			fmt.Fprintf(w, "  %s\n", cmd.Usage)
		}
	}
}

//nolint:errcheck // display-only writes
func ShowCommandHelp(w io.Writer, cmd *Command) {
	fmt.Fprintf(w, "\nCommand: %s\n", cmd.Name)

	if len(cmd.Aliases) > 0 {
		fmt.Fprintf(w, "Aliases: %s\n", strings.Join(cmd.Aliases, ", "))
	}

	fmt.Fprintf(w, "Usage: %s\n", cmd.Usage)
	fmt.Fprintf(w, "Category: %s\n", cmd.Category)

	if cmd.IsPlugin {
		fmt.Fprintln(w, "Type: External Plugin")
	}

	fmt.Fprintf(w, "\nDescription:\n%s\n", cmd.Description)

	if cmd.LongHelp != "" {
		fmt.Fprintf(w, "\nDetails:\n%s\n", cmd.LongHelp)
	}
}
