// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// Alias and set management commands

import (
	"fmt"
	"io"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

func (r *REPLState) cmdAlias(args []string, _ interface{}) (command.Result, error) {
	result, err := r.app().Alias(r.commandContext(), args)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutputResult(w, func() error { return r.renderAliasResult(result) })
	}, projectAliasResult(result))
}

// runAlias handles the alias command by delegating semantic work to
// apshellapp and rendering the result.
func (r *REPLState) renderAliasResult(result *apshellapp.AliasCommandResult) error {
	switch result.Mode {
	case "usage":
		for _, line := range result.Usage {
			r.printf("  %s\n", line)
		}
		return nil
	case "list":
		if len(result.Aliases) == 0 {
			r.println("No aliases defined")
			return nil
		}

		r.println("Defined aliases:")
		for _, alias := range result.Aliases {
			r.printf("  %s\n", r.app().FormatAddress(alias.Address, ""))
		}

		if len(result.Warnings) > 0 {
			r.println("\nColor legend:")
			for _, warning := range result.Warnings {
				r.printf("  %s\n", warning.Message)
			}
		}
		return nil
	case "delete":
		r.printf("Removed alias: %s (was %s)\n", result.Name, r.app().FormatAddress(result.Removed, ""))
		return nil
	case "show":
		r.printf("%s → %s\n", result.Name, r.app().FormatAddress(result.Alias.Address, ""))
		return nil
	case "upsert":
		added := result.Added
		if added.WasUpdated {
			r.printf("Updated alias: %s → %s (was %s)\n", result.Name, r.app().FormatAddress(added.Address, ""), r.app().FormatAddress(added.OldAddress, ""))
		} else if added.OldAddress == "" {
			r.printf("Added alias: %s → %s\n", result.Name, r.app().FormatAddress(added.Address, ""))
		} else {
			r.printf("Alias '%s' already points to %s\n", result.Name, r.app().FormatAddress(added.Address, ""))
		}
		return nil
	}

	return fmt.Errorf("unsupported alias mode: %s", result.Mode)
}

func (r *REPLState) cmdSets(args []string, _ interface{}) (command.Result, error) {
	result, err := r.app().Sets(r.commandContext(), args)
	if err != nil {
		return nil, err
	}
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutputResult(w, func() error { return r.renderSetsResult(result) })
	}, projectSetsResult(result))
}

// stripBrackets removes bracket notation from an address list.
// Supports both [ addr1 addr2 ] (standalone) and [addr1 addr2] (attached) styles.
// runSets handles the sets command by delegating semantic work to apshellapp
// and rendering the result.
func (r *REPLState) renderSetsResult(result *apshellapp.SetsCommandResult) error {
	switch result.Mode {
	case "usage":
		for _, line := range result.Usage {
			r.printf("  %s\n", line)
		}
		return nil
	case "list":
		if len(result.Sets) == 0 {
			r.println("No sets defined")
			return nil
		}

		r.println("Defined sets:")
		for _, set := range result.Sets {
			r.printf("  @%s (%d addresses)\n", set.Name, set.Count)
		}
		return nil
	case "add":
		added := len(result.Mutation.Addresses) - result.Mutation.OldCount
		r.printf("Added %d address(es) to @%s (now %d total)\n", added, result.Mutation.Name, len(result.Mutation.Addresses))
		return nil
	case "remove":
		removed := result.Mutation.OldCount - len(result.Mutation.Addresses)
		r.printf("Removed %d address(es) from @%s (now %d total)\n", removed, result.Mutation.Name, len(result.Mutation.Addresses))
		return nil
	case "delete":
		r.printf("Deleted set @%s (%d addresses)\n", result.SetName, result.Count)
		return nil
	case "show":
		r.printf("Set '%s' (%d addresses):\n", result.SetName, len(result.Addresses))
		for i, addr := range result.Addresses {
			r.printf("  %d. %s\n", i+1, r.app().FormatAddress(addr, ""))
		}
		return nil
	case "create":
		if result.Mutation.WasUpdated {
			r.printf("Updated set @%s: %d → %d addresses\n", result.Mutation.Name, result.Mutation.OldCount, len(result.Mutation.Addresses))
		} else {
			r.printf("Created set @%s with %d addresses\n", result.Mutation.Name, len(result.Mutation.Addresses))
		}
		return nil
	}

	return fmt.Errorf("unsupported sets mode: %s", result.Mode)
}
