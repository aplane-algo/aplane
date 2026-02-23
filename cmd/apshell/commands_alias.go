// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Alias and set management commands

import (
	"fmt"
	"strings"
)

func (r *REPLState) cmdAlias(args []string, _ interface{}) error {
	return r.aliasWithEngine(args)
}

// aliasWithEngine handles alias command using Engine pattern.
// REPL layer: parsing, UI output formatting
// Engine layer: cache management, auth cache updates
func (r *REPLState) aliasWithEngine(args []string) error {
	// No arguments: list all aliases
	if len(args) == 0 {
		result := r.Engine.ListAliases()
		if len(result.Aliases) == 0 {
			fmt.Println("No aliases defined")
			return nil
		}

		fmt.Println("Defined aliases:")
		for _, alias := range result.Aliases {
			fmt.Printf("  %s\n", r.FormatAddress(alias.Address, ""))
		}

		if r.Engine.SignerCache.Count() > 0 {
			fmt.Println("\nColor legend:")
			fmt.Println("  Yellow = signable falcon")
			fmt.Println("  Cyan = signable ed25519")
		}
		return nil
	}

	// Remove command: alias remove <name>
	if args[0] == "remove" {
		if len(args) != 2 {
			return fmt.Errorf("usage: alias remove <name>")
		}
		name := args[1]

		address, err := r.Engine.RemoveAlias(name)
		if err != nil {
			return err
		}

		fmt.Printf("Removed alias: %s (was %s)\n", name, r.FormatAddress(address, ""))
		return nil
	}

	// One argument: show specific alias
	if len(args) == 1 {
		name := args[0]
		alias := r.Engine.GetAlias(name)
		if alias == nil {
			return fmt.Errorf("alias '%s' not found", name)
		}

		fmt.Printf("%s → %s\n", name, r.FormatAddress(alias.Address, ""))
		return nil
	}

	// Two arguments: add/update alias (address first, then name for tab completion)
	if len(args) == 2 {
		address := args[0]
		name := args[1]

		result, err := r.Engine.AddAlias(name, address)
		if err != nil {
			return err
		}

		if result.WasUpdated {
			fmt.Printf("Updated alias: %s → %s (was %s)\n", name, r.FormatAddress(result.Address, ""), r.FormatAddress(result.OldAddress, ""))
		} else if result.OldAddress == "" {
			fmt.Printf("Added alias: %s → %s\n", name, r.FormatAddress(result.Address, ""))
		} else {
			fmt.Printf("Alias '%s' already points to %s\n", name, r.FormatAddress(result.Address, ""))
		}
		return nil
	}

	return fmt.Errorf("usage: alias [<address> <name>] | alias remove <name>")
}

func (r *REPLState) cmdSets(args []string, _ interface{}) error {
	return r.setsWithEngine(args)
}

// setsWithEngine handles sets command using Engine pattern.
// REPL layer: parsing, UI output formatting
// Engine layer: cache management
func (r *REPLState) setsWithEngine(args []string) error {
	// No arguments: list all sets
	if len(args) == 0 {
		result := r.Engine.ListSets()
		if len(result.Sets) == 0 {
			fmt.Println("No sets defined")
			return nil
		}

		fmt.Println("Defined sets:")
		for _, set := range result.Sets {
			fmt.Printf("  @%s (%d addresses)\n", set.Name, set.Count)
		}
		return nil
	}

	// "add" subcommand: sets add <addr>... to <name>
	if args[0] == "add" {
		// Find the "to" keyword
		toIndex := -1
		for i, arg := range args {
			if arg == "to" {
				toIndex = i
				break
			}
		}

		if toIndex == -1 || toIndex == 1 || toIndex == len(args)-1 {
			return fmt.Errorf("usage: sets add <address>... to <name>")
		}

		addresses := args[1:toIndex]
		setName := args[toIndex+1]

		result, err := r.Engine.AddToSet(setName, addresses)
		if err != nil {
			return err
		}

		added := len(result.Addresses) - result.OldCount
		fmt.Printf("Added %d address(es) to @%s (now %d total)\n", added, result.Name, len(result.Addresses))
		return nil
	}

	// "remove" subcommand: sets remove <addr>... from <name>
	if args[0] == "remove" {
		// Find the "from" keyword
		fromIndex := -1
		for i, arg := range args {
			if arg == "from" {
				fromIndex = i
				break
			}
		}

		if fromIndex == -1 || fromIndex == 1 || fromIndex == len(args)-1 {
			return fmt.Errorf("usage: sets remove <address>... from <name>")
		}

		addresses := args[1:fromIndex]
		setName := args[fromIndex+1]

		result, err := r.Engine.RemoveFromSet(setName, addresses)
		if err != nil {
			return err
		}

		removed := result.OldCount - len(result.Addresses)
		fmt.Printf("Removed %d address(es) from @%s (now %d total)\n", removed, result.Name, len(result.Addresses))
		return nil
	}

	// "delete" subcommand: sets delete <name>
	if args[0] == "delete" {
		if len(args) != 2 {
			return fmt.Errorf("usage: sets delete <name>")
		}
		setName := args[1]

		count, err := r.Engine.RemoveSet(setName)
		if err != nil {
			return err
		}

		fmt.Printf("Deleted set @%s (%d addresses)\n", setName, count)
		return nil
	}

	// One argument: show specific set (static or dynamic)
	if len(args) == 1 {
		setRef := args[0]

		// Ensure it has @ prefix for resolver
		if !strings.HasPrefix(setRef, "@") {
			setRef = "@" + setRef
		}

		// Use resolver to handle both static and dynamic sets
		resolver := r.Engine.NewAddressResolver()
		addresses, err := resolver.ResolveList([]string{setRef})
		if err != nil {
			return fmt.Errorf("set '%s' not found or error: %v", args[0], err)
		}

		fmt.Printf("Set '%s' (%d addresses):\n", setRef, len(addresses))
		for i, addr := range addresses {
			fmt.Printf("  %d. %s\n", i+1, r.FormatAddress(addr, ""))
		}
		return nil
	}

	// Two or more arguments: create/replace set
	setName := args[0]
	addresses := args[1:]

	// Clean up brackets if present (e.g., sets myteam [addr1 addr2])
	cleanedAddresses := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		cleaned := strings.Trim(addr, "[]")
		if cleaned != "" {
			cleanedAddresses = append(cleanedAddresses, cleaned)
		}
	}

	if len(cleanedAddresses) == 0 {
		return fmt.Errorf("no valid addresses provided")
	}

	result, err := r.Engine.AddSet(setName, cleanedAddresses)
	if err != nil {
		return err
	}

	if result.WasUpdated {
		fmt.Printf("Updated set @%s: %d → %d addresses\n", result.Name, result.OldCount, len(result.Addresses))
	} else {
		fmt.Printf("Created set @%s with %d addresses\n", result.Name, len(result.Addresses))
	}
	return nil
}
