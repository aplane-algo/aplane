// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellapp

import (
	"context"
	"fmt"
	"strings"

	"github.com/aplane-algo/aplane/internal/refname"
)

func validateAliasNameInput(name string) error {
	return refname.ValidateAlias(name)
}

func validateSetNameInput(name string) error {
	cleaned := strings.TrimPrefix(name, "@")
	return refname.ValidateSet(cleaned)
}

func normalizeSetNameInput(name string) string {
	return refname.NormalizeSet(name)
}

func normalizeAliasNameInput(name string) string {
	return refname.NormalizeAlias(name)
}

// stripBrackets removes bracket notation from an address list.
// Supports both [ addr1 addr2 ] (standalone) and [addr1 addr2] (attached) styles.
func stripBrackets(args []string) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		cleaned := strings.Trim(arg, "[]")
		if cleaned != "" {
			result = append(result, cleaned)
		}
	}
	return result
}

// Alias resolves alias command semantics while leaving rendering to the shell.
func (a *App) Alias(ctx context.Context, args []string) (*AliasCommandResult, error) {
	if len(args) == 0 {
		return &AliasCommandResult{
			Mode:  "usage",
			Usage: aliasUsageLines(),
		}, nil
	}

	if args[0] == "list" {
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: alias list")
		}
		result := &AliasCommandResult{
			Mode:    "list",
			Aliases: aliasEntryListFromEngine(a.eng.ListAliases().Aliases),
		}
		if a.eng.SignerKeyCount() > 0 {
			result.Warnings = []Warning{
				{Code: "signable_falcon", Message: "Yellow = signable falcon"},
				{Code: "signable_ed25519", Message: "Cyan = signable ed25519"},
			}
		}
		return result, nil
	}

	if args[0] == "delete" || args[0] == "remove" {
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: alias delete <name>")
		}
		name := normalizeAliasNameInput(args[1])
		if err := validateAliasNameInput(name); err != nil {
			return nil, err
		}
		address, err := a.eng.RemoveAlias(name)
		if err != nil {
			return nil, err
		}
		return &AliasCommandResult{
			Mode:    "delete",
			Name:    name,
			Removed: address,
		}, nil
	}

	if len(args) == 1 {
		name := normalizeAliasNameInput(args[0])
		if err := validateAliasNameInput(name); err != nil {
			return nil, err
		}
		aliasResult := a.eng.GetAlias(name)
		var alias *AliasEntry
		if aliasResult != nil {
			entry := aliasEntryFromEngine(*aliasResult)
			alias = &entry
		}
		if alias == nil {
			return nil, fmt.Errorf("alias '%s' not found", name)
		}
		return &AliasCommandResult{
			Mode:  "show",
			Name:  name,
			Alias: alias,
		}, nil
	}

	if len(args) == 2 {
		name := normalizeAliasNameInput(args[0])
		address := args[1]
		if err := validateAliasNameInput(name); err != nil {
			return nil, err
		}
		result, err := a.eng.AddAliasWithContext(ctx, name, address)
		if err != nil {
			return nil, err
		}
		return &AliasCommandResult{
			Mode:  "upsert",
			Name:  name,
			Added: aliasMutationFromEngine(result),
		}, nil
	}

	return nil, fmt.Errorf("usage: %s", strings.Join(aliasUsageLines(), " | "))
}

// Sets resolves sets command semantics while leaving rendering to the shell.
func (a *App) Sets(_ context.Context, args []string) (*SetsCommandResult, error) {
	if len(args) == 0 {
		return &SetsCommandResult{
			Mode:  "usage",
			Usage: setsUsageLines(),
		}, nil
	}

	if args[0] == "list" {
		if len(args) != 1 {
			return nil, fmt.Errorf("usage: sets list")
		}
		return &SetsCommandResult{
			Mode: "list",
			Sets: setEntryListFromEngine(a.eng.ListSets().Sets),
		}, nil
	}

	if args[0] == "add" {
		toIndex := indexOf(args, "to")
		if toIndex == -1 || toIndex == 1 || toIndex == len(args)-1 {
			return nil, fmt.Errorf("usage: sets add <address>... to <name>")
		}
		addresses := stripBrackets(args[1:toIndex])
		setName := normalizeSetNameInput(args[toIndex+1])
		if err := validateSetNameInput(setName); err != nil {
			return nil, err
		}
		result, err := a.eng.AddToSet(setName, addresses)
		if err != nil {
			return nil, err
		}
		return &SetsCommandResult{
			Mode:     "add",
			SetName:  result.Name,
			Mutation: setMutationFromEngine(result),
		}, nil
	}

	if args[0] == "remove" {
		fromIndex := indexOf(args, "from")
		if fromIndex == -1 || fromIndex == 1 || fromIndex == len(args)-1 {
			return nil, fmt.Errorf("usage: sets remove <address>... from <name>")
		}
		addresses := stripBrackets(args[1:fromIndex])
		setName := normalizeSetNameInput(args[fromIndex+1])
		if err := validateSetNameInput(setName); err != nil {
			return nil, err
		}
		result, err := a.eng.RemoveFromSet(setName, addresses)
		if err != nil {
			return nil, err
		}
		return &SetsCommandResult{
			Mode:     "remove",
			SetName:  result.Name,
			Mutation: setMutationFromEngine(result),
		}, nil
	}

	if args[0] == "delete" {
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: sets delete <name>")
		}
		setName := normalizeSetNameInput(args[1])
		if err := validateSetNameInput(setName); err != nil {
			return nil, err
		}
		count, err := a.eng.RemoveSet(setName)
		if err != nil {
			return nil, err
		}
		return &SetsCommandResult{
			Mode:    "delete",
			SetName: setName,
			Count:   count,
		}, nil
	}

	if len(args) == 1 {
		setRef := normalizeSetNameInput(args[0])
		if err := validateSetNameInput(setRef); err != nil {
			return nil, err
		}
		if !strings.HasPrefix(setRef, "@") {
			setRef = "@" + setRef
		}
		addresses, err := a.eng.NewAddressResolver().ResolveList([]string{setRef})
		if err != nil {
			return nil, fmt.Errorf("set '%s' not found or error: %v", args[0], err)
		}
		return &SetsCommandResult{
			Mode:      "show",
			SetName:   setRef,
			Addresses: addresses,
		}, nil
	}

	setName := normalizeSetNameInput(args[0])
	if err := validateSetNameInput(setName); err != nil {
		return nil, err
	}
	addresses := stripBrackets(args[1:])
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no valid addresses provided")
	}
	result, err := a.eng.AddSet(setName, addresses)
	if err != nil {
		return nil, err
	}
	return &SetsCommandResult{
		Mode:     "create",
		SetName:  result.Name,
		Mutation: setMutationFromEngine(result),
	}, nil
}

func aliasUsageLines() []string {
	return []string{
		"alias list",
		"alias <name> <address>",
		"alias <name>",
		"alias delete <name>",
	}
}

func setsUsageLines() []string {
	return []string{
		"sets list",
		"sets <name>",
		"sets <name> <addr1> <addr2> ...",
		"sets add <addr>... to <name>",
		"sets remove <addr>... from <name>",
		"sets delete <name>",
	}
}

func indexOf(items []string, target string) int {
	for i, item := range items {
		if item == target {
			return i
		}
	}
	return -1
}
