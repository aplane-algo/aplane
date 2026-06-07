// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import "fmt"

func cmdTemplate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore template <list|show|import|remove>")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("usage: apstore template list")
		}
		return cmdTemplates()
	case "show":
		if len(args) != 3 || args[2] != "--show-sensitive-template" {
			return fmt.Errorf("usage: apstore template show <key-type> --show-sensitive-template")
		}
		return cmdShowTemplate(args[1], true)
	case "import":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore template import <yaml-file>")
		}
		return runStoreMutatingCommand("template", func() error {
			return cmdImportTemplate(args[1])
		})
	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore template remove <key-type>")
		}
		return runStoreMutatingCommand("template", func() error {
			return cmdRemoveTemplate(args[1])
		})
	default:
		return fmt.Errorf("usage: apstore template <list|show|import|remove>")
	}
}

func cmdKeyType(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: apstore keytype <enable|disable>")
	}
	switch args[0] {
	case "enable":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore keytype enable <key-type>")
		}
		return cmdActivateKeyType(args[1])
	case "disable":
		if len(args) != 2 {
			return fmt.Errorf("usage: apstore keytype disable <key-type>")
		}
		return cmdDeactivateKeyType(args[1])
	default:
		return fmt.Errorf("usage: apstore keytype <enable|disable>")
	}
}
