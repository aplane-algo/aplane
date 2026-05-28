// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// ASA (Algorand Standard Asset) management commands

import (
	"fmt"
	"strconv"
)

func (r *REPLState) cmdInfo(args []string, _ interface{}) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: info <asa-id>")
	}

	asaID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid ASA ID: %s", args[0])
	}

	result, err := r.app().ASAInfo(r.commandContext(), asaID)
	if err != nil {
		return err
	}
	info := result.Info

	r.printf("ASA ID: %d\n", info.AssetID)
	r.printf("Name: %s\n", info.Name)
	r.printf("Unit Name: %s\n", info.UnitName)
	r.printf("Decimals: %d\n", info.Decimals)
	r.printf("Total Supply: %d\n", info.Total)
	r.printf("URL: %s\n", info.URL)
	if info.Creator != "" {
		r.printf("Creator: %s\n", info.Creator)
	}
	return nil
}

func (r *REPLState) cmdASA(args []string, _ interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: asa <list|add|remove|clear> [args...]")
	}

	switch args[0] {
	case "list":
		result, err := r.app().ASACacheList(r.commandContext())
		if err != nil {
			return err
		}
		if len(result.ASAs) == 0 {
			r.println("No ASAs in cache")
			return nil
		}
		r.printf("ASA cache (%d entries):\n", len(result.ASAs))
		for _, asa := range result.ASAs {
			r.printf("  %d: %s (%s) - %d decimals\n", asa.AssetID, asa.Name, asa.UnitName, asa.Decimals)
		}
		return nil

	case "add":
		if len(args) != 2 {
			return fmt.Errorf("usage: asa add <id>")
		}
		asaID, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ASA ID: %s", args[1])
		}

		result, err := r.app().ASACacheAdd(r.commandContext(), asaID)
		if err != nil {
			return fmt.Errorf("failed to add ASA %d: %w", asaID, err)
		}

		r.printf("ASA %d (%s) added to %s cache\n", asaID, result.Info.UnitName, result.Network)
		return nil

	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: asa remove <id>")
		}
		asaID, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ASA ID: %s", args[1])
		}

		result, err := r.app().ASACacheRemove(r.commandContext(), asaID)
		if err != nil {
			return err
		}

		r.printf("ASA %d removed from %s cache\n", asaID, result.Network)
		return nil

	case "clear":
		result, err := r.app().ASACacheClear(r.commandContext())
		if err != nil {
			r.printf("Warning: failed to save ASA cache: %v\n", err)
		}

		r.printf("Cleared %d ASAs from %s cache\n", result.Count, result.Network)
		return nil

	default:
		return fmt.Errorf("unknown asa command: %s", args[0])
	}
}
