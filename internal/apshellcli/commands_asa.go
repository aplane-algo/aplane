// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package apshellcli

// ASA (Algorand Standard Asset) management commands

import (
	"fmt"
	"io"
	"strconv"

	"github.com/aplane-algo/aplane/internal/apshellapp"
	"github.com/aplane-algo/aplane/internal/command"
)

func (r *REPLState) cmdInfo(args []string, _ interface{}) (command.Result, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("usage: info <asa-id>")
	}

	asaID, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid ASA ID: %s", args[0])
	}

	result, err := r.app().ASAInfo(r.commandContext(), asaID)
	if err != nil {
		return nil, err
	}
	info := result.Info
	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			r.printf("ASA ID: %d\n", info.AssetID)
			r.printf("Name: %s\n", info.Name)
			r.printf("Unit Name: %s\n", info.UnitName)
			r.printf("Decimals: %d\n", info.Decimals)
			r.printf("Total Supply: %d\n", info.Total)
			r.printf("URL: %s\n", info.URL)
			if info.Creator != "" {
				r.printf("Creator: %s\n", info.Creator)
			}
		})
	}, projectASAInfo(info))
}

func (r *REPLState) cmdASA(args []string, _ interface{}) (command.Result, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: asa <list|add|remove|clear> [args...]")
	}

	var result *apshellapp.ASACommandResult
	var warning error
	switch args[0] {
	case "list":
		var err error
		result, err = r.app().ASACacheList(r.commandContext())
		if err != nil {
			return nil, err
		}

	case "add":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: asa add <id>")
		}
		asaID, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ASA ID: %s", args[1])
		}

		result, err = r.app().ASACacheAdd(r.commandContext(), asaID)
		if err != nil {
			return nil, fmt.Errorf("failed to add ASA %d: %w", asaID, err)
		}

	case "remove":
		if len(args) != 2 {
			return nil, fmt.Errorf("usage: asa remove <id>")
		}
		asaID, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid ASA ID: %s", args[1])
		}

		result, err = r.app().ASACacheRemove(r.commandContext(), asaID)
		if err != nil {
			return nil, err
		}

	case "clear":
		result, warning = r.app().ASACacheClear(r.commandContext())

	default:
		return nil, fmt.Errorf("unknown asa command: %s", args[0])
	}

	return newShellCommandResult(func(w io.Writer) error {
		return r.withOutput(w, func() {
			switch result.Mode {
			case "list":
				if len(result.ASAs) == 0 {
					r.println("No ASAs in cache")
					return
				}
				r.printf("ASA cache (%d entries):\n", len(result.ASAs))
				for _, item := range result.ASAs {
					r.printf("  %d: %s (%s) - %d decimals\n", item.AssetID, item.Name, item.UnitName, item.Decimals)
				}
			case "add":
				r.printf("ASA %d (%s) added to %s cache\n", result.AssetID, result.Info.UnitName, result.Network)
			case "remove":
				r.printf("ASA %d removed from %s cache\n", result.AssetID, result.Network)
			case "clear":
				if warning != nil {
					r.printf("Warning: failed to save ASA cache: %v\n", warning)
				}
				r.printf("Cleared %d ASAs from %s cache\n", result.Count, result.Network)
			}
		})
	}, projectASACacheResult(result))
}
