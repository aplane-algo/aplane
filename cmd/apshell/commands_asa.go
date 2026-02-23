// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

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

	info, err := r.Engine.GetASAInfo(asaID)
	if err != nil {
		return err
	}

	fmt.Printf("ASA ID: %d\n", info.AssetID)
	fmt.Printf("Name: %s\n", info.Name)
	fmt.Printf("Unit Name: %s\n", info.UnitName)
	fmt.Printf("Decimals: %d\n", info.Decimals)
	fmt.Printf("Total Supply: %d\n", info.Total)
	fmt.Printf("URL: %s\n", info.URL)
	if info.Creator != "" {
		fmt.Printf("Creator: %s\n", info.Creator)
	}
	return nil
}

func (r *REPLState) cmdASA(args []string, _ interface{}) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: asa <list|add|remove|clear> [args...]")
	}

	switch args[0] {
	case "list":
		asas := r.Engine.ListCachedASAs()
		if len(asas) == 0 {
			fmt.Println("No ASAs in cache")
			return nil
		}
		fmt.Printf("ASA cache (%d entries):\n", len(asas))
		for _, asa := range asas {
			fmt.Printf("  %d: %s (%s) - %d decimals\n", asa.AssetID, asa.Name, asa.UnitName, asa.Decimals)
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

		info, err := r.Engine.AddASAToCache(asaID)
		if err != nil {
			return fmt.Errorf("failed to add ASA %d: %w", asaID, err)
		}

		if err := r.Engine.AsaCache.SaveCache(r.Engine.Network); err != nil {
			fmt.Printf("Warning: failed to save ASA cache: %v\n", err)
		}

		fmt.Printf("ASA %d (%s) added to %s cache\n", asaID, info.UnitName, r.Engine.Network)
		return nil

	case "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: asa remove <id>")
		}
		asaID, err := strconv.ParseUint(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ASA ID: %s", args[1])
		}

		if err := r.Engine.RemoveASAFromCache(asaID); err != nil {
			return err
		}

		if err := r.Engine.AsaCache.SaveCache(r.Engine.Network); err != nil {
			fmt.Printf("Warning: failed to save ASA cache: %v\n", err)
		}

		fmt.Printf("ASA %d removed from %s cache\n", asaID, r.Engine.Network)
		return nil

	case "clear":
		count := r.Engine.ClearASACache()

		if err := r.Engine.AsaCache.SaveCache(r.Engine.Network); err != nil {
			fmt.Printf("Warning: failed to save ASA cache: %v\n", err)
		}

		fmt.Printf("Cleared %d ASAs from %s cache\n", count, r.Engine.Network)
		return nil

	default:
		return fmt.Errorf("unknown asa command: %s", args[0])
	}
}
