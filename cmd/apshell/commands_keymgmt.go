// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

// Key management commands: generate, delete

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/algorithm"
	"github.com/aplane-algo/aplane/internal/util"
)

func (r *REPLState) cmdGenerate(args []string, _ interface{}) error {
	if r.Engine.SignerClient == nil {
		fmt.Println("Not connected to Signer. Run 'connect host:port' first.")
		return nil
	}

	if len(args) < 1 {
		return fmt.Errorf("usage: generate <key_type> [param=value ...]")
	}

	keyType := args[0]
	params := make(map[string]string)
	for _, arg := range args[1:] {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid parameter %q (expected param=value)", arg)
		}
		params[parts[0]] = parts[1]
	}

	resp, err := r.Engine.SignerClient.AdminGenerate(keyType, params)
	if err != nil {
		return err
	}

	fmt.Printf("Generated %s key: %s\n", resp.KeyType, resp.Address)

	// Refresh signer key cache
	r.refreshSignerCache()

	return nil
}

func (r *REPLState) cmdDelete(args []string, _ interface{}) error {
	if r.Engine.SignerClient == nil {
		fmt.Println("Not connected to Signer. Run 'connect host:port' first.")
		return nil
	}

	if len(args) != 1 {
		return fmt.Errorf("usage: delete <address>")
	}

	address, err := r.Engine.AliasCache.ResolveAddress(args[0])
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}

	fmt.Printf("Delete key %s? [y/N]: ", r.FormatAddress(address, ""))
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return nil
	}
	response := strings.ToLower(strings.TrimSpace(scanner.Text()))
	if response != "y" && response != "yes" {
		fmt.Println("Cancelled.")
		return nil
	}

	_, err = r.Engine.SignerClient.AdminDeleteKey(address)
	if err != nil {
		return err
	}

	fmt.Println("Key deleted.")

	// Refresh signer key cache
	r.refreshSignerCache()

	return nil
}

// refreshSignerCache fetches keys from Signer and rebuilds the local cache.
func (r *REPLState) refreshSignerCache() {
	keysResp, err := r.Engine.SignerClient.GetKeys("")
	if err != nil {
		return
	}
	if keysResp.Locked {
		return
	}
	r.Engine.SignerCache = util.NewSignerCache()
	r.populateSignerCacheFromKeys(keysResp.Keys)
	r.Engine.SignerCache.SetColorFormatter(algorithm.GetDisplayColor)
	r.Engine.SignerCache.Checksum = keysResp.Checksum
}
