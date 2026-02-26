// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/util"
)

func cmdClear() error {
	configPath := filepath.Join(dataDirectory, "config.yaml")

	// Load config to detect current method
	config := util.LoadServerConfig(dataDirectory)
	method := detectMethod(config.PassphraseCommandArgv)

	if method == "none" {
		fmt.Println("No auto-unlock is configured. Nothing to clear.")
		return nil
	}

	fmt.Printf("Current auto-unlock method: %s\n", method)
	fmt.Println("")

	// Remove config keys
	fmt.Printf("Removing passphrase_command_argv and passphrase_timeout from %s...\n", configPath)
	if err := configRemoveKeys(configPath, []string{"passphrase_command_argv", "passphrase_timeout"}); err != nil {
		return fmt.Errorf("editing config: %w", err)
	}

	// Method-specific cleanup
	switch method {
	case "passfile":
		passFile := filepath.Join(dataDirectory, "passphrase")
		if _, err := os.Stat(passFile); err == nil {
			fmt.Printf("Removing passphrase file %s...\n", passFile)
			if err := os.Remove(passFile); err != nil {
				return fmt.Errorf("removing passphrase file: %w", err)
			}
		}

	case "systemcreds":
		// Regenerate service file WITHOUT --auto-unlock to remove LoadCredentialEncrypted
		svc, err := parseServiceFile(defaultServiceFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not parse service file: %v\n", err)
		} else {
			setupScript := filepath.Join(dataDirectory, "scripts", "systemd-setup.sh")
			if _, err := os.Stat(setupScript); err == nil {
				fmt.Println("Regenerating service file without LoadCredentialEncrypted...")
				cmd := exec.Command(setupScript, svc.User, svc.Group, svc.BinDir)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if err := cmd.Run(); err != nil {
					return fmt.Errorf("systemd-setup.sh failed: %w", err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "Warning: systemd-setup.sh not found at %s; service file not updated\n", setupScript)
			}
		}

		credFile := filepath.Join(dataDirectory, "passphrase.cred")
		if _, err := os.Stat(credFile); err == nil {
			fmt.Printf("Removing credential file %s...\n", credFile)
			if err := os.Remove(credFile); err != nil {
				return fmt.Errorf("removing credential file: %w", err)
			}
		}
	}

	fmt.Println("")
	fmt.Println("=== Auto-unlock removed ===")
	fmt.Println("")
	fmt.Println("The service will start locked. Use apadmin to unlock after starting:")
	fmt.Println("  sudo systemctl restart aplane")
	fmt.Printf("  sudo -u <service-user> apadmin -d %s\n", dataDirectory)

	return nil
}
