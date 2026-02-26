// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
		// Remove LoadCredentialEncrypted from the service file directly.
		// We can't delegate to systemd-setup.sh because it has a guard that
		// refuses to remove LoadCredentialEncrypted (anti-downgrade protection).
		if err := removeLoadCredentialFromService(); err != nil {
			return err
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

// removeLoadCredentialFromService removes any LoadCredentialEncrypted line
// from the systemd service file and runs daemon-reload.
func removeLoadCredentialFromService() error {
	data, err := os.ReadFile(defaultServiceFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read service file %s: %v\n", defaultServiceFile, err)
		return nil
	}

	var kept []string
	removed := false
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "LoadCredentialEncrypted") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading service file: %w", err)
	}

	if !removed {
		return nil
	}

	fmt.Printf("Removing LoadCredentialEncrypted from %s...\n", defaultServiceFile)
	output := strings.Join(kept, "\n") + "\n"
	if err := os.WriteFile(defaultServiceFile, []byte(output), 0644); err != nil {
		return fmt.Errorf("writing service file: %w", err)
	}

	fmt.Println("Running systemctl daemon-reload...")
	cmd := exec.Command("systemctl", "daemon-reload")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}

	return nil
}
