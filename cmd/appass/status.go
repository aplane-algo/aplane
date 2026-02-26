// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/util"
)

func cmdStatus() error {
	config := util.LoadServerConfig(dataDirectory)
	method := detectMethod(config.PassphraseCommandArgv)

	fmt.Printf("Data directory:  %s\n", dataDirectory)
	fmt.Printf("Auto-unlock:     %s\n", method)

	if method == "none" {
		fmt.Println("\nThe service starts locked. Use apadmin to unlock after starting.")
		return nil
	}

	// Show helper binary info
	if len(config.PassphraseCommandArgv) > 0 {
		helperPath := config.PassphraseCommandArgv[0]
		fmt.Printf("Helper binary:   %s\n", helperPath)
		if info, err := os.Stat(helperPath); err != nil {
			fmt.Printf("  Status:        NOT FOUND (%v)\n", err)
		} else if info.Mode()&0111 == 0 {
			fmt.Printf("  Status:        exists but NOT executable\n")
		} else {
			fmt.Printf("  Status:        OK\n")
		}
	}

	// Show method-specific file info
	switch method {
	case "passfile":
		passFile := filepath.Join(dataDirectory, "passphrase")
		if len(config.PassphraseCommandArgv) > 1 {
			passFile = config.PassphraseCommandArgv[1]
		}
		fmt.Printf("Passphrase file: %s\n", passFile)
		if _, err := os.Stat(passFile); err != nil {
			fmt.Printf("  Status:        NOT FOUND\n")
		} else {
			fmt.Printf("  Status:        OK\n")
		}

	case "systemcreds":
		credFile := filepath.Join(dataDirectory, "passphrase.cred")
		if len(config.PassphraseCommandArgv) > 1 {
			credFile = config.PassphraseCommandArgv[1]
		}
		fmt.Printf("Credential file: %s\n", credFile)
		if _, err := os.Stat(credFile); err != nil {
			fmt.Printf("  Status:        NOT FOUND\n")
		} else {
			fmt.Printf("  Status:        OK\n")
		}
	}

	// Check service file for LoadCredentialEncrypted
	if _, err := os.Stat(defaultServiceFile); err == nil {
		svc, err := parseServiceFile(defaultServiceFile)
		if err == nil {
			fmt.Printf("Service file:    %s\n", defaultServiceFile)
			if svc.HasLoadCred {
				fmt.Printf("  LoadCredentialEncrypted: yes\n")
			} else {
				fmt.Printf("  LoadCredentialEncrypted: no\n")
			}
		}
	}

	return nil
}
