// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/keymigration"
	"golang.org/x/term"
)

func main() {
	var dataDir string
	var identity string
	var apply bool
	var passphraseEnv string
	var passphraseFile string
	var listSupported bool

	defaultDataDir := os.Getenv("APSIGNER_DATA")
	flag.StringVar(&dataDir, "d", defaultDataDir, "signer data directory")
	flag.StringVar(&identity, "identity", "", "identity to scan; default scans all identities")
	flag.BoolVar(&apply, "apply", false, "write repaired key files; default is dry-run")
	flag.StringVar(&passphraseEnv, "passphrase-env", "", "environment variable containing the store passphrase")
	flag.StringVar(&passphraseFile, "passphrase-file", "", "file containing the store passphrase")
	flag.BoolVar(&listSupported, "list-supported", false, "list key-file states this tool can repair")
	flag.Parse()

	if listSupported {
		keymigration.PrintSupportedConditions(os.Stdout)
		return
	}

	passphrase, err := readPassphrase(passphraseEnv, passphraseFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apkey-migrate: %v\n", err)
		os.Exit(2)
	}
	defer crypto.ZeroBytes(passphrase)

	result, err := keymigration.Run(keymigration.Options{
		DataDir:    dataDir,
		Identity:   identity,
		Passphrase: passphrase,
		Apply:      apply,
		Out:        os.Stdout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "apkey-migrate: %v\n", err)
		os.Exit(1)
	}
	if result.Failed > 0 {
		os.Exit(1)
	}
}

func readPassphrase(envName, filePath string) ([]byte, error) {
	if envName != "" {
		if value := os.Getenv(envName); value != "" {
			return []byte(value), nil
		}
		return nil, fmt.Errorf("environment variable %s is empty", envName)
	}
	if value := os.Getenv("APLANE_STORE_PASSPHRASE"); value != "" {
		return []byte(value), nil
	}
	if value := os.Getenv("APSIGNER_PASSPHRASE"); value != "" {
		return []byte(value), nil
	}
	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read passphrase file: %w", err)
		}
		return []byte(strings.TrimSpace(string(data))), nil
	}

	fmt.Print("Enter store passphrase: ")
	fd := int(os.Stdin.Fd()) // #nosec G115 - file descriptors are small integers
	if term.IsTerminal(fd) {
		passphrase, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return nil, err
		}
		return passphrase, nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(line)), nil
}
