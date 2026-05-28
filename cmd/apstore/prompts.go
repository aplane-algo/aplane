// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/internal/crypto"
	"golang.org/x/term"
)

var stdinReader *bufio.Reader

func readPromptedPassword() ([]byte, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 - file descriptors are small integers
	if term.IsTerminal(fd) {
		bytePassword, err := term.ReadPassword(fd)
		if err != nil {
			return nil, err
		}
		return bytePassword, nil
	}

	// stdin is not a terminal (e.g. piped/scripted input or test stdin). In that
	// case, consume the next line directly instead of falling back to /dev/tty,
	// which would block automated callers and bypass injected stdin.
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(line)), nil
}

// readPassword safely reads a password from stdin, handling both terminal and non-terminal inputs.
// If APSIGNER_PASSPHRASE is set, it is returned directly (for non-interactive / scripted use).
func readPassword() ([]byte, error) {
	if p := os.Getenv("APSIGNER_PASSPHRASE"); p != "" {
		return []byte(p), nil
	}
	return readPromptedPassword()
}

func readCurrentPassphrase() ([]byte, error) {
	fmt.Print("Enter current passphrase: ")
	passphrase, err := readPromptedPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	fmt.Println()
	return passphrase, nil
}

func readNewPassphrase(oldPassphrase []byte) ([]byte, error) {
	fmt.Print("Enter new passphrase: ")
	newPassphrase, err := readPromptedPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to read new passphrase: %w", err)
	}
	fmt.Println()

	if len(newPassphrase) == 0 {
		return nil, fmt.Errorf("new passphrase cannot be empty")
	}

	fmt.Print("Confirm new passphrase: ")
	confirm, err := readPromptedPassword()
	if err != nil {
		crypto.ZeroBytes(newPassphrase)
		return nil, fmt.Errorf("failed to read confirmation: %w", err)
	}
	defer crypto.ZeroBytes(confirm)
	fmt.Println()

	if !bytes.Equal(newPassphrase, confirm) {
		crypto.ZeroBytes(newPassphrase)
		return nil, fmt.Errorf("passphrases do not match")
	}
	if bytes.Equal(newPassphrase, oldPassphrase) {
		crypto.ZeroBytes(newPassphrase)
		return nil, fmt.Errorf("new passphrase must be different from current passphrase")
	}
	return newPassphrase, nil
}

func confirmPassphraseChange() bool {
	fmt.Print("Proceed with passphrase change? [y/N]: ")
	return confirmYesNo("")
}

func confirmRemoveTemplate(keyType string) bool {
	return confirmYesNo(fmt.Sprintf("Remove installed template %s? [y/N]: ", displayKeyType(keyType)))
}

func confirmDeactivateKeyType(keyType string) bool {
	return confirmYesNo(fmt.Sprintf("Deactivate key type %s? [y/N]: ", displayKeyType(keyType)))
}

func confirmYesNo(prompt string) bool {
	if prompt != "" {
		fmt.Print(prompt)
	}

	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	response, _ := stdinReader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}
