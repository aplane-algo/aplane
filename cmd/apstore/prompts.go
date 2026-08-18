// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
