// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package policycmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

const (
	passphraseEnv        = "APSIGNER_PASSPHRASE"
	retiredPassphraseEnv = "APPOLICY_PASSPHRASE"
)

var OpenTTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

func RejectRetiredEnvironment() error {
	if os.Getenv(retiredPassphraseEnv) != "" {
		return fmt.Errorf("%s is retired; use %s for explicit local policy commands", retiredPassphraseEnv, passphraseEnv)
	}
	return nil
}

// ReadPassphrase reads the policy command's authentication secret. The
// APSIGNER_PASSPHRASE automation source is deliberately local-only. An
// explicit stdin line is accepted locally or remotely when stdin is not the
// policy document stream.
func ReadPassphrase(stdin io.Reader, stderr io.Writer, remote, stdinReserved bool) ([]byte, error) {
	if !remote {
		if value := os.Getenv(passphraseEnv); value != "" {
			return []byte(value), nil
		}
	}

	if file, ok := stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		return readTerminalPassphrase(file, stderr)
	}

	if !stdinReserved {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		passphrase := []byte(strings.TrimSpace(line))
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("passphrase cannot be empty")
		}
		return passphrase, nil
	}

	if tty, err := OpenTTY(); err == nil {
		defer func() { _ = tty.Close() }()
		return readTerminalPassphrase(tty, tty)
	}

	if remote {
		return nil, fmt.Errorf("remote policy authentication requires a controlling terminal when policy YAML is read from stdin; %s is intentionally local-only; for scripted remote use, pass the policy as a file argument and pipe the passphrase on stdin", passphraseEnv)
	}
	return nil, fmt.Errorf("passphrase must come from %s or a controlling terminal when policy YAML is read from stdin", passphraseEnv)
}

func readTerminalPassphrase(terminal *os.File, prompt io.Writer) ([]byte, error) {
	_, _ = fmt.Fprint(prompt, "Enter store passphrase: ")
	passphrase, err := term.ReadPassword(int(terminal.Fd()))
	_, _ = fmt.Fprintln(prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	return passphrase, nil
}
