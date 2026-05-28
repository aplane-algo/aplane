// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// appass-systemd-creds is a passphrase command helper that stores the passphrase
// encrypted via systemd-creds (TPM2 and/or host key). The credential file
// can only be decrypted on the same machine.
//
// For reading, appass-systemd-creds prefers the systemd credential directory
// (populated by LoadCredentialEncrypted in the unit file) so that apsigner
// does not need root access. If CREDENTIALS_DIRECTORY is not set, it falls
// back to calling systemd-creds decrypt directly (which requires root).
//
// It implements the passphrase command protocol:
//
//	appass-systemd-creds read  <credential-file> — prints the passphrase to stdout
//	appass-systemd-creds write <credential-file> — reads passphrase from stdin, encrypts to file,
//	                                       then prints it back to stdout for round-trip verification
//
// Requires systemd-creds (systemd 250+) on the host for write and for
// read fallback. When using LoadCredentialEncrypted, systemd handles
// decryption before the service starts.
//
// Usage in config.yaml:
//
//	passphrase_command_argv: ["appass-systemd-creds", "passphrase.cred"]
//
// Systemd unit file (recommended):
//
//	[Service]
//	LoadCredentialEncrypted=aplane-passphrase:/path/to/passphrase.cred
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aplane-algo/aplane/internal/crypto"
)

const credentialName = "aplane-passphrase"

// systemdCredsPath is the absolute path to systemd-creds. An absolute path is
// required because the passphrase command protocol runs helpers with a stripped
// environment (no PATH).
const systemdCredsPath = "/usr/bin/systemd-creds"

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 3 {
		logErrorf("usage: appass-systemd-creds <read|write> <credential-file>")
		return 2
	}

	verb := os.Args[1]
	credFile := os.Args[2]

	switch verb {
	case "read":
		passphrase, err := readPassphrase(credFile)
		if err != nil {
			logErrorf("read: %v", err)
			return 1
		}
		defer crypto.ZeroBytes(passphrase)
		_, _ = os.Stdout.Write(passphrase)
		return 0

	case "write":
		if _, err := os.Stat(systemdCredsPath); err != nil {
			logErrorf("%s not found (required for write)", systemdCredsPath)
			return 1
		}

		passphrase, err := io.ReadAll(os.Stdin)
		if err != nil {
			logErrorf("read stdin: %v", err)
			return 1
		}
		defer crypto.ZeroBytes(passphrase)

		if err := encrypt(passphrase, credFile); err != nil {
			logErrorf("encrypt: %v", err)
			return 1
		}

		// Verify round-trip: decrypt and compare
		decrypted, err := decrypt(credFile)
		if err != nil {
			logErrorf("verification decrypt: %v", err)
			return 1
		}
		defer crypto.ZeroBytes(decrypted)
		if !bytes.Equal(passphrase, decrypted) {
			logErrorf("round-trip verification failed")
			return 1
		}

		// Echo back for caller's round-trip verification
		_, _ = os.Stdout.Write(passphrase)
		return 0

	default:
		logErrorf("unknown verb %q (expected read or write)", verb)
		return 2
	}
}

// readPassphrase reads the passphrase, preferring the systemd credential
// directory (CREDENTIALS_DIRECTORY) over calling systemd-creds decrypt.
//
// When apsigner runs as a systemd service with LoadCredentialEncrypted,
// systemd decrypts the credential at service start and places the plaintext
// in a tmpfs at $CREDENTIALS_DIRECTORY/<name>. This avoids requiring root.
func readPassphrase(credFile string) ([]byte, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		credPath := filepath.Join(dir, credentialName)
		data, err := os.ReadFile(credPath)
		if err == nil {
			return data, nil
		}
		// Fall through to systemd-creds if the credential file doesn't exist
		// in the directory (e.g., unit misconfiguration).
	}

	// Fallback: call systemd-creds decrypt directly (requires root).
	if _, err := os.Stat(systemdCredsPath); err != nil {
		return nil, fmt.Errorf("CREDENTIALS_DIRECTORY not set and %s not found", systemdCredsPath)
	}
	return decrypt(credFile)
}

// encrypt runs systemd-creds encrypt to write the passphrase to credFile.
func encrypt(passphrase []byte, credFile string) error {
	dir := filepath.Dir(credFile)
	tmp, err := os.CreateTemp(dir, filepath.Base(credFile)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp credential file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp credential file: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	cmd := exec.Command(systemdCredsPath, "encrypt",
		"--name="+credentialName, "-", tmpPath)
	cmd.Stdin = bytes.NewReader(passphrase)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, credFile); err != nil {
		return fmt.Errorf("rename credential file: %w", err)
	}
	cleanup = false
	return nil
}

// decrypt runs systemd-creds decrypt to read the passphrase from credFile.
func decrypt(credFile string) ([]byte, error) {
	cmd := exec.Command(systemdCredsPath, "decrypt",
		"--name="+credentialName, credFile, "-")
	cmd.Stderr = os.Stderr
	return cmd.Output()
}
