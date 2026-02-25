// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// pass-systemd-creds is a passphrase command helper that stores the passphrase
// encrypted via systemd-creds (TPM2 and/or host key). The credential file
// can only be decrypted on the same machine.
//
// For reading, pass-systemd-creds prefers the systemd credential directory
// (populated by LoadCredentialEncrypted in the unit file) so that apsignerd
// does not need root access. If CREDENTIALS_DIRECTORY is not set, it falls
// back to calling systemd-creds decrypt directly (which requires root).
//
// It implements the passphrase command protocol:
//
//	pass-systemd-creds read  <credential-file> — prints the passphrase to stdout
//	pass-systemd-creds write <credential-file> — reads passphrase from stdin, encrypts to file,
//	                                       then prints it back to stdout for round-trip verification
//
// Requires systemd-creds (systemd 250+) on the host for write and for
// read fallback. When using LoadCredentialEncrypted, systemd handles
// decryption before the service starts.
//
// Usage in config.yaml:
//
//	passphrase_command_argv: ["pass-systemd-creds", "passphrase.cred"]
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
)

const credentialName = "aplane-passphrase"

// systemdCredsPath is the absolute path to systemd-creds. An absolute path is
// required because the passphrase command protocol runs helpers with a stripped
// environment (no PATH).
const systemdCredsPath = "/usr/bin/systemd-creds"

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: pass-systemd-creds <read|write> <credential-file>\n")
		os.Exit(2)
	}

	verb := os.Args[1]
	credFile := os.Args[2]

	switch verb {
	case "read":
		passphrase, err := readPassphrase(credFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd-creds: read: %v\n", err)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(passphrase)

	case "write":
		if _, err := os.Stat(systemdCredsPath); err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd-creds: %s not found (required for write)\n", systemdCredsPath)
			os.Exit(1)
		}

		passphrase, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd-creds: read stdin: %v\n", err)
			os.Exit(1)
		}

		if err := encrypt(passphrase, credFile); err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd-creds: encrypt: %v\n", err)
			os.Exit(1)
		}

		// Verify round-trip: decrypt and compare
		decrypted, err := decrypt(credFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd-creds: verification decrypt: %v\n", err)
			os.Exit(1)
		}
		if !bytes.Equal(passphrase, decrypted) {
			fmt.Fprintf(os.Stderr, "pass-systemd-creds: round-trip verification failed\n")
			os.Exit(1)
		}

		// Echo back for caller's round-trip verification
		_, _ = os.Stdout.Write(passphrase)

	default:
		fmt.Fprintf(os.Stderr, "pass-systemd-creds: unknown verb %q (expected read or write)\n", verb)
		os.Exit(2)
	}
}

// readPassphrase reads the passphrase, preferring the systemd credential
// directory (CREDENTIALS_DIRECTORY) over calling systemd-creds decrypt.
//
// When apsignerd runs as a systemd service with LoadCredentialEncrypted,
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
	cmd := exec.Command(systemdCredsPath, "encrypt",
		"--name="+credentialName, "-", credFile)
	cmd.Stdin = bytes.NewReader(passphrase)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// decrypt runs systemd-creds decrypt to read the passphrase from credFile.
func decrypt(credFile string) ([]byte, error) {
	cmd := exec.Command(systemdCredsPath, "decrypt",
		"--name="+credentialName, credFile, "-")
	cmd.Stderr = os.Stderr
	return cmd.Output()
}
