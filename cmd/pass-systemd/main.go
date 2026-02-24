// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// pass-systemd is a passphrase command helper that encrypts the passphrase
// using systemd-creds (TPM2 and/or host key). The passphrase is stored on
// disk but can only be decrypted on the same machine.
//
// It implements the passphrase command protocol:
//
//	pass-systemd read  <credential-file> — decrypts and prints the passphrase to stdout
//	pass-systemd write <credential-file> — reads passphrase from stdin, encrypts to file,
//	                                       then prints it back to stdout for round-trip verification
//
// Requires systemd-creds (systemd 250+) on the host.
//
// Usage in config.yaml:
//
//	passphrase_command_argv: ["pass-systemd", "passphrase.cred"]
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
)

const credentialName = "aplane-passphrase"

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: pass-systemd <read|write> <credential-file>\n")
		os.Exit(2)
	}

	verb := os.Args[1]
	credFile := os.Args[2]

	if _, err := exec.LookPath("systemd-creds"); err != nil {
		fmt.Fprintf(os.Stderr, "pass-systemd: systemd-creds not found in PATH\n")
		os.Exit(1)
	}

	switch verb {
	case "read":
		passphrase, err := decrypt(credFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd: read: %v\n", err)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(passphrase)

	case "write":
		passphrase, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd: read stdin: %v\n", err)
			os.Exit(1)
		}

		if err := encrypt(passphrase, credFile); err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd: encrypt: %v\n", err)
			os.Exit(1)
		}

		// Verify round-trip: decrypt and compare
		decrypted, err := decrypt(credFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-systemd: verification decrypt: %v\n", err)
			os.Exit(1)
		}
		if !bytes.Equal(passphrase, decrypted) {
			fmt.Fprintf(os.Stderr, "pass-systemd: round-trip verification failed\n")
			os.Exit(1)
		}

		// Echo back for caller's round-trip verification
		_, _ = os.Stdout.Write(passphrase)

	default:
		fmt.Fprintf(os.Stderr, "pass-systemd: unknown verb %q (expected read or write)\n", verb)
		os.Exit(2)
	}
}

// encrypt runs systemd-creds encrypt to write the passphrase to credFile.
func encrypt(passphrase []byte, credFile string) error {
	cmd := exec.Command("systemd-creds", "encrypt",
		"--name="+credentialName, "-", credFile)
	cmd.Stdin = bytes.NewReader(passphrase)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// decrypt runs systemd-creds decrypt to read the passphrase from credFile.
func decrypt(credFile string) ([]byte, error) {
	cmd := exec.Command("systemd-creds", "decrypt",
		"--name="+credentialName, credFile, "-")
	cmd.Stderr = os.Stderr
	return cmd.Output()
}
