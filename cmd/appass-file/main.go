// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// appass-file is a passphrase command helper that stores the passphrase
// in a plaintext file. It implements the passphrase command protocol:
//
//	appass-file read   — prints the passphrase from the file to stdout
//	appass-file write  — reads a new passphrase from stdin, writes it to the file,
//	                   then prints it back to stdout for round-trip verification
//
// INSECURE / DEV ONLY: The passphrase is stored in plaintext.
// In production, use a secrets manager (macOS Keychain, TPM, Vault, etc.)
//
// Usage in config.yaml:
//
//	passphrase_command_argv: ["/path/to/appass-file", "/path/to/passphrase-file"]
package main

import (
	"io"
	"os"

	"github.com/aplane-algo/aplane/internal/crypto"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 3 {
		logErrorf("usage: appass-file <read|write> <passphrase-file>")
		return 2
	}

	verb := os.Args[1]
	filePath := os.Args[2]

	switch verb {
	case "read":
		data, err := os.ReadFile(filePath)
		if err != nil {
			logErrorf("read %s: %v", filePath, err)
			return 1
		}
		defer crypto.ZeroBytes(data)
		// Write passphrase to stdout (no trailing newline — caller strips one if present)
		_, _ = os.Stdout.Write(data)
		return 0

	case "write":
		passphrase, err := io.ReadAll(os.Stdin)
		if err != nil {
			logErrorf("read stdin: %v", err)
			return 1
		}
		defer crypto.ZeroBytes(passphrase)
		if err := os.WriteFile(filePath, passphrase, 0600); err != nil {
			logErrorf("write %s: %v", filePath, err)
			return 1
		}
		// Read back and echo for round-trip verification
		_, _ = os.Stdout.Write(passphrase)
		return 0

	default:
		logErrorf("unknown verb %q (expected read or write)", verb)
		return 2
	}
}
