// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

// pass-file is a passphrase command helper that stores the passphrase
// in a plaintext file. It implements the passphrase command protocol:
//
//	pass-file read   — prints the passphrase from the file to stdout
//	pass-file write  — reads a new passphrase from stdin, writes it to the file,
//	                   then prints it back to stdout for round-trip verification
//
// INSECURE / DEV ONLY: The passphrase is stored in plaintext.
// In production, use a secrets manager (macOS Keychain, TPM, Vault, etc.)
//
// Usage in config.yaml:
//
//	passphrase_command_argv: ["/path/to/pass-file", "/path/to/passphrase-file"]
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: pass-file <read|write> <passphrase-file>\n")
		os.Exit(2)
	}

	verb := os.Args[1]
	filePath := os.Args[2]

	switch verb {
	case "read":
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-file: read %s: %v\n", filePath, err)
			os.Exit(1)
		}
		// Write passphrase to stdout (no trailing newline — caller strips one if present)
		_, _ = os.Stdout.Write(data)

	case "write":
		passphrase, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pass-file: read stdin: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(filePath, passphrase, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "pass-file: write %s: %v\n", filePath, err)
			os.Exit(1)
		}
		// Read back and echo for round-trip verification
		_, _ = os.Stdout.Write(passphrase)

	default:
		fmt.Fprintf(os.Stderr, "pass-file: unknown verb %q (expected read or write)\n", verb)
		os.Exit(2)
	}
}
