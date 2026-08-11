// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// native-funding-address derives the integration suite's protocol-native
// Falcon-1024 funding address from TEST_FUNDING_MNEMONIC.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/aplane-algo/aplane/test/integration/harness"
)

func main() {
	words := strings.TrimSpace(os.Getenv("TEST_FUNDING_MNEMONIC"))
	if words == "" {
		_, _ = fmt.Fprintln(os.Stderr, "TEST_FUNDING_MNEMONIC is not set")
		os.Exit(1)
	}
	address, err := harness.NativeFundingAddressFromMnemonic(words)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "derive native Falcon funding address: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Println(address)
}
