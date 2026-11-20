// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package algotest resolves the algod endpoint that tests compiling TEAL use.
package algotest

import "os"

const (
	// defaultPublicAlgodURL is the public testnet algod these tests use when
	// no endpoint is configured.
	defaultPublicAlgodURL = "https://testnet-api.4160.nodely.dev"

	// TEALCompileAlgodURLEnv overrides the algod endpoint used by compile-only
	// tests. It falls back to ALGOD_URL for consistency with the
	// integration environment, then to defaultPublicAlgodURL.
	TEALCompileAlgodURLEnv = "TEAL_COMPILE_ALGOD_URL"

	// tealCompileAlgodTokenEnv overrides the algod API token used by compile-only
	// tests. It falls back to ALGOD_TOKEN for consistency with the
	// integration environment.
	tealCompileAlgodTokenEnv = "TEAL_COMPILE_ALGOD_TOKEN"
)

// ResolveTEALCompileAlgodURL returns the algod endpoint for compile-only paths.
func ResolveTEALCompileAlgodURL() string {
	if v := os.Getenv(TEALCompileAlgodURLEnv); v != "" {
		return v
	}
	if v := os.Getenv("ALGOD_URL"); v != "" {
		return v
	}
	return defaultPublicAlgodURL
}

// ResolveTEALCompileAlgodToken returns the algod token for compile-only paths.
func ResolveTEALCompileAlgodToken() string {
	if v := os.Getenv(tealCompileAlgodTokenEnv); v != "" {
		return v
	}
	return os.Getenv("ALGOD_TOKEN")
}
