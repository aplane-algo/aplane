// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package algo

import "os"

const (
	// DefaultPublicAlgodURL is the repo-wide public algod default for testnet-facing
	// tooling and tests when no explicit endpoint is provided.
	DefaultPublicAlgodURL = "https://testnet-api.4160.nodely.dev"

	// TEALCompileAlgodURLEnv overrides the algod endpoint used by compile-only
	// tooling and tests. It falls back to ALGOD_URL for consistency with the
	// integration environment, then to DefaultPublicAlgodURL.
	TEALCompileAlgodURLEnv = "TEAL_COMPILE_ALGOD_URL"

	// TEALCompileAlgodTokenEnv overrides the algod API token used by compile-only
	// tooling and tests. It falls back to ALGOD_TOKEN for consistency with the
	// integration environment.
	TEALCompileAlgodTokenEnv = "TEAL_COMPILE_ALGOD_TOKEN"
)

// ResolveTEALCompileAlgodURL returns the algod endpoint for compile-only paths.
func ResolveTEALCompileAlgodURL() string {
	if v := os.Getenv(TEALCompileAlgodURLEnv); v != "" {
		return v
	}
	if v := os.Getenv("ALGOD_URL"); v != "" {
		return v
	}
	return DefaultPublicAlgodURL
}

// ResolveTEALCompileAlgodToken returns the algod token for compile-only paths.
func ResolveTEALCompileAlgodToken() string {
	if v := os.Getenv(TEALCompileAlgodTokenEnv); v != "" {
		return v
	}
	return os.Getenv("ALGOD_TOKEN")
}
