// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

// Package serverconfig owns the apsigner server configuration: loading and
// validating config.yaml for the signer data directory, server endpoint and
// SSH settings, and passphrase-command execution for headless unlock. Shared
// configuration primitives (algod settings, network IDs, genesis-hash
// resolution, atomic config writes) live in internal/config, which this
// package builds on; client configuration lives there too.
package serverconfig
