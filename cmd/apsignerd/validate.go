// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/util"
	utilkeys "github.com/aplane-algo/aplane/internal/util/keys"
)

// RuntimeState holds the results of runtime capability checks.
type RuntimeState struct {
	CoreDumpsDisabled bool
	MemoryLocked      bool
}

// StartupInfo holds the results of startup validation checks.
type StartupInfo struct {
	KeystoreExists bool
}

// validateStartup performs comprehensive startup validation for apsignerd.
// It checks both configuration and runtime state in one place.
// Returns an error for required failures (caller should halt).
// Prints warnings for optional failures (caller continues).
func validateStartup(config *util.ServerConfig, runtime *RuntimeState) (*StartupInfo, error) {
	var warnings []string
	info := &StartupInfo{}

	// === Keystore check (non-fatal — allows starting without keystore) ===

	if !crypto.KeystoreMetadataExistsIn(utilkeys.KeystoreMetadataDir(auth.DefaultIdentityID)) {
		info.KeystoreExists = false
		warnings = append(warnings, "Keystore not initialized — run 'apstore init' then unlock via apadmin")
	} else {
		info.KeystoreExists = true

		// Headless mode conflicts (only relevant when keystore exists)
		if len(config.PassphraseCommandArgv) > 0 {
			if config.LockOnDisconnect != nil && *config.LockOnDisconnect {
				return nil, fmt.Errorf("conflicting config: passphrase_command_argv and lock_on_disconnect:true cannot be used together (headless mode requires signer to stay unlocked)")
			}
			if config.PassphraseTimeout != "" && config.PassphraseTimeout != "0" {
				return nil, fmt.Errorf("conflicting config: passphrase_command_argv requires passphrase_timeout:0 (headless mode must stay unlocked, got %q)", config.PassphraseTimeout)
			}
			if err := util.ValidatePassphraseCommandConfig(config.PassphraseCommandCfg()); err != nil {
				return nil, err
			}
			warnings = append(warnings, util.ValidateHeadlessPolicy(config)...)
		}
	}

	// === Required runtime checks (based on config) ===

	if config.RequireMemoryProtection {
		if !runtime.CoreDumpsDisabled {
			return nil, fmt.Errorf("memory protection required (require_memory_protection: true) but core dumps could not be disabled - run with sudo")
		}
		if !runtime.MemoryLocked {
			return nil, fmt.Errorf("memory protection required (require_memory_protection: true) but memory could not be locked - run with sudo")
		}
	}

	// === Optional config warnings ===

	if config.TEALCompilerAlgodURL == "" {
		warnings = append(warnings, "teal_compiler_algod_url not configured: LogicSig generation will fail")
	}

	// === Optional runtime warnings ===

	if !runtime.CoreDumpsDisabled {
		warnings = append(warnings, "Core dumps enabled (keys may be written to disk on crash)")
	}
	if !runtime.MemoryLocked {
		warnings = append(warnings, "Memory not locked (keys may be swapped to disk)")
	}

	// Print all warnings
	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr, "")
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "⚠️  %s\n", w)
		}
	}

	return info, nil
}
