// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 aPlane Authors

package main

import (
	"fmt"
	"os"

	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/util"
)

// RuntimeState holds the results of runtime capability checks.
type RuntimeState struct {
	CoreDumpsDisabled bool
	MemoryLocked      bool
}

// validateStartup performs comprehensive startup validation for apsignerd.
// It checks both configuration and runtime state in one place.
// Returns an error for required failures (caller should halt).
// Prints warnings for optional failures (caller continues).
func validateStartup(config *util.ServerConfig, runtime *RuntimeState) error {
	var warnings []string

	// === Required config checks ===

	// Keystore metadata must exist (.keystore file with master salt)
	if !crypto.KeystoreMetadataExistsIn(config.StoreDir) {
		return fmt.Errorf("keystore not initialized: .keystore metadata not found in %s\n"+
			"       Run 'apstore init' to initialize the keystore with a passphrase", config.StoreDir)
	}

	// Validate unseal_kind unconditionally (rejects unknown values even without unseal_command_argv)
	if err := util.ValidateUnsealKind(config.UnsealKind); err != nil {
		return err
	}

	// unseal_kind: master_key requires unseal_command_argv (IPC always provides a passphrase)
	if config.UnsealKind == "master_key" && len(config.UnsealCommandArgv) == 0 {
		return fmt.Errorf("unseal_kind: master_key requires unseal_command_argv to be configured (IPC unlock always provides a passphrase)")
	}

	// Headless mode conflicts
	if len(config.UnsealCommandArgv) > 0 {
		if config.LockOnDisconnect != nil && *config.LockOnDisconnect {
			return fmt.Errorf("conflicting config: unseal_command_argv and lock_on_disconnect:true cannot be used together (headless mode requires signer to stay unlocked)")
		}
		if config.PassphraseTimeout != "" && config.PassphraseTimeout != "0" {
			return fmt.Errorf("conflicting config: unseal_command_argv requires passphrase_timeout:0 (headless mode must stay unlocked, got %q)", config.PassphraseTimeout)
		}
		if err := util.ValidateUnsealCommandConfig(config.UnsealCommandCfg()); err != nil {
			return err
		}
		warnings = append(warnings, util.ValidateHeadlessPolicy(config)...)
	}

	// === Required runtime checks (based on config) ===

	if config.RequireMemoryProtection {
		if !runtime.CoreDumpsDisabled {
			return fmt.Errorf("memory protection required (require_memory_protection: true) but core dumps could not be disabled - run with sudo")
		}
		if !runtime.MemoryLocked {
			return fmt.Errorf("memory protection required (require_memory_protection: true) but memory could not be locked - run with sudo")
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

	return nil
}
