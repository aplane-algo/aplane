// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package startup

import (
	"fmt"
	"os"

	signerbootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/storepaths"
	"github.com/aplane-algo/aplane/internal/storeperm"
)

const (
	prodMarkerFile            = signerbootstrap.ProdMarkerFile
	systemdManagedInstanceEnv = signerbootstrap.SystemdManagedInstanceEnv
)

// RuntimeState holds the results of process runtime capability checks.
type RuntimeState struct {
	CoreDumpsDisabled bool
	MemoryLocked      bool
}

// ValidationInfo holds the results of startup validation checks.
type ValidationInfo struct {
	KeystoreExists bool
}

var auditPrivateStore = storeperm.Audit
var managedServiceOwner = storeperm.ManagedServiceOwner

// BlockManualProdStart rejects manual startup for a systemd-managed data
// directory unless the process is running under systemd.
func BlockManualProdStart(dataDir string) error {
	prodManaged, err := IsProductionManagedDataDir(dataDir)
	if err != nil {
		return err
	}
	if !prodManaged {
		return nil
	}

	if RunningUnderSystemd() {
		return nil
	}

	return fmt.Errorf(
		"refusing manual startup for systemd-managed data directory %s; start with 'systemctl start apsigner'",
		dataDir,
	)
}

// IsProductionManagedDataDir reports whether dataDir has the systemd-managed
// marker written by the systemd installer.
func IsProductionManagedDataDir(dataDir string) (bool, error) {
	return signerbootstrap.IsProductionManagedDataDir(dataDir)
}

// RunningUnderSystemd reports whether the process appears to be launched by
// systemd or an equivalent service manager PID 1 context.
func RunningUnderSystemd() bool {
	return signerbootstrap.RunningUnderSystemd()
}

// ValidateProductionStorePermissions fails before configuration or lock files
// are opened when a systemd-managed store is not private to the daemon's uid.
func ValidateProductionStorePermissions(dataDir string) error {
	prodManaged, err := IsProductionManagedDataDir(dataDir)
	if err != nil {
		return err
	}
	if !prodManaged {
		return nil
	}
	expectedUID, expectedGID, err := managedServiceOwner(dataDir)
	if err != nil {
		return fmt.Errorf(
			"resolve managed signer service principal: %w; rerun the systemd installer or systemd-setup",
			err,
		)
	}
	runtimeUID, runtimeGID := os.Geteuid(), os.Getegid()
	if runtimeUID != expectedUID || runtimeGID != expectedGID {
		return fmt.Errorf(
			"managed signer service principal mismatch: daemon runs as %d:%d but installer metadata requires %d:%d; stop apsigner and rerun the systemd installer or systemd-setup",
			runtimeUID, runtimeGID, expectedUID, expectedGID,
		)
	}
	findings, err := auditPrivateStore(storeperm.ProductionAuditOptions(dataDir, expectedUID, expectedGID))
	if err != nil {
		return fmt.Errorf("inspect private signer store: %w", err)
	}
	if len(findings) != 0 {
		return fmt.Errorf(
			"unsafe signer-store permissions (%d finding(s)); first: %s; stop apsigner and run 'sudo apstore -d %s permissions migrate'",
			len(findings), findings[0].Error(), dataDir,
		)
	}
	return nil
}

// Validate performs comprehensive signer startup validation.
// It returns an error for required failures and writes optional warnings to stderr.
func Validate(config *serverconfig.ServerConfig, runtime *RuntimeState, keyPaths storepaths.Paths, identityID string) (*ValidationInfo, error) {
	var warnings []string
	info := &ValidationInfo{}

	if config.Endpoint.SSH.Port <= 0 {
		return nil, fmt.Errorf("invalid endpoint.ssh configuration: endpoint.ssh.port must be greater than zero")
	}
	if err := serverconfig.ValidateSSHListenAddress(config.Endpoint.SSH.ListenAddress); err != nil {
		return nil, fmt.Errorf("invalid endpoint.ssh configuration: %w", err)
	}
	if config.Endpoint.SSH.HostKeyPath == "" {
		return nil, fmt.Errorf("invalid endpoint.ssh configuration: endpoint.ssh.host_key_path is required")
	}
	if config.Endpoint.SSH.AuthorizedKeysPath == "" {
		return nil, fmt.Errorf("invalid endpoint.ssh configuration: endpoint.ssh.authorized_keys_path is required")
	}

	if !crypto.KeyringExistsIn(keyPaths.KeystoreMetadataDir(identityID)) {
		info.KeystoreExists = false
		warnings = append(warnings, "Keystore not initialized — run 'apstore initialize'")
	} else {
		info.KeystoreExists = true

		if len(config.PassphraseCommandArgv) > 0 {
			if config.LockOnDisconnect != nil && *config.LockOnDisconnect {
				return nil, fmt.Errorf("conflicting config: passphrase_command_argv and lock_on_disconnect:true cannot be used together (headless mode requires signer to stay unlocked)")
			}
			if config.PassphraseTimeout != "" && config.PassphraseTimeout != "0" {
				return nil, fmt.Errorf("conflicting config: passphrase_command_argv requires passphrase_timeout:0 (headless mode disables admin idle timeout, got %q)", config.PassphraseTimeout)
			}
			if err := serverconfig.ValidatePassphraseCommandConfig(config.PassphraseCommandCfg()); err != nil {
				return nil, err
			}
			warnings = append(warnings, serverconfig.ValidateHeadlessPolicy(config)...)
		}
	}

	if config.RequireMemoryProtection {
		if !runtime.CoreDumpsDisabled {
			return nil, fmt.Errorf("memory protection required (require_memory_protection: true) but core dumps could not be disabled - run with sudo")
		}
		if !runtime.MemoryLocked {
			return nil, fmt.Errorf("memory protection required (require_memory_protection: true) but memory could not be locked - run with sudo")
		}
	}

	tealCfg, err := config.GetTEALCompileAlgod()
	if err != nil || tealCfg.Server == "" {
		warnings = append(warnings, fmt.Sprintf("algod.%s.server not configured: LogicSig generation will fail", config.TEALCompileNetwork))
	}

	if !runtime.CoreDumpsDisabled {
		warnings = append(warnings, "Core dumps enabled (keys may be written to disk on crash)")
	}
	if !runtime.MemoryLocked {
		warnings = append(warnings, "Memory not locked (keys may be swapped to disk)")
	}

	if len(warnings) > 0 {
		fmt.Fprintln(os.Stderr, "")
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "⚠️  %s\n", w)
		}
	}

	return info, nil
}
