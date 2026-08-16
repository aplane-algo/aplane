// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/auth"
	"github.com/aplane-algo/aplane/internal/authz"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/logicsigdsa"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/identity"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signerstartuptemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/storelock"
	"github.com/aplane-algo/aplane/internal/tokenfile"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
)

// Run starts the signer daemon rooted at dataDir (empty means resolve via
// APSIGNER_DATA) and blocks until shutdown. The caller is responsible for
// provider registration before calling Run. The return value is the process
// exit code.
func Run(dataDir string) int {
	if err := ensureProviders(); err != nil {
		logErrorf("%v", err)
		return 1
	}

	resolvedDataDir, err := bootstrap.ResolveDataDir(dataDir)
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		return 1
	}
	if err := signerstartup.BlockManualProdStart(resolvedDataDir); err != nil {
		logErrorf("%v", err)
		return 1
	}
	if err := signerstartup.ValidateProductionStorePermissions(resolvedDataDir); err != nil {
		logErrorf("startup validation failed: %v", err)
		return 1
	}

	startupOpts, err := signerstartup.LoadOptions(dataDir, auth.CurrentProductIdentityID())
	if err != nil {
		logErrorf("%v", err)
		logErrorf("use -d <path> or set APSIGNER_DATA environment variable")
		return 1
	}
	resolvedDataDir = startupOpts.DataDir

	storeGuard, err := storelock.AcquireShared(resolvedDataDir)
	if err != nil {
		if errors.Is(err, storelock.ErrBusy) {
			logErrorf("signer store is locked by an offline apstore mutation in %s", resolvedDataDir)
			return 1
		}
		logErrorf("failed to acquire signer store lock: %v", err)
		return 1
	}
	defer func() { _ = storeGuard.Close() }()

	logInfof("APlane Signing Server")
	logInfof("============================================")
	logInfof("Data directory: %s", resolvedDataDir)

	// Plugin audit: Log all registered signature providers at startup
	registeredSigners := signing.GetRegisteredFamilies()
	if len(registeredSigners) > 0 {
		logInfof("loaded signature providers: %v", registeredSigners)
	} else {
		logWarnf("no signature providers registered (check plugins.go)")
	}
	logInfof("--------------------------------------------")

	config := startupOpts.Config
	resolvedIPCPath, _, err := adminipc.ResolveDaemonPathForDataDir(resolvedDataDir, config.IPCPath)
	if err != nil {
		logErrorf("failed to resolve admin IPC path: %v", err)
		return 1
	}
	config.IPCPath = resolvedIPCPath
	passphraseTimeout := startupOpts.PassphraseTimeout
	identityID := startupOpts.IdentityID
	if _, err := serverconfig.ParsePassphraseTimeout(config.PassphraseTimeout); err != nil {
		logWarnf("invalid passphrase_timeout in config: %v, using default (0)", err)
		_ = os.Stderr.Sync()
	}

	// Use config values for port settings
	port := config.Endpoint.SignerPort

	// Log the admin idle timeout mode
	if passphraseTimeout == 0 {
		logWarnf("admin idle timeout: disabled")
		logWarnf("set passphrase_timeout in config to disconnect idle apadmin sessions")
	} else {
		logInfof("admin idle timeout: %s (disconnects idle apadmin sessions)", passphraseTimeout.String())
	}

	// Memory Security: Attempt to disable core dumps and lock memory
	// Results are validated by ValidateStartup below
	runtime := &signerstartup.RuntimeState{}

	if err := disableCoreDumps(); err == nil {
		runtime.CoreDumpsDisabled = true
		logInfof("core dumps disabled")
	}

	// Skip memory locking if DISABLE_MEMORY_LOCK is set (for testing)
	if os.Getenv("DISABLE_MEMORY_LOCK") != "" {
		runtime.MemoryLocked = false
	} else if err := lockMemory(); err == nil {
		runtime.MemoryLocked = true
		logInfof("memory locked (keys will not swap to disk)")
	}

	// Comprehensive startup validation (config + runtime)
	// This handles required vs optional checks and prints warnings
	startupInfo, err := signerstartup.Validate(&config, runtime, startupOpts.Paths, identityID)
	if err != nil {
		logErrorf("startup validation failed: %v", err)
		return 1
	}

	unlockPlan, err := signerstartup.BuildUnlockPlan(startupOpts, startupInfo.KeystoreExists, os.Getenv("TEST_PASSPHRASE"))
	if err != nil {
		logErrorf("%v", err)
		if strings.Contains(err.Error(), "passphrase from passphrase command does not match existing keystore") {
			logErrorf("the passphrase_command_argv must return the same passphrase used to create the keystore")
		}
		return 1
	}
	startPassphrase := unlockPlan.Passphrase
	startLocked := unlockPlan.StartLocked
	passphraseSource := string(unlockPlan.Source)

	switch unlockPlan.Source {
	case signerstartup.UnlockSourceIPC:
		if !startupInfo.KeystoreExists {
			logWarnf("starting in LOCKED state (keystore not initialized)")
			logWarnf("run 'apstore initialize' to create the keystore")
		} else {
			logInfof("starting in LOCKED state")
			logInfof("connect with apadmin to unlock")
		}
	case signerstartup.UnlockSourceTestPassphrase:
		logWarnf("using TEST_PASSPHRASE for encryption (testing mode)")
	case signerstartup.UnlockSourcePassphraseCommand:
		logInfof("passphrase loaded via passphrase command")
		logInfof("starting in UNLOCKED state (headless mode)")
	}

	// Scan keys directory (skip if starting locked - keys loaded after unlock)
	if startLocked {
		logInfof("keys will be loaded after unlock via apadmin TUI")
	}

	// Initialize audit logger
	auditLog, err := NewAuditLogger(filepath.Join(resolvedDataDir, "audit.log"))
	if err != nil {
		logWarnf("failed to initialize audit log: %v", err)
		// Continue without audit logging - not fatal
	} else {
		logInfof("audit logging enabled (audit.log)")
	}

	// Log policy settings
	logInfof("Policy settings:")
	logInfof("  user_auto_approve: %v", config.UserAutoApprove)

	// Warn about unusual configs in interactive mode (not headless)
	if len(config.PassphraseCommandArgv) == 0 {
		printInteractiveModeWarnings(&config)
	}

	authorizer := authz.NewProductSingleAuthorizer()

	// Create the process root server (shared infrastructure only)
	reg := identity.NewRegistry()
	server := &Signer{
		registry:     reg,
		registryAuth: identity.NewRegistryAuthenticator(reg),
		authorizer:   authorizer,
		auditLog:     auditLog,
		config:       &config,
		keyPaths:     startupOpts.Paths,
		dataDir:      resolvedDataDir,
	}

	ir, err := signerstartup.BuildRegistry(server.registry, signerstartup.IdentityBuildOptions{
		DataDir:               resolvedDataDir,
		KeyPaths:              startupOpts.Paths,
		Config:                &config,
		DefaultSessionTimeout: passphraseTimeout,
		ProductIdentityID:     identityID,
	}, server.identityBuildHooks())
	if err != nil {
		logErrorf("%v", err)
		return 1
	}
	logInfof("product identity runtime initialized")
	removed, cleanupErr := backupadmin.CleanupIncompleteBackupImports(server.keyPaths, identityID)
	if cleanupErr != nil {
		logErrorf("failed to clean incomplete backup imports: %v", cleanupErr)
		return 1
	}
	if removed != 0 {
		logInfof("removed %d incomplete backup import(s)", removed)
	}
	logInfof("API token loaded from %s", tokenfile.GetAPlaneTokenPathForRoot(startupOpts.Paths.Root(), identityID))

	// Configure algod client on all DSA providers that need it (for TEAL compilation)
	configureAlgodOnDSAs(&config)

	if startLocked {
		logInfof("signer runtime initialized (waiting for apadmin connection)")
	} else {
		// Generation-based stores reconcile before startup unlock: CURRENT
		// is the sole commit record; uncommitted attempts are discarded and
		// the selected generation must validate, else recovery mode.
		adminServices := signerAdminServices{signer: server}
		generationErr := adminServices.reconcileGenerations(ir)
		if generationErr != nil {
			success, errMsg := ir.TryRecoveryUnlock(startPassphrase)
			crypto.ZeroBytes(startPassphrase)
			if !success {
				logErrorf("error unlocking recovery-blocked store: %s", errMsg)
				return 1
			}
			logWarnf("identity is recovery-blocked: %v", generationErr)
			startPassphrase = nil
		}
		if generationErr == nil {
			rotationErr := adminServices.completePendingRotation(ir, startPassphrase)
			if rotationErr != nil {
				success, errMsg := ir.TryRecoveryUnlock(startPassphrase)
				crypto.ZeroBytes(startPassphrase)
				if !success {
					logErrorf("error unlocking rotation-blocked store: %s", errMsg)
					return 1
				}
				logWarnf("identity is recovery-blocked by incomplete key rotation: %v", rotationErr)
				startPassphrase = nil
			}
		}
		if generationErr == nil && startPassphrase != nil {
			// Headless mode: load keys using passphrase, then zero it immediately.
			logInfof("scanning keys directory for private keys")
			_, err := ir.ReloadWithPassphrase(startPassphrase)
			if err != nil && signerstartuptemplates.IsGenerationValidationErr(err) {
				// Content defects in the selected generation are a recovery
				// condition, not a startup failure: keep the daemon up with
				// signing blocked so the admin surface exists to repair the
				// store, exactly as interactive unlock does.
				success, errMsg := ir.TryRecoveryUnlock(startPassphrase)
				crypto.ZeroBytes(startPassphrase)
				if !success {
					logErrorf("error unlocking recovery-blocked store: %s", errMsg)
					return 1
				}
				logWarnf("identity is recovery-blocked: %v", err)
			} else if err != nil {
				crypto.ZeroBytes(startPassphrase)
				logErrorf("error loading keys: %v", err)
				return 1
			} else {
				crypto.ZeroBytes(startPassphrase)
				ir.SetUnlocked()
			}
		}

		keyCount := ir.KeyCount()
		if keyCount == 0 && !ir.IsRecovery() {
			logWarnf("no private keys found in keys directory")
			logWarnf("keys must be generated using the apadmin tool:")
			logWarnf("  1. run apadmin on this machine (local access required)")
			logWarnf("  2. use 'generate' command to create new keys")
			logWarnf("  3. use 'import' command to restore from mnemonic")
			logWarnf("server will start and keys will auto-load when created")
		}
	}

	lockOnDisconnect := config.ShouldLockOnDisconnect()
	if err := startIPCServer(server, config.IPCPath); err != nil {
		logErrorf("failed to start IPC server: %v", err)
		return 1
	}

	// Print consolidated security audit
	printSecurityAudit(passphraseTimeout, &config, config.IPCPath, runtime.CoreDumpsDisabled, runtime.MemoryLocked, lockOnDisconnect, passphraseSource)

	// Log server start
	keysSnapshot, _ := ir.KeySnapshot()
	keyCount := len(keysSnapshot)

	if auditLog != nil {
		auditLog.LogServerStart(keyCount)
	}

	httpServer := buildHTTPServer(server, port)
	logHTTPStartup(keyCount, keysSnapshot, port)

	sshRuntime, err := startSSHRuntime(server, config.Endpoint.SSH.ListenAddress, config.Endpoint.SSH.Port, config.Endpoint.SSH.HostKeyPath, config.Endpoint.SSH.AuthorizedKeysPath, auditLog)
	if err != nil {
		logErrorf("failed to start SSH server: %v", err)
		return 1
	}
	server.setSSHRuntime(sshRuntime)
	runCtx, stopSignals := signalContext()
	defer stopSignals()

	signerstartup.RunLifecycle(runCtx, signerstartup.LifecyclePlan{
		Registry:        server.registry,
		ProductRuntime:  ir,
		ShutdownTimeout: 5 * time.Second,
		AuditLog:        auditLog,
		StartWatcher: func(product *identity.Runtime) {
			product.EnsureKeyWatcher(startKeyWatcherForDir)
		},
		Services: []signerstartup.LifecycleService{
			{
				Name: "IPC server",
				Start: func(ctx context.Context, errs chan<- error) error {
					return nil
				},
				Stop: func(ctx context.Context) error {
					if server.ipcServer != nil {
						server.ipcServer.Stop()
					}
					return nil
				},
			},
			{
				Name: "SSH server",
				Start: func(ctx context.Context, errs chan<- error) error {
					return nil
				},
				Stop: func(ctx context.Context) error {
					return server.stopSSHRuntime()
				},
			},
			{
				Name: "HTTP server",
				Start: func(ctx context.Context, errs chan<- error) error {
					go func() {
						if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
							errs <- err
						}
					}()
					return nil
				},
				Stop: func(ctx context.Context) error {
					return httpServer.Shutdown(ctx)
				},
			},
		},
		Info: func(msg string) {
			logInfof("%s", msg)
		},
		Warn: func(msg string) {
			logWarnf("%s", msg)
		},
		Error: func(msg string) {
			logErrorf("%s", msg)
		},
	})
	return 0
}

// ensureProviders validates that required providers are registered.
// Uses dynamic registry queries instead of hard-coded provider lists.
func ensureProviders() error {
	registered := signing.GetRegisteredFamilies()
	if len(registered) == 0 {
		return errors.New("no signing providers registered - register providers before starting the daemon")
	}

	// Verify ed25519 is registered (required for standard Algorand transactions)
	for _, kt := range registered {
		if kt == "ed25519" {
			return nil
		}
	}
	return errors.New("ed25519 signing provider required but not registered")
}

// printSecurityAudit prints a consolidated security configuration summary
func printSecurityAudit(passphraseTimeout time.Duration, config *serverconfig.ServerConfig, ipcPath string, coreDumpsDisabled bool, memoryLocked bool, lockOnDisconnect bool, passphraseSource string) {
	logInfof("Security configuration:")

	// Passphrase source status
	switch passphraseSource {
	case "passphrase_command":
		logInfof("  passphrase_source: passphrase command (headless)")
	case "TEST_PASSPHRASE":
		logWarnf("  passphrase_source: env var (testing)")
	default:
		logInfof("  passphrase_source: IPC unlock")
	}

	// Admin idle timeout status
	if passphraseTimeout == 0 {
		logWarnf("  admin_idle_timeout: disabled")
	} else {
		logInfof("  admin_idle_timeout: %s", passphraseTimeout)
	}

	// Lock on disconnect status
	if lockOnDisconnect {
		logInfof("  lock_on_disconnect: yes")
	} else {
		logWarnf("  lock_on_disconnect: no")
	}

	// User auto-approve status - operator-default approval fallback
	if !config.UserAutoApprove {
		logInfof("  user_auto_approve: disabled")
	} else {
		logWarnf("  user_auto_approve: enabled")
	}

	// Validation transactions are always auto-approved (0 ALGO self-send)
	logInfof("  validate_txns: always auto-approve")

	// IPC path status
	logInfof("  ipc_path: %s", ipcPath)

	// Memory protection status
	if coreDumpsDisabled {
		logInfof("  core_dumps: disabled")
	} else {
		logWarnf("  core_dumps: enabled")
	}
	if memoryLocked {
		logInfof("  memory_locked: yes")
	} else {
		logWarnf("  memory_locked: no")
	}
}

// printInteractiveModeWarnings prints warnings for unusual configs in interactive mode.
// These are not errors, just alerts that the user may have misconfigured something.
func printInteractiveModeWarnings(config *serverconfig.ServerConfig) {
	var warnings []string

	// Warn if user auto-approve is enabled - all non-rejected default-fallback transactions sign without confirmation.
	if config.UserAutoApprove {
		warnings = append(warnings, "user_auto_approve:true - non-rejected default-fallback transactions will be signed without confirmation")
	}

	if len(config.PassphraseCommandArgv) > 0 {
		warnings = append(warnings, "headless mode keeps the signer unlocked in memory until process exit or manual lock")
	}

	// Warn if lock_on_disconnect is false - signer stays unlocked after admin leaves
	if config.LockOnDisconnect != nil && !*config.LockOnDisconnect {
		warnings = append(warnings, "lock_on_disconnect:false - signer stays unlocked when apadmin disconnects")
	}

	// Print warnings if any
	if len(warnings) > 0 {
		logWarnf("interactive mode warnings:")
		for _, w := range warnings {
			logWarnf("  - %s", w)
		}
	}
}

// configureAlgodOnDSAs sets up the algod client on all DSA providers that support it.
// This enables runtime TEAL compilation for composed providers during key import.
func configureAlgodOnDSAs(serverCfg *serverconfig.ServerConfig) {
	cfg, err := serverCfg.GetTEALCompileAlgod()
	if err != nil || cfg.Server == "" {
		return // No algod configured, providers will use precompiled fallback where available
	}

	client, err := algod.MakeClient(cfg.Server, cfg.Token)
	if err != nil {
		logWarnf("failed to create algod client for DSA providers: %v", err)
		logWarnf("composed providers will fail without algod; pure aplane.falcon1024.v1 will use precompiled fallback")
		return
	}

	logicsigdsa.ConfigureAlgodClient(client)
}
