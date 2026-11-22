// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 APlane Project LLC

package daemon

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aplane-algo/aplane/internal/adminipc"
	"github.com/aplane-algo/aplane/internal/authz"
	bootstrap "github.com/aplane-algo/aplane/internal/bootstrap/signer"
	"github.com/aplane-algo/aplane/internal/crypto"
	"github.com/aplane-algo/aplane/internal/lsigprovider"
	"github.com/aplane-algo/aplane/internal/security"
	"github.com/aplane-algo/aplane/internal/serverconfig"
	"github.com/aplane-algo/aplane/internal/signerapp/backupadmin"
	"github.com/aplane-algo/aplane/internal/signerapp/productruntime"
	signerstartup "github.com/aplane-algo/aplane/internal/signerapp/startup"
	signerstartuptemplates "github.com/aplane-algo/aplane/internal/signerapp/templates"
	"github.com/aplane-algo/aplane/internal/signerapp/unlockconfig"
	"github.com/aplane-algo/aplane/internal/signing"
	"github.com/aplane-algo/aplane/internal/sshtunnel"
	"github.com/aplane-algo/aplane/internal/storelock"

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

	startupOpts, err := bootstrap.LoadResolved(resolvedDataDir)
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
	startupOpts.Config = config
	passphraseTimeout := startupOpts.PassphraseTimeout

	// Use config values for port settings
	port := config.Endpoint.SignerPort

	// Memory Security: Attempt to disable core dumps and lock memory
	// Results are validated by ValidateStartup below
	runtime := &signerstartup.RuntimeState{}

	if err := security.DisableCoreDumps(); err == nil {
		runtime.CoreDumpsDisabled = true
		logInfof("core dumps disabled")
	}

	// Skip memory locking if DISABLE_MEMORY_LOCK is set (for testing)
	if os.Getenv("DISABLE_MEMORY_LOCK") != "" {
		runtime.MemoryLocked = false
	} else if err := security.LockMemory(); err == nil {
		runtime.MemoryLocked = true
		logInfof("memory locked (keys will not swap to disk)")
	}

	// Comprehensive startup validation (config + runtime)
	// This handles required vs optional checks and prints warnings
	startupInfo, unlockPlan, err := signerstartup.ValidateAndBuildUnlockPlan(startupOpts, runtime, os.Getenv("TEST_PASSPHRASE"))
	if err != nil {
		logErrorf("%v", err)
		return 1
	}
	startPassphrase := unlockPlan.Passphrase
	// unlockAtStartup zeroes the passphrase once it is used; this covers each
	// return before that, and zeroing twice is harmless.
	defer crypto.ZeroBytes(startPassphrase)
	startLocked := unlockPlan.StartLocked

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

	authorizer := authz.NewProductSingleAuthorizer()

	// Create the process root server (shared infrastructure only)
	server := &Signer{
		nodeFailState: &productruntime.NodeFailState{},
		authorizer:    authorizer,
		auditLog:      auditLog,
		config:        &config,
		keyPaths:      startupOpts.Paths,
		dataDir:       resolvedDataDir,
	}
	// Hold leaf-family spends from the start: a new release memory reads as
	// restored, and no listener may find it that way, whatever order the
	// services start in.
	server.rotatingReleases.Reset()

	ir, err := signerstartup.BuildProductRuntime(signerstartup.ProductBuildOptions{
		DataDir:               resolvedDataDir,
		KeyPaths:              startupOpts.Paths,
		Config:                &config,
		DefaultSessionTimeout: passphraseTimeout,
		UnlockMethod:          unlockPlan.Method,
	}, server.productBuildHooks())
	if err != nil {
		logErrorf("%v", err)
		return 1
	}
	server.runtime = ir
	server.httpAuth = newProductAuthenticator(server.nodeFailState, ir)
	logInfof("product runtime initialized")
	printModeWarnings(ir)
	removed, cleanupErr := backupadmin.CleanupIncompleteBackupImports(server.keyPaths)
	if cleanupErr != nil {
		logErrorf("failed to clean incomplete backup imports: %v", cleanupErr)
		return 1
	}
	if removed != 0 {
		logInfof("removed %d incomplete backup import(s)", removed)
	}
	logInfof("client authentication: enrolled SSH keys in %s", ir.AuthorizedKeysPath())

	// Configure algod client on all DSA providers that need it (for TEAL compilation)
	configureAlgodOnDSAs(&config)

	if startLocked {
		logInfof("signer runtime initialized (waiting for apadmin connection)")
	} else if !server.unlockAtStartup(ir, startPassphrase) {
		return 1
	}

	// The admin listener starts only after the startup unlock has published
	// its state, so no admin login or unlock can run beside that reload.
	if err := startIPCServer(server, config.IPCPath); err != nil {
		logErrorf("failed to start IPC server: %v", err)
		return 1
	}

	// Print consolidated security audit with the runtime's effective
	// settings: a passphrase helper turns off lock-on-disconnect and the idle
	// timeout whatever config.yaml says.
	effective := ir.Config()
	printSecurityAudit(effective.SessionTimeout(), effective.UserAutoApprove(), config.IPCPath, runtime.CoreDumpsDisabled, runtime.MemoryLocked, effective.LockOnDisconnect(), unlockPlan.Source)

	// Log server start
	keysSnapshot, _ := ir.KeySnapshot()
	keyCount := len(keysSnapshot)

	if auditLog != nil {
		auditLog.LogServerStart(keyCount)
	}

	httpServer := buildHTTPServer(server, port)
	cancelHTTPRequests := withCancelableRequests(httpServer)
	defer cancelHTTPRequests()
	logHTTPStartup(keyCount, keysSnapshot, port)
	apiListener := sshtunnel.NewAPIListener(maxHTTPConnections)
	server.apiListener = apiListener

	sshRuntime, err := startSSHRuntime(server, config.Endpoint.SSH.ListenAddress, config.Endpoint.SSH.Port, config.Endpoint.SSH.HostKeyPath, auditLog)
	if err != nil {
		logErrorf("failed to start SSH server: %v", err)
		if server.ipcServer != nil {
			server.ipcServer.Stop()
		}
		return 1
	}
	server.setSSHRuntime(sshRuntime)
	runCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	// A service that fails to start or serve exits non-zero (RunLifecycle has
	// already logged it); a shutdown signal exits 0.
	runErr := signerstartup.RunLifecycle(runCtx, server.lifecyclePlan(ir, httpServer, apiListener, cancelHTTPRequests))
	if runErr != nil {
		return 1
	}
	return 0
}

// lifecyclePlan is the signer process's lifecycle: the services RunLifecycle
// starts and stops, in order, and the audit log it records the stop in.
func (fs *Signer) lifecyclePlan(ir *productruntime.Runtime, httpServer *http.Server, apiListener *sshtunnel.APIListener, cancelHTTPRequests context.CancelFunc) signerstartup.LifecyclePlan {
	return signerstartup.LifecyclePlan{
		ProductRuntime:  ir,
		ShutdownTimeout: 5 * time.Second,
		AuditLog:        optionalAuditLog[signerstartup.ServerAuditLogger](fs.auditLog),
		StartWatcher: func(product *productruntime.Runtime) {
			product.EnsureKeyWatcher(startKeyWatcherForDir)
		},
		Services: []signerstartup.LifecycleService{
			stageTableWorkerService(fs),
			{
				Name: "IPC server",
				Start: func(ctx context.Context, errs chan<- error) error {
					return nil
				},
				Stop: func(ctx context.Context) error {
					if fs.ipcServer != nil {
						fs.ipcServer.Stop()
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
					return fs.stopSSHRuntime(ctx)
				},
			},
			{
				Name: "HTTP server",
				Start: func(ctx context.Context, errs chan<- error) error {
					ln, err := listenHTTP(httpServer.Addr)
					if err != nil {
						return err
					}
					go func() {
						if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
							errs <- err
						}
					}()
					go func() {
						if err := httpServer.Serve(newLimitListener(apiListener, maxHTTPConnections)); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
							errs <- err
						}
					}()
					return nil
				},
				Stop: func(ctx context.Context) error {
					return stopHTTPServer(ctx, httpServer, apiListener, cancelHTTPRequests)
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
	}
}

// unlockAtStartup unlocks the store with the passphrase a helper or the test
// environment supplied, and zeroes the passphrase. It reports false, having
// logged why, when the daemon cannot start.
func (s *Signer) unlockAtStartup(ir *productruntime.Runtime, passphrase []byte) bool {
	// Authenticate the sole store root and reconcile residue before
	// publishing any signing state. Selected-generation damage enters
	// recovery with the root keyring available.
	adminServices := s.adminServices()
	generationErr := adminServices.reconcileGenerations(ir, passphrase)
	if generationErr != nil {
		success, errMsg := ir.TryRecoveryUnlock(passphrase)
		crypto.ZeroBytes(passphrase)
		if !success {
			logErrorf("error unlocking recovery-blocked store: %s", errMsg)
			return false
		}
		logWarnf("identity is recovery-blocked: %v", generationErr)
		passphrase = nil
	}
	if generationErr == nil && passphrase != nil {
		// Headless mode: load keys using passphrase, then zero it immediately.
		logInfof("scanning keys directory for private keys")
		_, err := ir.ReloadWithPassphrase(passphrase)
		if err != nil && signerstartuptemplates.IsGenerationValidationErr(err) {
			// Content defects in the selected generation are a recovery
			// condition, not a startup failure: keep the daemon up with
			// signing blocked so the admin surface exists to repair the
			// store, exactly as interactive unlock does.
			success, errMsg := ir.TryRecoveryUnlock(passphrase)
			crypto.ZeroBytes(passphrase)
			if !success {
				logErrorf("error unlocking recovery-blocked store: %s", errMsg)
				return false
			}
			logWarnf("identity is recovery-blocked: %v", err)
		} else if err != nil {
			crypto.ZeroBytes(passphrase)
			logErrorf("error loading keys: %v", err)
			return false
		} else {
			crypto.ZeroBytes(passphrase)
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
	return true
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
func printSecurityAudit(passphraseTimeout time.Duration, userAutoApprove bool, ipcPath string, coreDumpsDisabled bool, memoryLocked bool, lockOnDisconnect bool, passphraseSource signerstartup.UnlockSource) {
	logInfof("Security configuration:")

	// Passphrase source status
	switch passphraseSource {
	case signerstartup.UnlockSourcePassphraseCommand:
		logInfof("  passphrase_source: passphrase command (headless)")
	case signerstartup.UnlockSourceTestPassphrase:
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

	// User auto-approve status: when on, every non-rejected request signs
	// without a prompt, review matches included.
	if !userAutoApprove {
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

// modeWarnings lists the settings in effect that an operator should hear
// about at startup. It reads the product runtime's settings, not
// config.yaml's: identities/default/config.yaml, where apadmin saves a
// change, overlays config.yaml, and a passphrase helper (unlock.yaml, set by
// appass) makes the runtime headless, which turns off lock-on-disconnect and
// the idle timeout whatever either file sets. headless reports which.
func modeWarnings(ir *productruntime.Runtime) (warnings []string, headless bool) {
	cfg := ir.Config()
	if ir.UnlockMethod() != unlockconfig.MethodNone {
		warnings = append(warnings,
			"headless mode keeps the signer unlocked in memory until process exit or manual lock",
			"headless mode turns off lock_on_disconnect and passphrase_timeout, whatever the config files set")
		if !cfg.UserAutoApprove() {
			warnings = append(warnings, "headless mode with user_auto_approve:false: transactions will require manual approval via apadmin")
		}
		return warnings, true
	}

	// User auto-approve signs every non-rejected transaction, including one
	// that matches a review rule, without confirmation.
	if cfg.UserAutoApprove() {
		warnings = append(warnings, "user_auto_approve:true - all non-rejected transactions, including review-rule matches, will be signed without confirmation")
	}
	if !cfg.LockOnDisconnect() {
		warnings = append(warnings, "lock_on_disconnect:false - signer stays unlocked when apadmin disconnects")
	}
	if cfg.SessionTimeout() == 0 {
		warnings = append(warnings, "passphrase_timeout:0 - idle apadmin sessions are never disconnected")
	}
	return warnings, false
}

// printModeWarnings logs modeWarnings, if there are any.
func printModeWarnings(ir *productruntime.Runtime) {
	warnings, headless := modeWarnings(ir)
	if len(warnings) == 0 {
		return
	}
	if headless {
		logWarnf("headless mode warnings:")
	} else {
		logWarnf("interactive mode warnings:")
	}
	for _, w := range warnings {
		logWarnf("  - %s", w)
	}
}

// configureAlgodOnDSAs sets up the algod client on all DSA providers that support it.
// Every DSA LogicSig provider, aplane.falcon1024.v1 included, compiles its
// TEAL with algod to derive an account, so without one generation and import
// of those keys fail; nothing is precompiled.
func configureAlgodOnDSAs(serverCfg *serverconfig.ServerConfig) {
	cfg, err := serverCfg.GetTEALCompileAlgod()
	if err != nil || cfg.Server == "" {
		return
	}

	client, err := algod.MakeClient(cfg.Server, cfg.Token)
	if err != nil {
		logWarnf("failed to create algod client for DSA providers: %v", err)
		logWarnf("DSA LogicSig keys, aplane.falcon1024.v1 included, cannot be generated or imported without algod")
		return
	}

	lsigprovider.ConfigureAlgodClient(client)
}
